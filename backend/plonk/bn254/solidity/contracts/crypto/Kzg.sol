 // It has not been audited and is provided as-is, we make no guarantees or warranties to its safety and reliability. 
// 
// According to https://eprint.iacr.org/archive/2019/953/1585767119.pdf
pragma solidity >=0.6.0;
pragma experimental ABIEncoderV2;

import {Bn254} from './Bn254.sol';
import {Fr} from './Fr.sol';
import {TranscriptLibrary} from './Transcript.sol';

// cf https://github.com/ConsenSys/gnark-crypto/blob/develop/ecc/bn254/fr/kzg/kzg.go
library Kzg {

    using Bn254 for Bn254.G1Point;
    using Bn254 for Bn254.G2Point;
    using Fr for uint256;
    using TranscriptLibrary for TranscriptLibrary.Transcript;

    struct OpeningProof {
        // H quotient polynomial (f - f(z))/(x-z)
        Bn254.G1Point H;

        // claimed_value purported value
        uint256 claimed_value;
    }

    struct BatchOpeningProof {
        
        // H quotient polynomial Sum_i gamma**i*(f - f(z))/(x-z)
        Bn254.G1Point H;

        // claimed_values purported values
        uint256[] claimed_values;
    }

    event PrintUint256(uint256 a);

    // fold the digests corresponding to a batch opening proof at a given point
    // return the proof associated to the folded digests, and the folded digest
    function fold_proof(Bn254.G1Point[] memory digests, BatchOpeningProof memory batch_opening_proof, uint256 point)
    internal view returns(OpeningProof memory opening_proof, Bn254.G1Point memory folded_digests)
    {
        require(digests.length==batch_opening_proof.claimed_values.length);

        TranscriptLibrary.Transcript memory t = TranscriptLibrary.new_transcript();
        t.set_challenge_name("gamma");
        t.update_with_fr(point);
        for (uint i = 0; i<digests.length; i++){
            t.update_with_g1(digests[i]);
        }
        uint256 gamma = t.get_challenge();

        Bn254.copy_g1(opening_proof.H,batch_opening_proof.H);
        
        // fold the claimed values
        uint256[] memory gammai = new uint256[](digests.length);
        gammai[0] = 1;
        opening_proof.claimed_value = batch_opening_proof.claimed_values[0];
        uint256 tmp;
        for (uint i=1; i<digests.length; i++) {
            gammai[i] = Fr.mul(gammai[i-1], gamma);
            tmp = Fr.mul(gammai[i], batch_opening_proof.claimed_values[i]);
            opening_proof.claimed_value = Fr.add(opening_proof.claimed_value, tmp);
        }

        folded_digests = Bn254.multi_exp(digests, gammai);

        return (opening_proof, folded_digests);
    }

    // returns \sum_i [lambda^{i}p_i]H_i \sum_i [lambda^{i)]H_i, \sum_i [lambda_i]Comm_i, \sum_i lambda^i*p_i
    function fold_digests_quotients_evals(uint256[] memory lambda, uint256[] memory points, Bn254.G1Point[] memory digests, OpeningProof[] memory proofs)
    internal view returns(
        Bn254.G1Point memory res_quotient, 
        Bn254.G1Point memory res_digest,
        Bn254.G1Point memory res_points_quotients,
        uint256 res_eval)
    {
        uint256 tmp;

        Bn254.G1Point memory tmp_point;

        res_quotient = proofs[0].H;
        
        res_digest = digests[0];
        res_points_quotients = Bn254.point_mul(proofs[0].H, points[0]);
        res_eval = proofs[0].claimed_value;

        for (uint i=1; i<proofs.length; i++){

            tmp_point = Bn254.point_mul(proofs[i].H, lambda[i]);
            res_quotient = Bn254.point_add(res_quotient, tmp_point);

            tmp_point = Bn254.point_mul(digests[i], lambda[i]);
            res_digest = Bn254.point_add(res_digest, tmp_point);

            tmp = Fr.mul(lambda[i], points[i]);
            tmp_point = Bn254.point_mul(proofs[i].H, tmp);
            res_points_quotients = Bn254.point_add(res_points_quotients, tmp_point);

            tmp = Fr.mul(lambda[i], proofs[i].claimed_value);
            res_eval = Fr.add(res_eval, tmp);

        }

        return (res_points_quotients, res_digest, res_quotient, res_eval);

    }

    function batch_verify_multi_points(Bn254.G1Point[] memory digests, OpeningProof[] memory proofs, uint256[] memory points, Bn254.G2Point memory g2)
    internal view returns(bool)
    {

        require(digests.length == proofs.length);
        require(digests.length == points.length);

        // sample a random number (it's up to the verifier only so no need to take extra care)
        uint256[] memory lambda = new uint256[](digests.length);
        lambda[0] = 1;
        for (uint i=1; i<digests.length; i++){
            lambda[i] = uint256(sha256(abi.encodePacked(digests[i].X)))%Fr.r_mod;
        }

        Bn254.G1Point memory folded_digests;
        Bn254.G1Point memory folded_quotients;
        Bn254.G1Point memory folded_points_quotients;
        uint256 folded_evals;
        (folded_points_quotients, folded_digests, folded_quotients, folded_evals) = fold_digests_quotients_evals(lambda, points, digests, proofs);

        // compute commitment to folded Eval  [∑ᵢλᵢfᵢ(aᵢ)]G₁
        Bn254.G1Point memory g1 = Bn254.P1();
        Bn254.G1Point memory folded_evals_commit = Bn254.point_mul(g1, folded_evals);

        // compute foldedDigests = ∑ᵢλᵢ[fᵢ(α)]G₁ - [∑ᵢλᵢfᵢ(aᵢ)]G₁
        folded_digests.point_sub_assign(folded_evals_commit);

        // ∑ᵢλᵢ[f_i(α)]G₁ - [∑ᵢλᵢfᵢ(aᵢ)]G₁ + ∑ᵢλᵢ[p_i]([Hᵢ(α)]G₁)
	    // = [∑ᵢλᵢf_i(α) - ∑ᵢλᵢfᵢ(aᵢ) + ∑ᵢλᵢpᵢHᵢ(α)]G₁
        folded_digests = Bn254.point_add(folded_digests, folded_points_quotients);
        folded_quotients.Y = Bn254.p_mod - folded_quotients.Y;

        // pairing check
	    // e([∑ᵢλᵢ(fᵢ(α) - fᵢ(pᵢ) + pᵢHᵢ(α))]G₁, G₂).e([-∑ᵢλᵢ[Hᵢ(α)]G₁), [α]G₂)
        Bn254.G2Point memory g2srs = Bn254.P2();

        bool check = Bn254.pairingProd2(folded_digests, g2srs, folded_quotients, g2);

        return check;

    }

}