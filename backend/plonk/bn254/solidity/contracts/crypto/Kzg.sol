// Warning this code was contributed into gnark here: 
// https://github.com/ConsenSys/gnark/pull/358
// 
// It has not been audited and is provided as-is, we make no guarantees or warranties to its safety and reliability. 
// 
// According to https://eprint.iacr.org/archive/2019/953/1585767119.pdf
pragma solidity ^0.8.0;
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
    internal returns(OpeningProof memory opening_proof, Bn254.G1Point memory folded_digests)
    {
        require(digests.length==batch_opening_proof.claimed_values.length);

        TranscriptLibrary.Transcript memory t = TranscriptLibrary.new_transcript();
        t.set_challenge_name("gamma");
        t.update_with_fr(point);
        for (uint i = 0; i<digests.length; i++){
            t.update_with_g1(digests[i]);
        }
        uint256 gamma = t.get_challenge();

        opening_proof.H = batch_opening_proof.H.copy_g1();
        
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

    function batch_verify_multi_points(Bn254.G1Point[] memory digests, OpeningProof[] memory proofs, uint256[] memory points, Bn254.G2Point memory g2)
    internal returns(bool)
    {

        require(digests.length == proofs.length);
        require(digests.length == points.length);

        // sample a random number (it's up to the verifier only so no need to take extra care)
        uint256 lambda = uint256(sha256(abi.encodePacked(digests[0].X)))%Fr.r_mod;
        uint256[] memory random_numbers = new uint256[](digests.length);
        random_numbers[0] = 1;
        for (uint i=1; i<digests.length; i++){
            random_numbers[i] = Fr.mul(random_numbers[i-1], lambda);
        }

        // fold the committed quotients compute ∑ᵢλᵢ[Hᵢ(α)]G₁
        Bn254.G1Point memory folded_quotients;
        Bn254.G1Point[] memory quotients = new Bn254.G1Point[](digests.length);
        for (uint i=0; i<digests.length; i++){
            quotients[i] = proofs[i].H.copy_g1();
        }
        folded_quotients = Bn254.multi_exp(quotients, random_numbers);

        // fold digests and evals
        uint256 folded_evals = proofs[0].claimed_value;
        Bn254.G1Point memory folded_digests = digests[0].copy_g1();
        uint256 utmp;
        Bn254.G1Point memory ptmp;
        for (uint i=1; i<digests.length; i++){
            utmp = Fr.mul(random_numbers[i], proofs[i].claimed_value);
            folded_evals = Fr.add(folded_evals, utmp);
            ptmp = Bn254.point_mul(digests[i], random_numbers[i]);
            folded_digests = Bn254.point_add(folded_digests, ptmp);
        }

        // compute commitment to folded Eval  [∑ᵢλᵢfᵢ(aᵢ)]G₁
        Bn254.G1Point memory g1 = Bn254.P1();
        Bn254.G1Point memory folded_evals_commit = Bn254.point_mul(g1, folded_evals);

        // compute foldedDigests = ∑ᵢλᵢ[fᵢ(α)]G₁ - [∑ᵢλᵢfᵢ(aᵢ)]G₁
        folded_digests.point_sub_assign(folded_evals_commit);

        // combine the points and the quotients using γᵢ
	    // ∑ᵢλᵢ[p_i]([Hᵢ(α)]G₁)
        for (uint i=0; i<digests.length; i++){
            random_numbers[i] = Fr.mul(random_numbers[i], points[i]);
        }
        Bn254.G1Point memory folded_points_quotients = Bn254.multi_exp(quotients, random_numbers);

        // ∑ᵢλᵢ[f_i(α)]G₁ - [∑ᵢλᵢfᵢ(aᵢ)]G₁ + ∑ᵢλᵢ[p_i]([Hᵢ(α)]G₁)
	    // = [∑ᵢλᵢf_i(α) - ∑ᵢλᵢfᵢ(aᵢ) + ∑ᵢλᵢpᵢHᵢ(α)]G₁
        folded_digests = Bn254.point_add(folded_digests, folded_points_quotients);
        folded_quotients.Y = Fr.sub(0, folded_quotients.Y);

        // pairing check
	    // e([∑ᵢλᵢ(fᵢ(α) - fᵢ(pᵢ) + pᵢHᵢ(α))]G₁, G₂).e([-∑ᵢλᵢ[Hᵢ(α)]G₁), [α]G₂)
        bool check = Bn254.pairingProd2(folded_digests, Bn254.P2(), folded_quotients, g2);
        return check;

    }

}