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
        // H = (h_x, h_y) quotient polynomial (f - f(z))/(x-z)
        //Bn254.G1Point H;
        uint256 h_x;
        uint256 h_y;

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

    function copy_opening_proof(OpeningProof memory src, OpeningProof memory dst)
    internal pure {
        assembly {
            mstore(src, mload(dst))
            mstore(add(src, 0x20), mload(add(dst, 0x20)))
            mstore(add(src, 0x40), mload(add(dst, 0x40)))
        }
    }

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

         // fold the claimed values
        uint256[] memory gammai = new uint256[](digests.length);
        uint256 r = Fr.r_mod;
        assembly {
            
            // opening_proof.H <- batch_opening_proof.H
            mstore(opening_proof, mload(add(batch_opening_proof, 0x40)))
            mstore(add(opening_proof,0x20), mload(add(batch_opening_proof, 0x60)))

            // opening_proof.claimed_value <- \sum_i batch_opening_proof.claimed_values[i]*gamma[i]
            // gammai <- [1,\gamma,..,\gamma^n]
            mstore(add(gammai,0x20), 1)
            let claimed_value_i := add(batch_opening_proof,0xa0)
            mstore(add(opening_proof,0x40), mload(claimed_value_i))
            let tmp := mload(0x40)
            let n := mload(digests)
            let prev_gamma := add(gammai,0x20)
            for {let i:=1} lt(i,n) {i:=add(i,1)}
            {
                claimed_value_i := add(claimed_value_i, 0x20)
                mstore(add(prev_gamma,0x20), mulmod(mload(prev_gamma),gamma,r))
                mstore(tmp, mulmod(mload(add(prev_gamma,0x20)), mload(claimed_value_i), r))
                mstore(add(opening_proof,0x40), addmod(mload(add(opening_proof,0x40)),  mload(tmp), r))
                prev_gamma := add(prev_gamma,0x20)
            }
        }

        // TODO hardcode the multi exp in the previous chunk ?
        folded_digests = Bn254.multi_exp(digests, gammai);

        return (opening_proof, folded_digests);
    }

    // returns \sum_i [lambda^{i}p_i]H_i \sum_i [lambda^{i)]H_i, \sum_i [lambda_i]Comm_i, \sum_i lambda^i*p_i
    function fold_digests_quotients_evals(uint256[] memory lambda, uint256[] memory points, Bn254.G1Point[] memory digests, OpeningProof[] memory proofs)
    internal returns(
        Bn254.G1Point memory res_quotient, 
        Bn254.G1Point memory res_digest,
        Bn254.G1Point memory res_points_quotients,
        uint256 res_eval)
    {

        uint256 r = Fr.r_mod;

        assembly {

            // res_quotient <- proofs[0].H
            let proof_i := add(proofs, mul(add(mload(proofs),1),0x20))
            mstore(res_quotient, mload(proof_i))
            mstore(add(res_quotient, 0x20), mload(add(proof_i, 0x20)))

            // res_digest <- digests[0]
            let digest_i := add(digests, mul(add(mload(digests),1), 0x20))
            mstore(res_digest, mload(digest_i))
            mstore(add(res_digest, 0x20), mload(add(digest_i, 0x20)))

            // dst <- [s]src
            function point_mul_local(dst,src,s) {
                let buf := mload(0x40)
                mstore(buf,mload(src))
                mstore(add(buf,0x20),mload(add(src,0x20)))
                mstore(add(buf,0x40),mload(s))
                pop(staticcall(gas(),7,buf,0x60,dst,0x40)) // TODO should we check success here ?
            }

            // dst <- dst + [s]src
            function point_acc_mul_local(dst,src,s) {
                let buf := mload(0x40)
                mstore(buf,mload(src))
                mstore(add(buf,0x20),mload(add(src,0x20)))
                mstore(add(buf,0x40),mload(s))
                pop(staticcall(gas(),7,buf,0x60,buf,0x40)) // TODO should we check success here ?
                mstore(add(buf,0x40),mload(dst))
                mstore(add(buf,0x60),mload(add(dst,0x20)))
                pop(staticcall(gas(),6,buf,0x80,dst, 0x40))
            }

            // dst <- dst + [ a*b [r] ]src
            function point_acc_mul_mul_local(dst,src,a,b,rmod) {
                let buf := mload(0x40)
                mstore(buf,mload(src))
                mstore(add(buf,0x20),mload(add(src,0x20)))
                mstore(add(buf,0x40),mulmod(mload(a),mload(b),rmod))
                pop(staticcall(gas(),7,buf,0x60,buf,0x40)) // TODO should we check success here ?
                mstore(add(buf,0x40),mload(dst))
                mstore(add(buf,0x60),mload(add(dst,0x20)))
                pop(staticcall(gas(),6,buf,0x80,dst, 0x40))
            }

            // res_points_quotients <- [points[0]]*proofs[0].H
            let point_i := add(points,0x20)
            point_mul_local(res_points_quotients, proof_i, point_i)

            // res_eval <- proofs[0].claimed_value
            res_eval:= mload(add(proof_i, 0x40))

            let lambda_i := add(lambda,0x20)

            for {let i:=1} lt(i,mload(proofs)) {i:=add(i,1)}
            {

                digest_i := add(digest_i,0x40)
                proof_i := add(proof_i,0x60)
                lambda_i := add(lambda_i,0x20)
                point_i := add(point_i,0x20)

                // res_quotient <- res_quotient + [\lambda_i]proof[i].H
                point_acc_mul_local(res_quotient, proof_i, lambda_i)
                   
                // res_digest <- res_digest + [\lambda_i]digest[i]
                point_acc_mul_local(res_digest, digest_i, lambda_i)

                // res_point_quotient <- [\lambda_i point[i]]proof[i].H
                point_acc_mul_mul_local(res_points_quotients, proof_i, lambda_i, point_i, r)
                
                res_eval := addmod(res_eval,mulmod(mload(lambda_i),mload(add(proof_i,0x40)),r),r)
            }
        }

        return (res_points_quotients, res_digest, res_quotient, res_eval);

    }

    function batch_verify_multi_points(Bn254.G1Point[] memory digests, OpeningProof[] memory proofs, uint256[] memory points, Bn254.G2Point memory g2)
    internal returns(bool)
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