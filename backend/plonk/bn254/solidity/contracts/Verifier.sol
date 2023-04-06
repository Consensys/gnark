// Warning this code was contributed into gnark here: 
// https://github.com/ConsenSys/gnark/pull/358
// 
// It has not been audited and is provided as-is, we make no guarantees or warranties to its safety and reliability. 
// 
// According to https://eprint.iacr.org/archive/2019/953/1585767119.pdf
pragma solidity ^0.8.0;

import {Bn254} from './crypto/Bn254.sol';
import {Fr} from './crypto/Fr.sol';
import {TranscriptLibrary} from './crypto/Transcript.sol';
import {Polynomials} from './crypto/Polynomials.sol';
import {Types} from './crypto/Types.sol';

// contract PlonkVerifier {
library PlonkVerifier{

    using Bn254 for Bn254.G1Point;
    using Bn254 for Bn254.G2Point;
    using Fr for uint256;
    using TranscriptLibrary for TranscriptLibrary.Transcript;
    using Polynomials for *;
    using Types for *;

    uint256 constant STATE_WIDTH = 3;

    function derive_gamma_beta_alpha_zeta(

        Types.PartialVerifierState memory state,
        Types.Proof memory proof,
        Types.VerificationKey memory vk,
        uint256[] memory public_inputs) internal pure {

        TranscriptLibrary.Transcript memory t = TranscriptLibrary.new_transcript();
        t.set_challenge_name("gamma");

        for (uint256 i = 0; i < vk.permutation_commitments.length; i++) {
            t.update_with_g1(vk.permutation_commitments[i]);
        }
       
        t.update_with_g1(vk.selector_commitments[0]); // ql
        t.update_with_g1(vk.selector_commitments[1]); // qr
        t.update_with_g1(vk.selector_commitments[2]); // qm
        t.update_with_g1(vk.selector_commitments[3]); // qo
        t.update_with_g1(vk.selector_commitments[4]); // qk

        for (uint256 i = 0; i < public_inputs.length; i++) {
            t.update_with_u256(public_inputs[i]);
        }

        t.update_with_g1(proof.wire_commitments[3]); // PI2
        t.update_with_g1(proof.wire_commitments[0]); // [L]
        t.update_with_g1(proof.wire_commitments[1]); // [R]
        t.update_with_g1(proof.wire_commitments[2]); // [O]

        state.gamma = t.get_challenge();

        t.set_challenge_name("beta");
        state.beta = t.get_challenge();

        t.set_challenge_name("alpha");
        t.update_with_g1(proof.grand_product_commitment);
        state.alpha = t.get_challenge();

        t.set_challenge_name("zeta");
        for (uint256 i = 0; i < proof.quotient_poly_commitments.length; i++) {
            t.update_with_g1(proof.quotient_poly_commitments[i]);
        }
        state.zeta = t.get_challenge();

    }

    function verify_initial(
        Types.PartialVerifierState memory state,
        Types.Proof memory proof,
        Types.VerificationKey memory vk,
        uint256[] memory public_inputs) internal view returns (bool) {
        
        derive_gamma_beta_alpha_zeta(state, proof, vk, public_inputs);

        uint256 num_inputs = public_inputs.length;
        uint256[] memory lagrange_poly_numbers = new uint256[](num_inputs);
        for (uint256 i = 0; i < num_inputs; i++) {
            lagrange_poly_numbers[i] = i;
        }
        state.cached_lagrange_evals = batch_evaluate_lagrange_poly_out_of_domain(
            lagrange_poly_numbers,
            vk.domain_size,
            vk.omega, state.zeta
        );

        bool valid = verify_quotient_poly_eval_at_zeta(state, proof, vk, public_inputs);
        return valid;
    }

    function verify_commitments(
        Types.PartialVerifierState memory state,
        Types.Proof memory proof,
        Types.VerificationKey memory vk
    ) internal view returns (bool) {
        Bn254.G1Point memory d = reconstruct_d(state, proof, vk);

        Bn254.G1Point memory tmp_g1 = Bn254.P1();

        uint256 aggregation_challenge = 1;

        Bn254.G1Point memory commitment_aggregation = Bn254.copy_g1(state.cached_fold_quotient_ploy_commitments);
        uint256 tmp_fr = 1;

        aggregation_challenge.mul_assign(state.v);
        commitment_aggregation.point_add_assign(d);

        for (uint i = 0; i < proof.wire_commitments.length; i++) {
            aggregation_challenge.mul_assign(state.v);
            tmp_g1 = proof.wire_commitments[i].point_mul(aggregation_challenge);
            commitment_aggregation.point_add_assign(tmp_g1);
        }

        for (uint i = 0; i < vk.permutation_commitments.length - 1; i++) {
            aggregation_challenge.mul_assign(state.v);
            tmp_g1 = vk.permutation_commitments[i].point_mul(aggregation_challenge);
            commitment_aggregation.point_add_assign(tmp_g1);
        }

        // collect opening values
        aggregation_challenge = 1;

        uint256 aggregated_value = proof.quotient_polynomial_at_zeta;

        aggregation_challenge.mul_assign(state.v);

        tmp_fr = proof.linearization_polynomial_at_zeta;
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);

        for (uint i = 0; i < proof.wire_values_at_zeta.length; i++) {
            aggregation_challenge.mul_assign(state.v);

            tmp_fr = proof.wire_values_at_zeta[i];
            tmp_fr.mul_assign(aggregation_challenge);
            aggregated_value.add_assign(tmp_fr);
        }

        for (uint i = 0; i < proof.permutation_polynomials_at_zeta.length; i++) {
            aggregation_challenge.mul_assign(state.v);

            tmp_fr = proof.permutation_polynomials_at_zeta[i];
            tmp_fr.mul_assign(aggregation_challenge);
            aggregated_value.add_assign(tmp_fr);
        }
        tmp_fr = proof.grand_product_at_zeta_omega;
        tmp_fr.mul_assign(state.u);
        aggregated_value.add_assign(tmp_fr);

        commitment_aggregation.point_sub_assign(Bn254.P1().point_mul(aggregated_value));

        Bn254.G1Point memory pair_with_generator = commitment_aggregation;
        pair_with_generator.point_add_assign(proof.opening_at_zeta_proof.point_mul(state.zeta));

        tmp_fr = state.zeta;
        tmp_fr.mul_assign(vk.omega);
        tmp_fr.mul_assign(state.u);
        pair_with_generator.point_add_assign(proof.opening_at_zeta_omega_proof.point_mul(tmp_fr));

        Bn254.G1Point memory pair_with_x = proof.opening_at_zeta_omega_proof.point_mul(state.u);
        pair_with_x.point_add_assign(proof.opening_at_zeta_proof);
        pair_with_x.negate();

        return Bn254.pairingProd2(pair_with_generator, Bn254.P2(), pair_with_x, vk.g2_x);
    }

    function reconstruct_d(
        Types.PartialVerifierState memory state,
        Types.Proof memory proof,
        Types.VerificationKey memory vk
    ) internal view returns (Bn254.G1Point memory res) {
        res = Bn254.copy_g1(vk.selector_commitments[STATE_WIDTH + 1]);

        Bn254.G1Point memory tmp_g1 = Bn254.P1();
        uint256 tmp_fr = 0;

        // addition gates
        for (uint256 i = 0; i < STATE_WIDTH; i++) {
            tmp_g1 = vk.selector_commitments[i].point_mul(proof.wire_values_at_zeta[i]);
            res.point_add_assign(tmp_g1);
        }

        // multiplication gate
        tmp_fr = proof.wire_values_at_zeta[0];
        tmp_fr.mul_assign(proof.wire_values_at_zeta[1]);
        tmp_g1 = vk.selector_commitments[STATE_WIDTH].point_mul(tmp_fr);
        res.point_add_assign(tmp_g1);

        // z * non_res * beta + gamma + a
        uint256 grand_product_part_at_z = state.zeta;
        grand_product_part_at_z.mul_assign(state.beta);
        grand_product_part_at_z.add_assign(proof.wire_values_at_zeta[0]);
        grand_product_part_at_z.add_assign(state.gamma);
        for (uint256 i = 0; i < vk.permutation_non_residues.length; i++) {
            tmp_fr = state.zeta;
            tmp_fr.mul_assign(vk.permutation_non_residues[i]);
            tmp_fr.mul_assign(state.beta);
            tmp_fr.add_assign(state.gamma);
            tmp_fr.add_assign(proof.wire_values_at_zeta[i+1]);

            grand_product_part_at_z.mul_assign(tmp_fr);
        }

        grand_product_part_at_z.mul_assign(state.alpha);

        //tmp_fr = state.cached_lagrange_evals[0];
        tmp_fr = Polynomials.compute_ith_lagrange_at_z(0, state.zeta, vk.omega, vk.domain_size);
        tmp_fr = Fr.mul(tmp_fr, state.alpha);
        tmp_fr.mul_assign(state.alpha);
        // NOTICE
        grand_product_part_at_z = Fr.sub(grand_product_part_at_z, tmp_fr);
        uint256 last_permutation_part_at_z = 1;
        for (uint256 i = 0; i < proof.permutation_polynomials_at_zeta.length; i++) {
            tmp_fr = state.beta;
            tmp_fr.mul_assign(proof.permutation_polynomials_at_zeta[i]);
            tmp_fr.add_assign(state.gamma);
            tmp_fr.add_assign(proof.wire_values_at_zeta[i]);

            last_permutation_part_at_z.mul_assign(tmp_fr);
        }

        last_permutation_part_at_z.mul_assign(state.beta);
        last_permutation_part_at_z.mul_assign(proof.grand_product_at_zeta_omega);
        last_permutation_part_at_z.mul_assign(state.alpha);

        // gnark implementation: add third part and sub second second part
        // plonk paper implementation: add second part and sub third part
        /*
        tmp_g1 = proof.grand_product_commitment.point_mul(grand_product_part_at_z);
        tmp_g1.point_sub_assign(vk.permutation_commitments[STATE_WIDTH - 1].point_mul(last_permutation_part_at_z));
        */
        // add to the linearization

        tmp_g1 = vk.permutation_commitments[STATE_WIDTH - 1].point_mul(last_permutation_part_at_z);
        tmp_g1.point_sub_assign(proof.grand_product_commitment.point_mul(grand_product_part_at_z));
        res.point_add_assign(tmp_g1);

        generate_uv_challenge(state, proof, vk, res);

        res.point_mul_assign(state.v);
        res.point_add_assign(proof.grand_product_commitment.point_mul(state.u));
    }

    // gnark v generation process:
    // sha256(zeta, proof.quotient_poly_commitments, linearizedPolynomialDigest, proof.wire_commitments, vk.permutation_commitments[0..1], )
    // NOTICE: gnark use "gamma" name for v, it's not reasonable
    // NOTICE: gnark use zeta^(n+2) which is a bit different with plonk paper
    // generate_v_challenge();
    function generate_uv_challenge(
        Types.PartialVerifierState memory state,
        Types.Proof memory proof,
        Types.VerificationKey memory vk,
        Bn254.G1Point memory linearization_point) view internal {

        TranscriptLibrary.Transcript memory transcript = TranscriptLibrary.new_transcript();
        transcript.set_challenge_name("gamma");
        transcript.update_with_fr(state.zeta);
        uint256 zeta_plus_two = state.zeta;
        uint256 n_plus_two = vk.domain_size;

        n_plus_two.add_assign(2);
        zeta_plus_two = zeta_plus_two.pow(n_plus_two);
        state.cached_fold_quotient_ploy_commitments = Bn254.copy_g1(proof.quotient_poly_commitments[STATE_WIDTH-1]);
        for (uint256 i = 0; i < STATE_WIDTH - 1; i++) {
            state.cached_fold_quotient_ploy_commitments.point_mul_assign(zeta_plus_two);
            state.cached_fold_quotient_ploy_commitments.point_add_assign(proof.quotient_poly_commitments[STATE_WIDTH - 2 - i]);
        }
        transcript.update_with_g1(state.cached_fold_quotient_ploy_commitments);
        transcript.update_with_g1(linearization_point);

        for (uint256 i = 0; i < proof.wire_commitments.length; i++) {
            transcript.update_with_g1(proof.wire_commitments[i]);
        }
        for (uint256 i = 0; i < vk.permutation_commitments.length - 1; i++) {
            transcript.update_with_g1(vk.permutation_commitments[i]);
        }
        state.v = transcript.get_challenge();
        // gnark use local randomness to generate u
        // we use opening_at_zeta_proof and opening_at_zeta_omega_proof
        transcript.set_challenge_name("u");
        transcript.update_with_g1(proof.opening_at_zeta_proof);
        transcript.update_with_g1(proof.opening_at_zeta_omega_proof);
        state.u = transcript.get_challenge();
    }

    function batch_evaluate_lagrange_poly_out_of_domain(
        uint256[] memory poly_nums,
        uint256 domain_size,
        uint256 omega,
        uint256 at
    ) internal view returns (uint256[] memory res) {
        uint256 one = 1;
        uint256 tmp_1 = 0;
        uint256 tmp_2 = domain_size;
        uint256 vanishing_at_zeta = at.pow(domain_size);
        vanishing_at_zeta = Fr.sub(vanishing_at_zeta, one);
        // we can not have random point z be in domain
        require(vanishing_at_zeta != 0);
        uint256[] memory nums = new uint256[](poly_nums.length);
        uint256[] memory dens = new uint256[](poly_nums.length);

        // numerators in a form omega^i * (z^n - 1)
        // denoms in a form (z - omega^i) * N
        for (uint i = 0; i < poly_nums.length; i++) {
            tmp_1 = omega.pow(poly_nums[i]); // power of omega
            nums[i] = vanishing_at_zeta;
            nums[i].mul_assign(tmp_1);

            dens[i] = at; // (X - omega^i) * N
            dens[i] = Fr.sub(dens[i],tmp_1);
            dens[i].mul_assign(tmp_2); // mul by domain size
        }

        uint256[] memory partial_products = new uint256[](poly_nums.length);
        partial_products[0] = 1;
        for (uint i = 1; i < dens.length; i++) {
            partial_products[i] = dens[i-1];
            partial_products[i].mul_assign(partial_products[i-1]);
        }

        tmp_2 = partial_products[partial_products.length - 1];
        tmp_2.mul_assign(dens[dens.length - 1]);
        tmp_2 = tmp_2.inverse(); // tmp_2 contains a^-1 * b^-1 (with! the last one)

        for (uint i = dens.length; i > 0; i--) {
            tmp_1 = tmp_2; // all inversed
            tmp_1.mul_assign(partial_products[i-1]); // clear lowest terms
            tmp_2.mul_assign(dens[i-1]);
            dens[i-1] = tmp_1;
        }

        for (uint i = 0; i < nums.length; i++) {
            nums[i].mul_assign(dens[i]);
        }

        return nums;
    }

    // plonk paper verify process step8: Compute quotient polynomial evaluation
    function verify_quotient_poly_eval_at_zeta(
        Types.PartialVerifierState memory state,
        Types.Proof memory proof,
        Types.VerificationKey memory vk,
        uint256[] memory public_inputs
    ) internal view returns (bool) {

        uint256 lhs = evaluate_vanishing(vk.domain_size, state.zeta);

        require(lhs != 0); // we can not check a polynomial relationship if point z is in the domain
        lhs.mul_assign(proof.quotient_polynomial_at_zeta);

        uint256 quotient_challenge = 1;
        uint256 rhs = proof.linearization_polynomial_at_zeta;

        // public inputs
        // uint256 tmp = 0;
        uint256 tmp = Polynomials.compute_sum_li_zi(public_inputs, state.zeta, vk.omega, vk.domain_size);
        // for (uint256 i = 0; i < proof.input_values.length; i++) {
        //     tmp = state.cached_lagrange_evals[i];
        //     tmp.mul_assign(proof.input_values[i]);
        //     rhs.add_assign(tmp);
        // }
        rhs = Fr.add(rhs, tmp);

        quotient_challenge.mul_assign(state.alpha);

        uint256 z_part = proof.grand_product_at_zeta_omega;
        for (uint256 i = 0; i < proof.permutation_polynomials_at_zeta.length; i++) {
            tmp = proof.permutation_polynomials_at_zeta[i];
            tmp.mul_assign(state.beta);
            tmp.add_assign(state.gamma);
            tmp.add_assign(proof.wire_values_at_zeta[i]);

            z_part.mul_assign(tmp);
        }

        tmp = state.gamma;
        // we need a wire value of the last polynomial in enumeration
        tmp.add_assign(proof.wire_values_at_zeta[STATE_WIDTH - 1]);

        z_part.mul_assign(tmp);
        z_part.mul_assign(quotient_challenge);

        // NOTICE: this is different with plonk paper
        // plonk paper should be: rhs.sub_assign(z_part);
        rhs.add_assign(z_part);

        quotient_challenge.mul_assign(state.alpha);

        //tmp = state.cached_lagrange_evals[0]);
        uint256 lagrange_one = Polynomials.compute_ith_lagrange_at_z(0, state.zeta, vk.omega, vk.domain_size);
        tmp = Fr.mul(quotient_challenge, lagrange_one);
        // tmp.mul_assign(quotient_challenge);

        rhs = Fr.sub(rhs, tmp);

        return lhs == rhs;
    }

    function evaluate_vanishing(
        uint256 domain_size,
        uint256 at
    ) internal view returns (uint256 res) {
        res = at.pow(domain_size);
        res = Fr.sub(res, 1);
    }

	// This verifier is for a PLONK with a state width 3
    // and main gate equation
    // q_a(X) * a(X) + 
    // q_b(X) * b(X) + 
    // q_c(X) * c(X) +
    // q_m(X) * a(X) * b(X) + 
    // q_constants(X)+
    // where q_{}(X) are selectors a, b, c - state (witness) polynomials
    
    function verify(Types.Proof memory proof, Types.VerificationKey memory vk, uint256[] memory public_inputs) internal view returns (bool) {
        
        Types.PartialVerifierState memory state;
        
        bool valid = verify_initial(state, proof, vk, public_inputs);
        
        if (valid == false) {
            return false;
        }
        
        valid = verify_commitments(state, proof, vk);
        
        return valid;
    }
}

