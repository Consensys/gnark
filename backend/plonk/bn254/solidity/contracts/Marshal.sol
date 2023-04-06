pragma solidity ^0.8.0;
import './crypto/Types.sol';

library Marshal {
    uint256 constant SERIALIZED_PROOF_LENGTH = 26;
    function deserialize_proof(
        uint256[] memory public_inputs,
        uint256[] memory serialized_proof
    ) internal pure returns(Types.Proof memory proof) {
        require(serialized_proof.length == SERIALIZED_PROOF_LENGTH);
        proof.input_values = new uint256[](public_inputs.length);
        for (uint256 i = 0; i < public_inputs.length; i++) {
            proof.input_values[i] = public_inputs[i];
        }

        uint256 j = 0;
        for (uint256 i = 0; i < Types.STATE_WIDTH; i++) {     // LRO
            proof.wire_commitments[i] = Bn254.new_g1_checked(
                serialized_proof[j],
                serialized_proof[j+1]
            );

            j += 2;
        }

        proof.grand_product_commitment = Bn254.new_g1_checked(      // Z
            serialized_proof[j],
            serialized_proof[j+1]
        );
        j += 2;

        for (uint256 i = 0; i < Types.STATE_WIDTH; i++) {         // H
            proof.quotient_poly_commitments[i] = Bn254.new_g1_checked(
                serialized_proof[j],
                serialized_proof[j+1]
            );

            j += 2;
        }

        proof.opening_at_zeta_proof = Bn254.new_g1_checked(
            serialized_proof[j],
            serialized_proof[j+1]
        );
        j += 2;

        // <BACTHED CLAIMED VALUES>

        proof.quotient_polynomial_at_zeta = Bn254.new_fr(serialized_proof[j]);
        j += 1;

        proof.linearization_polynomial_at_zeta = Bn254.new_fr(serialized_proof[j]);
        j += 1;

        for (uint256 i = 0; i < Types.STATE_WIDTH; i++) {
            proof.wire_values_at_zeta[i] = Bn254.new_fr(serialized_proof[j]);
            j += 1;
        }

        for (uint256 i = 0; i < proof.permutation_polynomials_at_zeta.length; i++) {
            proof.permutation_polynomials_at_zeta[i] = Bn254.new_fr(serialized_proof[j]);
            j += 1;
        }

        proof.qcp_at_zeta = Bn254.new_fr(serialized_proof[j]);
        j += 1;

        // </BACTHED CLAIMED VALUES>

        proof.opening_at_zeta_omega_proof = Bn254.new_g1_checked(
            serialized_proof[j],
            serialized_proof[j+1]
        );
        j+= 2;

        proof.grand_product_at_zeta_omega = Bn254.new_fr(serialized_proof[j]);
        j+= 1;

        proof.bsb22_commitment = Bn254.new_g1_checked(
            serialized_proof[j],
            serialized_proof[j+1]
        );
        j+= 2;

        require(j == serialized_proof.length);
    }
}