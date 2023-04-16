pragma solidity ^0.8.0;
import './crypto/Types.sol';
import './crypto/Bn254.sol';

library Marshal {
    uint256 constant SERIALIZED_PROOF_LENGTH = 26;

    function read_uint256(bytes calldata b, uint256 i) internal pure returns (uint256, uint256 offset) {
        return (uint256(bytes32(b[i:i+32])), i+32);
    }

    function read_uint64(bytes calldata b, uint256 i) internal pure returns (uint64, uint256 offset) {
        return (uint64(bytes8(b[i:i+8])), i+8);
    }
    
    function read_uint32(bytes calldata b, uint256 i) internal pure returns (uint32, uint256 offset) {
        return (uint32(bytes4(b[i:i+4])), i+4);
    }

    function read_g1_checked(bytes calldata b, uint256 i) internal pure returns (Bn254.G1Point memory p, uint256 offset) {
        uint256 t1;
        uint256 t2;
        (t1, offset) = read_uint256(b, i);
        (t2, offset) = read_uint256(b, offset);
        return (Bn254.new_g1_checked(t1, t2), offset);
    }

    function read_g1(bytes calldata b, uint256 i) internal pure returns (Bn254.G1Point memory p, uint256 offset) {
        (p.X, offset) = read_uint256(b, i);
        (p.Y, offset) = read_uint256(b, offset);
    }

    function read_g2(bytes calldata b, uint256 i) internal pure returns (Bn254.G2Point memory p, uint256 offset) {
        (p.X[0], offset) = read_uint256(b, i);
        (p.X[1], offset) = read_uint256(b, offset);
        (p.Y[0], offset) = read_uint256(b, offset);
        (p.Y[1], offset) = read_uint256(b, offset);
    }

    function deserialize_vk(
        uint256[] calldata kzg,
        bytes calldata preprocessed
    ) internal pure returns (Types.VerificationKey memory vk) {
        require(kzg.length == 10);
        // TODO Check points 0 and 2 for correctness
        vk.g2_x.X[0] = kzg[5];
        vk.g2_x.X[1] = kzg[6];
        vk.g2_x.Y[0] = kzg[7];
        vk.g2_x.Y[1] = kzg[8];

        uint256 offset = 0;
        uint64 temp;
        
        (temp, offset) = read_uint64(preprocessed, offset);
        vk.domain_size = uint256(temp); // size

        offset += 32; // skip size_inv
        (vk.omega, offset) = read_uint256(preprocessed, offset); // generator
        offset += 8;    // skip nb_public_variables TODO: Deserialize public vars
        (vk.coset_shift, offset) = read_uint256(preprocessed, offset); // coset_shift
        (vk.permutation_commitments[0], offset) = read_g1(preprocessed, offset);
        (vk.permutation_commitments[1], offset) = read_g1(preprocessed, offset);
        (vk.permutation_commitments[2], offset) = read_g1(preprocessed, offset);

        (vk.selector_commitments[0], offset) = read_g1(preprocessed, offset);   // ql
        (vk.selector_commitments[1], offset) = read_g1(preprocessed, offset);   // qr
        (vk.selector_commitments[2], offset) = read_g1(preprocessed, offset);   // qm
        (vk.selector_commitments[3], offset) = read_g1(preprocessed, offset);   // qo
        (vk.selector_commitments[4], offset) = read_g1(preprocessed, offset);   // qc
        (vk.selector_commitments[5], offset) = read_g1(preprocessed, offset);   // qcp
    }

    function deserialize_proof(
        bytes calldata serialized_proof
    ) internal pure returns(Types.Proof memory proof) {
        require(serialized_proof.length == SERIALIZED_PROOF_LENGTH);

        uint256 j = 0;

        for (uint256 i = 0; i < 3; i++) {     // LRO
            (proof.wire_commitments[i], j) = read_g1_checked(serialized_proof, j);
        }

        (proof.grand_product_commitment, j) = read_g1_checked(serialized_proof, j);      // Z

        for (uint256 i = 0; i < 3; i++) {         // H
            (proof.quotient_poly_commitments[i], j) = read_g1_checked(serialized_proof, j);
        }

        (proof.opening_at_zeta_proof, j) = read_g1_checked(serialized_proof, j);
    
        // <BACTHED CLAIMED VALUES>
        uint32 nb_batched_comms;
       (nb_batched_comms, j) = read_uint32(serialized_proof, j);
       require(nb_batched_comms == 8);

        (proof.quotient_polynomial_at_zeta, j) = read_uint256(serialized_proof, j);
        nb_batched_comms--;

        (proof.linearization_polynomial_at_zeta, j) = read_uint256(serialized_proof, j);
        nb_batched_comms--;

        for (uint256 i = 0; i < 3; i++) {
            (proof.wire_values_at_zeta[i], j) = read_uint256(serialized_proof, j);
            nb_batched_comms--;
        }

        for (uint256 i = 0; i < proof.permutation_polynomials_at_zeta.length; i++) {
            (proof.permutation_polynomials_at_zeta[i], j) = read_uint256(serialized_proof, j);
            nb_batched_comms--;
        }

        (proof.qcp_at_zeta, j) = read_uint256(serialized_proof, j);
        nb_batched_comms--;

        require(nb_batched_comms == 0);

        // </BACTHED CLAIMED VALUES>

        (proof.opening_at_zeta_omega_proof, j) = read_g1_checked(serialized_proof, j);

        (proof.grand_product_at_zeta_omega, j) = read_uint256(serialized_proof, j);

        (proof.bsb22_commitment, j) = read_g1_checked(serialized_proof, j);

        require(j == serialized_proof.length);
    }
}