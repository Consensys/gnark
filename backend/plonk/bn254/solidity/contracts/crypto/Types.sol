// It has not been audited and is provided as-is, we make no guarantees or warranties to its safety and reliability. 
// 
// According to https://eprint.iacr.org/archive/2019/953/1585767119.pdf
pragma solidity >=0.6.0;

import {Bn254} from './Bn254.sol';
import {Kzg} from './Kzg.sol';

library Types {

    using Bn254 for *;
    using Kzg for *;

    int256 constant STATE_WIDTH = 3;

    struct VerificationKey {
        uint256 domain_size;
        uint256 omega;                                          // w
        //Bn254.G1Point[STATE_WIDTH+3] selector_commitments;    // [ql], [qr], [qm], [qo], [qk], [qcp]
        Bn254.G1Point[STATE_WIDTH+2] selector_commitments;      // [ql], [qr], [qm], [qo], [qk]
        Bn254.G1Point[] selector_commitments_commit_api;        // [qcp_i]
        Bn254.G1Point[STATE_WIDTH] permutation_commitments;     // [Sσ1(x)],[Sσ2(x)],[Sσ3(x)]
        uint256 coset_shift;                                    // generator of Fr*
        Bn254.G2Point g2_x;                                     // SRS.G2[1]
        uint256[] commitment_indices;                           // indices of the public wires resulting from the hash.

    }

    struct Proof {
        //Bn254.G1Point[STATE_WIDTH+1] wire_commitments;        // [a(x)]/[b(x)]/[c(x)]/[PI2(x)]
        Bn254.G1Point[STATE_WIDTH] wire_commitments;            // [a(x)]/[b(x)]/[c(x)]
        Bn254.G1Point[] wire_committed_commitments;             // commitment to the wires committed using Commit api
        Bn254.G1Point grand_product_commitment;                 // [z(x)]
        Bn254.G1Point[STATE_WIDTH] quotient_poly_commitments;   // [t_lo]/[t_mid]/[t_hi]
        uint256[STATE_WIDTH] wire_values_at_zeta;               // a(zeta)/b(zeta)/c(zeta)
        uint256 grand_product_at_zeta_omega;                    // z(w*zeta)
        uint256 quotient_polynomial_at_zeta;                    // t(zeta)
        uint256 linearization_polynomial_at_zeta;               // r(zeta)
        uint256[] selector_commit_api_at_zeta;                  // qc_i(zeta)
        uint256[STATE_WIDTH-1] permutation_polynomials_at_zeta; // Sσ1(zeta),Sσ2(zeta)

        Bn254.G1Point opening_at_zeta_proof;            // [Wzeta]
        Bn254.G1Point opening_at_zeta_omega_proof;      // [Wzeta*omega]
        Bn254.G1Point bsb22_commitment; // PI2
    }

    struct State {
     
        // challenges to check the claimed quotient
        uint256 alpha;
        uint256 beta;
        uint256 gamma;
        uint256 zeta;

        // challenges related to KZG
        uint256 v;
        uint256 u;

        // reusable value
        uint256 alpha_square_lagrange;

        // commitment to H
        Bn254.G1Point folded_h;

        // commitment to the linearised polynomial
        Bn254.G1Point linearised_polynomial;

        // Folded proof for the opening of H, linearised poly, l, r, o, s_1, s_2, qcp
        Kzg.OpeningProof folded_proof;

        // folded digests of H, linearised poly, l, r, o, s_1, s_2, qcp
        Bn254.G1Point folded_digests;

    }

}