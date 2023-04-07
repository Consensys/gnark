// Warning this code was contributed into gnark here: 
// https://github.com/ConsenSys/gnark/pull/358
// 
// It has not been audited and is provided as-is, we make no guarantees or warranties to its safety and reliability. 
// 
// According to https://eprint.iacr.org/archive/2019/953/1585767119.pdf
pragma solidity ^0.8.0;

import {Bn254} from './Bn254.sol';

library Types {

    using Bn254 for *;

    int256 constant STATE_WIDTH = 3;

    struct VerificationKey {
        uint256 domain_size;
        uint256 omega;                                     // w
        Bn254.G1Point[STATE_WIDTH+3] selector_commitments;  // [ql], [qr], [qm], [qo], [qk], [qcp]
        Bn254.G1Point[STATE_WIDTH] permutation_commitments; // [Sσ1(x)],[Sσ2(x)],[Sσ3(x)]
        uint256[STATE_WIDTH-1] permutation_non_residues;   // k1, k2
        Bn254.G2Point g2_x;
        uint256 commitmentIndex;                             // index of the public wire resulting from the hash
    }

    struct Proof {
        Bn254.G1Point[STATE_WIDTH+1] wire_commitments;  // [a(x)]/[b(x)]/[c(x)]/[PI2(x)]
        Bn254.G1Point grand_product_commitment;      // [z(x)]
        Bn254.G1Point[STATE_WIDTH] quotient_poly_commitments;  // [t_lo]/[t_mid]/[t_hi]
        uint256[STATE_WIDTH] wire_values_at_zeta;   // a(zeta)/b(zeta)/c(zeta)
        uint256 grand_product_at_zeta_omega;        // z(w*zeta)
        uint256 quotient_polynomial_at_zeta;        // t(zeta)
        uint256 linearization_polynomial_at_zeta;   // r(zeta)
        uint256 qcprime_at_zeta;                     // qc'(zeta)
        uint256[STATE_WIDTH-1] permutation_polynomials_at_zeta;  // Sσ1(zeta),Sσ2(zeta)
        uint256 qcp_at_zeta;

        Bn254.G1Point opening_at_zeta_proof;            // [Wzeta]
        Bn254.G1Point opening_at_zeta_omega_proof;      // [Wzeta*omega]
        Bn254.G1Point bsb22_commitment; // PI2
    }

    struct PartialVerifierState {
        uint256 alpha;
        uint256 beta;
        uint256 gamma;
        uint256 v;
        uint256 u;
        uint256 zeta;
        uint256[] cached_lagrange_evals;

        Bn254.G1Point cached_fold_quotient_ploy_commitments;
    }

}