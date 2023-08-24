package groth16

// solidityTemplate
// this is an experimental feature and gnark solidity generator as not been thoroughly tested
const solidityTemplate = `
{{- $numPublic := sub (len .G1.K) 1 }}
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Verifier {
    
    // Some of the provided public input values are larger than the field modulus.
    // Public input elements are not automatically reduced, as this is can be
    // a dangerous source of bugs.
    error PublicInputNotInField();

    // The proof is invalid. This can mean that provided Groth16 proof points are
    // not on their curves, that pairing equation does not check out, or that
    // the proof is not for the provided public input.
    error ProofInvalid();

    // Addresses of precompiles
    uint256 constant PRECOMPILE_MODEXP = 0x05;
    uint256 constant PRECOMPILE_ADD = 0x06;
    uint256 constant PRECOMPILE_MUL = 0x07;
    uint256 constant PRECOMPILE_VERIFY = 0x08;

    // Base field Fp order P and scalar field Fr order R.
    // For BN254 these are computed as follows:
    //     t = 4965661367192848881
    //     P = 36⋅t⁴ + 36⋅t³ + 24⋅t² + 6⋅t + 1
    //     R = 36⋅t⁴ + 36⋅t³ + 18⋅t² + 6⋅t + 1
    uint256 constant P = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
    uint256 constant R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    // Extension field Fp2 = Fp[i] / (i² + 1)
    // Note: This is the complex extension field of Fp with i² = -1.
    //       Values in Fp2 are represented as a pair of Fp elements (a₀, a₁) as a₀ + a₁⋅i.
    // Note: The order of Fp2 elements is *opposite* that of the pairing contract, which
    //       expects Fp2 elements in order (a₁, a₀). This is also the order in which
    //       Fp2 elements are encoded in the public interface as this became convention.

    // Constants in Fp
    uint256 constant FRACTION_1_2_FP = 0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea4;
    uint256 constant FRACTION_27_82_FP = 0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5;
    uint256 constant FRACTION_3_82_FP = 0x2fcd3ac2a640a154eb23960892a85a68f031ca0c8344b23a577dcf1052b9e775;

    // Exponents for inversions and square roots mod P
    uint256 constant EXP_INVERSE_FP = 0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD45; // P - 2
    uint256 constant EXP_SQRT_FP = 0xC19139CB84C680A6E14116DA060561765E05AA45A1C72A34F082305B61F3F52; // (P + 1) / 4;

    // Groth16 alpha point in G1
    uint256 constant ALPHA_X = {{.G1.Alpha.X.String}};
    uint256 constant ALPHA_Y = {{.G1.Alpha.Y.String}};

    // Groth16 beta point in G2 in powers of i
    uint256 constant BETA_NEG_X_0 = {{.G2.Beta.X.A0.String}};
    uint256 constant BETA_NEG_X_1 = {{.G2.Beta.X.A1.String}};
    uint256 constant BETA_NEG_Y_0 = {{.G2.Beta.Y.A0.String}};
    uint256 constant BETA_NEG_Y_1 = {{.G2.Beta.Y.A1.String}};

    // Groth16 gamma point in G2 in powers of i
    uint256 constant GAMMA_NEG_X_0 = {{.G2.Gamma.X.A0.String}};
    uint256 constant GAMMA_NEG_X_1 = {{.G2.Gamma.X.A1.String}};
    uint256 constant GAMMA_NEG_Y_0 = {{.G2.Gamma.Y.A0.String}};
    uint256 constant GAMMA_NEG_Y_1 = {{.G2.Gamma.Y.A1.String}};

    // Groth16 delta point in G2 in powers of i
    uint256 constant DELTA_NEG_X_0 = {{.G2.Delta.X.A0.String}};
    uint256 constant DELTA_NEG_X_1 = {{.G2.Delta.X.A1.String}};
    uint256 constant DELTA_NEG_Y_0 = {{.G2.Delta.Y.A0.String}};
    uint256 constant DELTA_NEG_Y_1 = {{.G2.Delta.Y.A1.String}};

    // Constant and public input points
    {{- $k0 := index .G1.K 0}}
    uint256 constant CONSTANT_X = {{$k0.X.String}};
    uint256 constant CONSTANT_Y = {{$k0.Y.String}};
    {{- range $i, $ki := .G1.K }}
        {{- if gt $i 0 }}
    uint256 constant PUB_{{sub $i 1}}_X = {{$ki.X.String}};
    uint256 constant PUB_{{sub $i 1}}_Y = {{$ki.Y.String}};
        {{- end }}
    {{- end }}

    // Negation in Fp.
    // The input does not need to be reduced.
    function negate(uint256 a) internal pure returns (uint256 x) {
        unchecked {
            x = (P - (a % P)) % P; // Modulo is cheaper than branching
        }
    }

    // Modular exponentiation in Fp.
    // The input does not need to be reduced.
    function exp(uint256 a, uint256 e) internal view returns (uint256 x) {
        bool success;
        assembly ("memory-safe") {
            let f := mload(0x40)
            mstore(f, 0x20)
            mstore(add(f, 0x20), 0x20)
            mstore(add(f, 0x40), 0x20)
            mstore(add(f, 0x60), a)
            mstore(add(f, 0x80), e)
            mstore(add(f, 0xa0), P)
            success := staticcall(gas(), PRECOMPILE_MODEXP, f, 0xc0, f, 0x20)
            x := mload(f)
        }
        if (!success) {
            // Exponentiation failed.
            // Should not happen.
            revert ProofInvalid();
        }
    }

    // Inverts an element in Fp.
    // The input does not need to be reduced.
    // If the inverse does not exist, the operation reverts.
    function invert_Fp(uint256 a) internal view returns (uint256 x) {
        x = exp(a, EXP_INVERSE_FP);
        if (mulmod(a, x, P) != 1) {
            // Inverse does not exist.
            // Can only happen during G2 point decompression.
            revert ProofInvalid();
        }
    }

    // Square root in Fp.
    // The input must be reduced or the operation reverts.
    // If a square root does not exist, the operation reverts.
    function sqrt_Fp(uint256 a) internal view returns (uint256 x) {
        x = exp(a, EXP_SQRT_FP);
        if (mulmod(x, x, P) != a) {
            // Square root does not exist or `a` is not reduced.
            // Happens when G1 point is not on curve.
            revert ProofInvalid();
        }
    }

    function isSquare_Fp(uint256 a) internal view returns (bool) {
        x = exp(a, EXP_SQRT_FP);
        return mulmod(x, x, P) == a;
    }

    // Square root in Fp2.
    // The input must be reduced or the operation reverts.
    // If a square root does not exist, the operation reverts.
    // The hint parameter is used to pick a sign internally.
    function sqrt_Fp2(uint256 a0, uint256 a1, bool hint) internal view returns (uint256 x0, uint256 x1) {
        // If this square root reverts there is no solution in Fp2.
        uint256 d = sqrt_Fp(addmod(mulmod(a0, a0, P), mulmod(a1, a1, P), P));
        if (hint) {
            d = negate(d);
        }
        // If this square root reverts there is no solution in Fp2.
        x0 = sqrt_Fp(mulmod(addmod(a0, d, P), FRACTION_1_2_FP, P));
        x1 = mulmod(a1, invert_Fp(mulmod(x0, 2, P)), P);

        // Check result.

        require(a0 == addmod(mulmod(x0, x0, P), negate(mulmod(x1, x1, P)), P));
        require(a1 == mulmod(2, mulmod(x0, x1, P), P));
    }

    function compress_g1(uint256 x, uint256 y) internal view returns (uint256 c) {
        if (x >= P || y >= P) {
            // G1 point not in field.
            revert ProofInvalid();
        }
        if (x == 0 && y == 0) {
            // Point at infinity
            return 0;
        }
        // Note: sqrt_Fp reverts if there is no solution, i.e. the x coordinate is invalid.
        y_pos = sqrt_Fp(addmod(mulmod(mulmod(x, x, P), x, P), 3, P));
        y_neg = negate(y);
        if (y == y_pos) {
            return (x << 1) | 0;
        } else if (y == y_neg) {
            return (x << 1) | 1;
        } else {
            // G1 point not on curve.
            revert ProofInvalid();
        }
    }

    // Decompress a point in G1 from a compressed representation.
    // The input is (X << 1 | sign_bit) for regular points and (0) for the point
    // at infinity.
    // If X is not reduced, the operation reverts.
    // If the point is not on the curve, the operation reverts.
    // See <https://2π.com/23/bn254-compression>
    function decompress_g1(uint256 c) internal view returns (uint256 x, uint256 y) {
        // Note that X = 0 is not on the curve since 0³ + 3 = 3 is not a square.
        // so we can use it to represent the point at infinity.
        if (c == 0) {
            // Point at infinity as encoded in EIP196 and EIP197.
            return (0, 0);
        }
        bool negate_point = c & 1 == 1;
        x = c >> 1;
        if (x >= P) {
            // G1 x coordinate not in field.
            revert ProofInvalid();
        }

        // Note: (x³ + 3) is irreducible in Fp, so it can not be zero and therefore
        //       y can not be zero.
        // Note: sqrt_Fp reverts if there is no solution, i.e. the point is not on the curve.
        y = sqrt_Fp(addmod(mulmod(mulmod(x, x, P), x, P), 3, P));
        if (negate_point) {
            y = negate(y);
        }
    }

    function compress_g2(uint256 x0, uint256 x1, uint256 y0, uint256 y1)
    internal view returns (uint256 c0, uint256 c1) {
        if (x0 >= P || x1 >= P || y0 >= P || y1 >= P) {
            // G2 point not in field.
            revert ProofInvalid();
        }
        if ((x0 | x1 | y0 | y1) == 0) {
            // Point at infinity
            return (0, 0);
        }

        // Compute y^2
        uint256 n3ab = mulmod(mulmod(x0, x1, P), P-3, P);
        uint256 a_3 = mulmod(mulmod(x0, x0, P), x0, P);
        uint256 b_3 = mulmod(mulmod(x1, x1, P), x1, P);
        uint256 y0_pos2 = addmod(FRACTION_27_82_FP, addmod(a_3, mulmod(n3ab, x1, P), P), P);
        uint256 y1_pos2 = negate(addmod(FRACTION_3_82_FP,  addmod(b_3, mulmod(n3ab, x0, P), P), P));

        // Determine hint bit
        // If this sqrt fails the x coordinate is not on the curve.
        uint256 d = sqrt_Fp(addmod(mulmod(y0_pos2, y0_pos2, P), mulmod(y1_pos2, y1_pos2, P), P));
        bool hint = !isSquare_Fp2(mulmod(addmod(y0_pos2, d, P), FRACTION_1_2_FP, P))

        // Recover y
        (uint256 y0_pos, uint256 y1_pos) = sqrt_Fp2(y0_pos2, y1_pos2, hint);
        uint256 y0_neg = negate(y0_pos);
        uint256 y1_neg = negate(y1_pos);
        if (y0 == y0_pos && y1 == y1_pos) {
            c0 = (x0 << 2) | (hint ? 2  : 0) | 0;
            c1 = x1;
        } else if (y0 == y0_neg && y1 == y1_neg) {
            c0 = (x0 << 2) | (hint ? 2  : 0) | 1;
            c1 = x1;
        } else {
            // G1 point not on curve.
            revert ProofInvalid();
        }
    }

    // Decompress a point in G2 from a compressed representation.
    // The input is (X₀ << 2 | hint_bit << 1 | sign_bit, X₁) for regular points
    // and (0, 0) for the point at infinity.
    // If X is not reduced, the operation reverts.
    // If the point is not on the curve, the operation reverts.
    // See <https://2π.com/23/bn254-compression>
    function decompress_g2(uint256 c0, uint256 c1)
    internal view returns (uint256 x0, uint256 x1, uint256 y0, uint256 y1) {
        // Note that X = (0, 0) is not on the curve since 0³ + 3/(9 + i) is not a square.
        // so we can use it to represent the point at infinity.
        if (c0 == 0 && c1 == 0) {
            // Point at infinity as encoded in EIP197.
            return (0, 0, 0, 0);
        }
        bool negate_point = c0 & 1 == 1;
        bool hint = c0 & 2 == 2;
        x0 = c0 >> 2;
        x1 = c1;
        if (x0 >= P || x1 >= P) {
            // G2 x0 or x1 coefficient not in field.
            revert ProofInvalid();
        }

        uint256 n3ab = mulmod(mulmod(x0, x1, P), P-3, P);
        uint256 a_3 = mulmod(mulmod(x0, x0, P), x0, P);
        uint256 b_3 = mulmod(mulmod(x1, x1, P), x1, P);

        y0 = addmod(FRACTION_27_82_FP, addmod(a_3, mulmod(n3ab, x1, P), P), P);
        y1 = negate(addmod(FRACTION_3_82_FP,  addmod(b_3, mulmod(n3ab, x0, P), P), P));

        // Note: sqrt_Fp2 reverts if there is no solution, i.e. the point is not on the curve.
        // Note: (X³ + 3/(9 + i)) is irreducible in Fp2, so y can not be zero.
        //       But y0 or y1 may still independently be zero.
        (y0, y1) = sqrt_Fp2(y0, y1, hint);
        if (negate_point) {
            y0 = negate(y0);
            y1 = negate(y1);
        }
    }

    // Compute the public input linear combination.
    // Reverts if the input is not in the field.
    function publicInputMSM(uint256[{{$numPublic}}] calldata input)
    internal view returns (uint256 x, uint256 y) {
        // Note: The ECMUL precompile does not reject unreduced values, so we check this.
        // Note: Unrolling this loop does not cost much extra in code-size, the bulk of the
        //       code-size is in the PUB_ constants.
        // ECMUL has input (x, y, scalar) and output (x', y').
        // ECADD has input (x1, y1, x2, y2) and output (x', y').
        // We call them such that ecmul output is already in the second point
        // argument to ECADD so we can have a tight loop.
        bool success = true;
        assembly ("memory-safe") {
            let f := mload(0x40)
            let g := add(f, 0x40)
            let s
            mstore(f, CONSTANT_X)
            mstore(add(f, 0x20), CONSTANT_Y)
            {{- range $i := intRange $numPublic }}
            mstore(g, PUB_{{$i}}_X)
            mstore(add(g, 0x20), PUB_{{$i}}_Y)
            {{- if eq $i 0 }}
            s :=  calldataload(input)
            {{- else }}
            s :=  calldataload(add(input, {{mul $i 0x20}}))
            {{- end }}
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            {{- end }}
            x := mload(f)
            y := mload(add(f, 0x20))
        }
        if (!success) {
            // Either Public input not in field, or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert PublicInputNotInField();
        }
    }

    function compressProof(uint256[8] calldata proof) internal view returns (uint256[4] compressed) {
        compressed[0] = compress_g1(proof[0], proof[1]);
        compressed[2], compressed[1] = compress_g2(proof[3], proof[2], proof[5], proof[4]);
        compressed[3] = compress_g1(proof[6], proof[7]);
    }

    // Verify a Groth16 proof with compressed points.
    // Reverts if the proof is invalid or the public input is not reduced.
    // Proof is (A, B, C), see decompress_g1 and decompress_g2 for the point encoding.
    function verifyCompressedProof(
        uint256[4] calldata compressedProof,
        uint256[{{$numPublic}}] calldata input
    ) public view returns (uint256, uint256) {
        (uint256 Ax, uint256 Ay) = decompress_g1(compressedProof[0]);
        (uint256 Bx0, uint256 Bx1, uint256 By0, uint256 By1) = decompress_g2(
                compressedProof[2], compressedProof[1]);
        (uint256 Cx, uint256 Cy) = decompress_g1(compressedProof[3]);
        (uint256 Lx, uint256 Ly) = publicInputMSM(input);

        // Verify the pairing
        // Note: The precompile expects the F2 coefficients in big-endian order.
        // Note: The pairing precompile rejects unreduced values, so we won't check that here.
        uint256[24] memory pairings;
        // e(A, B)
        pairings[ 0] = Ax;
        pairings[ 1] = Ay;
        pairings[ 2] = Bx1;
        pairings[ 3] = Bx0;
        pairings[ 4] = By1;
        pairings[ 5] = By0;
        // e(C, -δ)
        pairings[ 6] = Cx;
        pairings[ 7] = Cy;
        pairings[ 8] = DELTA_NEG_X_1;
        pairings[ 9] = DELTA_NEG_X_0;
        pairings[10] = DELTA_NEG_Y_1;
        pairings[11] = DELTA_NEG_Y_0;
        // e(α, -β)
        pairings[12] = ALPHA_X;
        pairings[13] = ALPHA_Y;
        pairings[14] = BETA_NEG_X_1;
        pairings[15] = BETA_NEG_X_0;
        pairings[16] = BETA_NEG_Y_1;
        pairings[17] = BETA_NEG_Y_0;
        // e(L_pub, -γ)
        pairings[18] = Lx;
        pairings[19] = Ly;
        pairings[20] = GAMMA_NEG_X_1;
        pairings[21] = GAMMA_NEG_X_0;
        pairings[22] = GAMMA_NEG_Y_1;
        pairings[23] = GAMMA_NEG_Y_0;

        // Check pairing equation.
        bool success;
        uint256[1] memory output;
        assembly ("memory-safe") {
            success := staticcall(gas(), PRECOMPILE_VERIFY, pairings, 0x300, output, 0x20)
        }
        if (!success || output[0] != 1) {
            // Either proof or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert ProofInvalid();
        }
    }

    // Verify a Groth16 proof.
    // Reverts if the proof is invalid or the public input is not reduced.
    // Proof is (A, B, C) encoded as in EIP-197.
    function verifyProof(
        uint256[8] calldata proof,
        uint256[{{$numPublic}}] calldata input
    ) public view {
        (uint256 x, uint256 y) = publicInputMSM(input);

        // Note: The precompile expects the F2 coefficients in big-endian order.
        // Note: The pairing precompile rejects unreduced values, so we won't check that here.
        
        bool success;
        assembly ("memory-safe") {
            let f := mload(0x40) // Free memory pointer.

            // Copy points (A, B, C) to memory. They are already in correct encoding.
            // This is pairing e(A, B) and G1 of e(C, -δ).
            calldatacopy(f, proof, 0x100)

            // Complete e(C, -δ) and write e(α, -β), e(L_pub, -γ) to memory.
            // OPT: This could be better done using a single codecopy, but
            //      Solidity (unlike standalone Yul) doesn't provide a way to
            //      to do this.
            mstore(add(f, 0x100), DELTA_NEG_X_1)
            mstore(add(f, 0x120), DELTA_NEG_X_0)
            mstore(add(f, 0x140), DELTA_NEG_Y_1)
            mstore(add(f, 0x160), DELTA_NEG_Y_0)
            mstore(add(f, 0x180), ALPHA_X)
            mstore(add(f, 0x1a0), ALPHA_Y)
            mstore(add(f, 0x1c0), BETA_NEG_X_1)
            mstore(add(f, 0x1e0), BETA_NEG_X_0)
            mstore(add(f, 0x200), BETA_NEG_Y_1)
            mstore(add(f, 0x220), BETA_NEG_Y_0)
            mstore(add(f, 0x240), x)
            mstore(add(f, 0x260), y)
            mstore(add(f, 0x280), GAMMA_NEG_X_1)
            mstore(add(f, 0x2a0), GAMMA_NEG_X_0)
            mstore(add(f, 0x2c0), GAMMA_NEG_Y_1)
            mstore(add(f, 0x2e0), GAMMA_NEG_Y_0)

            // Check pairing equation.
            success := staticcall(gas(), PRECOMPILE_VERIFY, f, 0x300, f, 0x20)
            // Also check returned value (both are either 1 or 0).
            success := and(success, mload(f))
        }
        if (!success) {
            // Either proof or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert ProofInvalid();
        }
    }
}
`
