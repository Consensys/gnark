package groth16

// solidityTemplate
// this is an experimental feature and gnark solidity generator as not been thoroughly tested
const solidityTemplate = `
{{- $numPublic := sub (len .G1.K) 1 }}
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Verifier {
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
        {{- if gt $i 0 -}}
    uint256 constant PUB_{{sub $i 1}}_X = {{$ki.X.String}};
    uint256 constant PUB_{{sub $i 1}}_Y = {{$ki.Y.String}};
        {{- end -}}
    {{- end }}

    // Negation in Fp.
    // The input must be reduced.
    function negate(uint256 a) internal pure returns (uint256 x) {
        x = (P - a) % P; // Modulo is cheaper than branching
    }

    // Modular exponentiation in Fp.
    // The input does not need to be reduced.
    function exp(uint256 a, uint256 e) internal view returns (uint256 x) {
        bool success;
        assembly {
            let f := mload(0x40)
            mstore(f, 0x20)
            mstore(add(f, 0x20), 0x20)
            mstore(add(f, 0x40), 0x20)
            mstore(add(f, 0x60), a)
            mstore(add(f, 0x80), e)
            mstore(add(f, 0xa0), P)
            success := staticcall(sub(gas(), 2000), PRECOMPILE_MODEXP, f, 0xc0, f, 0x20)
            x := mload(f)
        }
        require(success);
    }

    // Inverts an element in Fp.
    // The input does not need to be reduced.
    // If the inverse does not exist, the operation reverts.
    function invert_Fp(uint256 a) internal view returns (uint256 x) {
        x = exp(a, EXP_INVERSE_FP);
        require(mulmod(a, x, P) == 1);
    }

    // Square root in Fp.
    // The input must be reduced or the operation reverts.
    // If a square root does not exist, the operation reverts.
    function sqrt_Fp(uint256 a) internal view returns (uint256 x) {
        x = exp(a, EXP_SQRT_FP);
        require(mulmod(x, x, P) == a); // Reverts if a is not reduced.
    }

    // Square root in Fp2.
    // The input must be reduced or the operation reverts.
    // If a square root does not exist, the operation reverts.
    // The hint parameter is used to pick a sign internally.
    function sqrt_Fp2(uint256 a0, uint256 a1, bool hint) internal view returns (uint256 x0, uint256 x1) {
        uint256 d = sqrt_Fp(addmod(mulmod(a0, a0, P), mulmod(a1, a1, P), P));
        if (hint) {
            d = negate(d);
        }
        x0 = sqrt_Fp(mulmod(addmod(a0, d, P), FRACTION_1_2_FP, P));
        x1 = mulmod(a1, invert_Fp(mulmod(x0, 2, P)), P);

        require(a0 == addmod(mulmod(x0, x0, P), negate(mulmod(x1, x1, P)), P));
        require(a1 == mulmod(2, mulmod(x0, x1, P), P));
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
        require(x < P);
        // Note: (x³ + 3) is irreducible in Fp, so it can not be zero and therefore
        //       y can not be zero.
        // Note: sqrt_Fp reverts if there is no solution, i.e. the point is not on the curve.
        y = sqrt_Fp(addmod(mulmod(mulmod(x, x, P), x, P), 3, P));
        if (negate_point) {
            y = negate(y);
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
        require(x0 < P);
        require(x1 < P);

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

    // Returns a + s ⋅ b with a,b in G1 and s in FR
    // Reverts if s is not reduced or if a, b is not a valid point.
    // See <https://eips.ethereum.org/EIPS/eip-196>
    function muladd(uint256 a_x, uint256 a_y, uint256 b_x, uint256 b_y,uint256 s)
    internal view returns (uint256 x, uint256 y) {
        // Note: PRECOMPILE_MUL does not check if the scalar is reduced modulo R. So we do it here.
        require(s < R); // Public input out of range.
        bool success;
        assembly {
            let f := mload(0x40)
            mstore(f, b_x)
            mstore(add(f, 0x20), b_y)
            mstore(add(f, 0x40), s)
            // ECMUL has input (x, y, scalar) and output (x', y').
            success := staticcall(sub(gas(), 2000), PRECOMPILE_MUL, f, 0x60, f, 0x40)
            // ECMUL ouput is already in the first point argument.
            mstore(add(f, 0x40), a_x)
            mstore(add(f, 0x60), a_y)
            // ECADD has input (x1, y1, x2, y2) and output (x', y').
            success := and(success, staticcall(sub(gas(), 2000), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            x := mload(f)
            y := mload(add(f, 0x20))
        }
        // The precompiles can fail iff they are out of gas or if the inputs are not valid points.
        // The points are hardcoded part of the verification key, so they should be valid.
        require(success); // Verification key invalid or out of gas.
    }

    // Verify a Groth16 proof with compressed points.
    // Reverts if the proof is invalid.
    // See `decompress_g1` and `decompress_g2` for the point encoding.
    function verifyCompressedProof(
        uint256[4] calldata compressedProof,
        uint256[{{$numPublic}}] calldata input
    ) public view {
        uint256[8] memory proof;
        // Point A in G1
        (uint256 x, uint256 y) = decompress_g1(compressedProof[0]);
        proof[0] = x;
        proof[1] = y;
        // Point B in G2
        (uint256 x0, uint256 x1, uint256 y0, uint256 y1) = decompress_g2(
            compressedProof[2], compressedProof[1]);
        proof[2] = x1;
        proof[3] = x0;
        proof[4] = y1;
        proof[5] = y0;
        // Point C in G1
        (x,y) = decompress_g1(compressedProof[3]);
        proof[6] = x;
        proof[7] = y;
        verifyProof(proof, input);
    }

    // Verify a Groth16 proof.
    // Reverts if the proof is invalid.
    function verifyProof(
        uint256[8] memory proof, // TODO make these calldata
        uint256[{{$numPublic}}] calldata input
    ) public view {
        // Compute the public input linear combination
        // Note: The ECMUL precompile does not reject unreduced values, so we check in muladd.
        // Note: Unrolling this loop does not cost much extra in code-size, the bulk of the
        //       code-size is in the PUB_ constants.
        (uint256 x, uint256 y) = (CONSTANT_X, CONSTANT_Y);
        {{- range $i := intRange $numPublic }}
        (x, y) = muladd(x, y, PUB_{{$i}}_X, PUB_{{$i}}_Y, input[{{$i}}]);
        {{- end }}

        // Verify the pairing
        // Note: The precompile expects the F2 coefficients in big-endian order.
        // Note: The pairing precompile rejects unreduced values, so we won't check that here.
        // OPT: Calldatacopy proof to input. Swap pairings so proof is contiguous.
        // OPT: Codecopy remaining points except (x, y) to input.
        uint256[24] memory pairings;
        // e(A, B)
        pairings[ 0] = proof[0]; // A_x
        pairings[ 1] = proof[1]; // A_y
        pairings[ 2] = proof[2]; // B_x_1
        pairings[ 3] = proof[3]; // B_x_0
        pairings[ 4] = proof[4]; // B_y_1
        pairings[ 5] = proof[5]; // B_y_0
        // e(α, -β)
        pairings[ 6] = ALPHA_X;
        pairings[ 7] = ALPHA_Y;
        pairings[ 8] = BETA_NEG_X_1;
        pairings[ 9] = BETA_NEG_X_0;
        pairings[10] = BETA_NEG_Y_1;
        pairings[11] = BETA_NEG_Y_0;
        // e(L_pub, -γ)
        pairings[12] = x;
        pairings[13] = y;
        pairings[14] = GAMMA_NEG_X_1;
        pairings[15] = GAMMA_NEG_X_0;
        pairings[16] = GAMMA_NEG_Y_1;
        pairings[17] = GAMMA_NEG_Y_0;
        // e(C, -δ)
        pairings[18] = proof[6]; // C_x
        pairings[19] = proof[7]; // C_y
        pairings[20] = DELTA_NEG_X_1;
        pairings[21] = DELTA_NEG_X_0;
        pairings[22] = DELTA_NEG_Y_1;
        pairings[23] = DELTA_NEG_Y_0;

        bool success;
        uint256[1] memory output;
        assembly {
            // We should need exactly 147000 gas, but we give most of it in case this is
            // different in the future or on alternative EVM chains.
            success := staticcall(sub(gas(), 2000), PRECOMPILE_VERIFY, pairings, 0x300, output, 0x20)
        }
        require(success && output[0] == 1);
    }
}
`
