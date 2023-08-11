package groth16

// solidityTemplate
// this is an experimental feature and gnark solidity generator as not been thoroughly tested
const solidityTemplate = `
{{- $numPublic := sub (len .G1.K) 1 }}
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Verifier {
    uint256 constant PRECOMPILE_MODEXP = 0x05;
    uint256 constant PRECOMPILE_ADD = 0x06;
    uint256 constant PRECOMPILE_MUL = 0x07;
    uint256 constant PRECOMPILE_VERIFY = 0x08;

    // Base field order P and scalar field order R.
    // For BN254 these are computed as follows:
    //     t = 4965661367192848881
    //     P = 36⋅t⁴ + 36⋅t³ + 24⋅t² + 6⋅t + 1
    //     R = 36⋅t⁴ + 36⋅t³ + 18⋅t² + 6⋅t + 1
    uint256 constant P = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
    uint256 constant R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    uint256 constant FRACTION_1_2_FP = 0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea4;
    uint256 constant FRACTION_27_82_FP = 0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5;
    uint256 constant FRACTION_3_82_FP = 0x2fcd3ac2a640a154eb23960892a85a68f031ca0c8344b23a577dcf1052b9e775;

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


    function negate(uint256 a) public pure returns (uint256 x) {
        x = (P - a) % P; // Modulo is cheaper than branching
    }

    function exp(uint256 a, uint256 e) public view returns (uint256 x) {
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

    function invert_Fp(uint256 a) public view returns (uint256 x) {
        x = exp(a, EXP_INVERSE_FP);
        require(mulmod(a, x, P) == 1);
    }

    function sqrt_Fp(uint256 a) public view returns (uint256 x) {
        x = exp(a, EXP_SQRT_FP);
        require(mulmod(x, x, P) == a);
    }

    function sqrt_Fp2(uint256 a0, uint256 a1, bool hint) public view returns (uint256 x0, uint256 x1) {
        uint256 d = sqrt_Fp(addmod(mulmod(a0, a0, P), mulmod(a1, a1, P), P));
        if (hint) {
            d = negate(d);
        }
        x0 = sqrt_Fp(mulmod(addmod(a0, d, P), FRACTION_1_2_FP, P));
        x1 = mulmod(a1, invert_Fp(mulmod(x0, 2, P)), P);

        require(a0 == addmod(mulmod(x0, x0, P), negate(mulmod(x1, x1, P)), P));
        require(a1 == mulmod(2, mulmod(x0, x1, P), P));
    }

    function decompress_g1(uint256 c) public view returns (uint256 x, uint256 y) {
        bool negate_point = c & 1 == 1;
        x = c >> 1;
        y = sqrt_Fp(mulmod(mulmod(x, x, P), x, P) + 3);
        if (negate_point) {
            y = negate(y);
        }
    }

    function decompress_g2(uint256 c0, uint256 c1) public view returns (uint256 x0, uint256 x1, uint256 y0, uint256 y1) {
        bool negate_point = c0 & 1 == 1;
        bool hint = c0 & 2 == 2;
        x0 = c0 >> 2;
        x1 = c1;

        uint256 n3ab = mulmod(mulmod(x0, x1, P), P-3, P);
        uint256 a_3 = mulmod(mulmod(x0, x0, P), x0, P);
        uint256 b_3 = mulmod(mulmod(x1, x1, P), x1, P);

        y0 = addmod(FRACTION_27_82_FP, addmod(a_3, mulmod(n3ab, x1, P), P), P);
        y1 = negate(addmod(FRACTION_3_82_FP,  addmod(b_3, mulmod(n3ab, x0, P), P), P));

        (y0, y1) = sqrt_Fp2(y0, y1, hint);
        if (negate_point) {
            y0 = negate(y0);
            y1 = negate(y1);
        }
    }

    function add(uint256 a_x, uint256 a_y, uint256 b_x, uint256 b_y) public view returns (uint256 x, uint256 y) {
        bool success;
        assembly {
            let f := mload(0x40)
            mstore(f, a_x)
            mstore(add(f, 0x20), a_y)
            mstore(add(f, 0x40), b_x)
            mstore(add(f, 0x60), b_y)
            success := staticcall(sub(gas(), 2000), PRECOMPILE_ADD, f, 0x80, f, 0x40)
            x := mload(f)
            y := mload(add(f, 0x20))
        }
        require(success);
    }

    function mul(uint256 a_x, uint256 a_y, uint256 s) public view returns (uint256 x, uint256 y) {
        bool success;
        assembly {
            let f := mload(0x40)
            mstore(f, a_x)
            mstore(add(f, 0x20), a_y)
            mstore(add(f, 0x40), s)
            success := staticcall(sub(gas(), 2000), PRECOMPILE_MUL, f, 0x60, f, 0x40)
            x := mload(f)
            y := mload(add(f, 0x20))
        }
        require(success);
    }

    // Returns a + s ⋅ b with a,b in G1 and s in F1
    // See https://eips.ethereum.org/EIPS/eip-196
    function muladd(uint256 a_x, uint256 a_y, uint256 b_x, uint256 b_y,uint256 s) public view returns (uint256 x, uint256 y) {
        // OPT: Inline both functions and re-use memory layout.
        require(s < R);
        (x, y) = mul(b_x, b_y, s);
        (x, y) = add(a_x, a_y, x, y);
    }

    function verifyCompressedProof(
        uint256[4] calldata compressedProof,
        uint256[{{$numPublic}}] calldata input
    ) public view {
        uint256[8] memory proof;
        (uint256 x, uint256 y) = decompress_g1(compressedProof[0]); // A
        proof[0] = x;
        proof[1] = y;

        (uint256 x0, uint256 x1, uint256 y0, uint256 y1) = decompress_g2(compressedProof[2], compressedProof[1]); // B

        proof[2] = x1;
        proof[3] = x0;
        proof[4] = y1;
        proof[5] = y0;
        
        (x,y) = decompress_g1(compressedProof[3]); // C
        proof[6] = x;
        proof[7] = y;

        // TODO: Inline this so we can keep calldata arguments.
        verifyProof(proof, input);
    }

    function verifyProof(
        uint256[8] memory proof, // TODO make these calldata
        uint256[{{$numPublic}}] memory input // TODO make these calldata
    ) public view {
        // Compute the public input linear combination
        // TODO: Public input is not checked for being in reduced form.
        // Note: The ECMUL precompile does not reject unreduced values, so we check in muladd.
        uint256 x;
        uint256 y;
        (x, y) = (CONSTANT_X, CONSTANT_Y);
        {{- range $i := intRange $numPublic }}
        (x, y) = muladd(x, y, PUB_{{$i}}_X, PUB_{{$i}}_Y, input[{{$i}}]);
        {{- end }}

        // OPT: Calldatacopy proof to input. Swap pairings so proof is contiguous.
        // OPT: Codecopy remaining points except (x, y) to input.

        // Verify the pairing
        // Note: The precompile expects the F2 coefficients in big-endian order.
        // Note: The pairing precompile rejects unreduced values, so we won't check that here.
        uint256[24] memory input;
        // e(A, B)
        input[ 0] = proof[0]; // A_x
        input[ 1] = proof[1]; // A_y
        input[ 2] = proof[2]; // B_x_1
        input[ 3] = proof[3]; // B_x_0
        input[ 4] = proof[4]; // B_y_1
        input[ 5] = proof[5]; // B_y_0
        // e(α, -β)
        input[ 6] = ALPHA_X;
        input[ 7] = ALPHA_Y;
        input[ 8] = BETA_NEG_X_1;
        input[ 9] = BETA_NEG_X_0;
        input[10] = BETA_NEG_Y_1;
        input[11] = BETA_NEG_Y_0;
        // e(L_pub, -γ)
        input[12] = x;
        input[13] = y;
        input[14] = GAMMA_NEG_X_1;
        input[15] = GAMMA_NEG_X_0;
        input[16] = GAMMA_NEG_Y_1;
        input[17] = GAMMA_NEG_Y_0;
        // e(C, -δ)
        input[18] = proof[6]; // C_x
        input[19] = proof[7]; // C_y
        input[20] = DELTA_NEG_X_1;
        input[21] = DELTA_NEG_X_0;
        input[22] = DELTA_NEG_Y_1;
        input[23] = DELTA_NEG_Y_0;

        bool success;
        uint256[1] memory output;
        assembly {
            // We should need exactly 147000 gas, but we give most of it in case this is
            // different in the future or on alternative EVM chains.
            success := staticcall(sub(gas(), 2000), PRECOMPILE_VERIFY, input, 0x300, output, 0x20)
        }
        require(success && output[0] == 1);
    }
}
`
