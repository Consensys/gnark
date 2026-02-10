package groth16

import (
	"bytes"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)

// solidityTemplate is the Solidity template for the Groth16 verifier on BLS12-381.
// It uses EIP-2537 precompiles for BLS12-381 operations:
//   - BLS12_G1MSM (0x0c) for multi-scalar multiplication
//   - BLS12_PAIR (0x0f) for pairing checks
//
// BLS12-381 Fp elements are 48 bytes (384 bits), encoded as [hi_uint256 || lo_uint256]
// where hi is the top 16 bytes and lo is the bottom 32 bytes.
// G1 points in EIP-2537 format: 128 bytes (x: 64 bytes padded, y: 64 bytes padded)
// G2 points in EIP-2537 format: 256 bytes (4 × 64 bytes padded coordinates)
const solidityTemplate = `
{{- $numPublic := sub (len .Vk.G1.K) 1 }}
{{- $numCommitments := len .Vk.PublicAndCommitmentCommitted }}
{{- $numWitness := sub $numPublic $numCommitments }}
{{- $PublicAndCommitmentCommitted := .Vk.PublicAndCommitmentCommitted }}
// SPDX-License-Identifier: MIT

pragma solidity {{ .Cfg.PragmaVersion }};
{{- if .Cfg.SortedImports }}
{{ range $imp := .Cfg.SortedImports }}
{{ $imp }}
{{- end }}
{{- end }}

/// @title Groth16 verifier template.
/// @notice Supports verifying Groth16 proofs over BLS12-381 using EIP-2537 precompiles.
/// @notice Proofs can be in uncompressed (384 bytes) and compressed (256 bytes) format.
/// A view function is provided to compress proofs.
contract Verifier{{ .Cfg.InterfaceDeclaration }} {

    /// Some of the provided public input values are larger than the field modulus.
    /// @dev Public input elements are not automatically reduced, as this is can be
    /// a dangerous source of bugs.
    error PublicInputNotInField();

    /// The proof is invalid.
    /// @dev This can mean that provided Groth16 proof points are not on their
    /// curves, that pairing equation fails, or that the proof is not for the
    /// provided public input.
    error ProofInvalid();

    {{- if gt $numCommitments 0 }}
    /// The commitment is invalid
    /// @dev This can mean that provided commitment points and/or proof of knowledge are not on their
    /// curves, that pairing equation fails, or that the commitment and/or proof of knowledge is not for the
    /// commitment key.
    error CommitmentInvalid();
    {{- end }}

    // Addresses of precompiles
    uint256 constant PRECOMPILE_MODEXP = 0x05;
    uint256 constant PRECOMPILE_BLS12_G1MSM = 0x0c;
    uint256 constant PRECOMPILE_BLS12_PAIR = 0x0f;

    // BLS12-381 scalar field Fr order R.
    uint256 constant R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    // Groth16 alpha point in G1
    uint256 constant ALPHA_X_HI = {{ fpstr_hi .Vk.G1.Alpha.X }};
    uint256 constant ALPHA_X_LO = {{ fpstr_lo .Vk.G1.Alpha.X }};
    uint256 constant ALPHA_Y_HI = {{ fpstr_hi .Vk.G1.Alpha.Y }};
    uint256 constant ALPHA_Y_LO = {{ fpstr_lo .Vk.G1.Alpha.Y }};

    // Groth16 beta point in G2 (negated)
    uint256 constant BETA_NEG_X_0_HI = {{ fpstr_hi .Vk.G2.Beta.X.A0 }};
    uint256 constant BETA_NEG_X_0_LO = {{ fpstr_lo .Vk.G2.Beta.X.A0 }};
    uint256 constant BETA_NEG_X_1_HI = {{ fpstr_hi .Vk.G2.Beta.X.A1 }};
    uint256 constant BETA_NEG_X_1_LO = {{ fpstr_lo .Vk.G2.Beta.X.A1 }};
    uint256 constant BETA_NEG_Y_0_HI = {{ fpstr_hi .Vk.G2.Beta.Y.A0 }};
    uint256 constant BETA_NEG_Y_0_LO = {{ fpstr_lo .Vk.G2.Beta.Y.A0 }};
    uint256 constant BETA_NEG_Y_1_HI = {{ fpstr_hi .Vk.G2.Beta.Y.A1 }};
    uint256 constant BETA_NEG_Y_1_LO = {{ fpstr_lo .Vk.G2.Beta.Y.A1 }};

    // Groth16 gamma point in G2 (negated)
    uint256 constant GAMMA_NEG_X_0_HI = {{ fpstr_hi .Vk.G2.Gamma.X.A0 }};
    uint256 constant GAMMA_NEG_X_0_LO = {{ fpstr_lo .Vk.G2.Gamma.X.A0 }};
    uint256 constant GAMMA_NEG_X_1_HI = {{ fpstr_hi .Vk.G2.Gamma.X.A1 }};
    uint256 constant GAMMA_NEG_X_1_LO = {{ fpstr_lo .Vk.G2.Gamma.X.A1 }};
    uint256 constant GAMMA_NEG_Y_0_HI = {{ fpstr_hi .Vk.G2.Gamma.Y.A0 }};
    uint256 constant GAMMA_NEG_Y_0_LO = {{ fpstr_lo .Vk.G2.Gamma.Y.A0 }};
    uint256 constant GAMMA_NEG_Y_1_HI = {{ fpstr_hi .Vk.G2.Gamma.Y.A1 }};
    uint256 constant GAMMA_NEG_Y_1_LO = {{ fpstr_lo .Vk.G2.Gamma.Y.A1 }};

    // Groth16 delta point in G2 (negated)
    uint256 constant DELTA_NEG_X_0_HI = {{ fpstr_hi .Vk.G2.Delta.X.A0 }};
    uint256 constant DELTA_NEG_X_0_LO = {{ fpstr_lo .Vk.G2.Delta.X.A0 }};
    uint256 constant DELTA_NEG_X_1_HI = {{ fpstr_hi .Vk.G2.Delta.X.A1 }};
    uint256 constant DELTA_NEG_X_1_LO = {{ fpstr_lo .Vk.G2.Delta.X.A1 }};
    uint256 constant DELTA_NEG_Y_0_HI = {{ fpstr_hi .Vk.G2.Delta.Y.A0 }};
    uint256 constant DELTA_NEG_Y_0_LO = {{ fpstr_lo .Vk.G2.Delta.Y.A0 }};
    uint256 constant DELTA_NEG_Y_1_HI = {{ fpstr_hi .Vk.G2.Delta.Y.A1 }};
    uint256 constant DELTA_NEG_Y_1_LO = {{ fpstr_lo .Vk.G2.Delta.Y.A1 }};

    {{- if gt $numCommitments 0 }}
    // Pedersen G point in G2
    {{- $cmtVk0 := index .Vk.CommitmentKeys 0 }}
    uint256 constant PEDERSEN_G_X_0_HI = {{ fpstr_hi $cmtVk0.G.X.A0 }};
    uint256 constant PEDERSEN_G_X_0_LO = {{ fpstr_lo $cmtVk0.G.X.A0 }};
    uint256 constant PEDERSEN_G_X_1_HI = {{ fpstr_hi $cmtVk0.G.X.A1 }};
    uint256 constant PEDERSEN_G_X_1_LO = {{ fpstr_lo $cmtVk0.G.X.A1 }};
    uint256 constant PEDERSEN_G_Y_0_HI = {{ fpstr_hi $cmtVk0.G.Y.A0 }};
    uint256 constant PEDERSEN_G_Y_0_LO = {{ fpstr_lo $cmtVk0.G.Y.A0 }};
    uint256 constant PEDERSEN_G_Y_1_HI = {{ fpstr_hi $cmtVk0.G.Y.A1 }};
    uint256 constant PEDERSEN_G_Y_1_LO = {{ fpstr_lo $cmtVk0.G.Y.A1 }};

    // Pedersen GSigmaNeg point in G2
    uint256 constant PEDERSEN_GSIGMANEG_X_0_HI = {{ fpstr_hi $cmtVk0.GSigmaNeg.X.A0 }};
    uint256 constant PEDERSEN_GSIGMANEG_X_0_LO = {{ fpstr_lo $cmtVk0.GSigmaNeg.X.A0 }};
    uint256 constant PEDERSEN_GSIGMANEG_X_1_HI = {{ fpstr_hi $cmtVk0.GSigmaNeg.X.A1 }};
    uint256 constant PEDERSEN_GSIGMANEG_X_1_LO = {{ fpstr_lo $cmtVk0.GSigmaNeg.X.A1 }};
    uint256 constant PEDERSEN_GSIGMANEG_Y_0_HI = {{ fpstr_hi $cmtVk0.GSigmaNeg.Y.A0 }};
    uint256 constant PEDERSEN_GSIGMANEG_Y_0_LO = {{ fpstr_lo $cmtVk0.GSigmaNeg.Y.A0 }};
    uint256 constant PEDERSEN_GSIGMANEG_Y_1_HI = {{ fpstr_hi $cmtVk0.GSigmaNeg.Y.A1 }};
    uint256 constant PEDERSEN_GSIGMANEG_Y_1_LO = {{ fpstr_lo $cmtVk0.GSigmaNeg.Y.A1 }};
    {{- end }}

    // Constant and public input points
    {{- $k0 := index .Vk.G1.K 0}}
    uint256 constant CONSTANT_X_HI = {{ fpstr_hi $k0.X }};
    uint256 constant CONSTANT_X_LO = {{ fpstr_lo $k0.X }};
    uint256 constant CONSTANT_Y_HI = {{ fpstr_hi $k0.Y }};
    uint256 constant CONSTANT_Y_LO = {{ fpstr_lo $k0.Y }};
    {{- range $i, $ki := .Vk.G1.K }}
        {{- if gt $i 0 }}
    uint256 constant PUB_{{sub $i 1}}_X_HI = {{ fpstr_hi $ki.X }};
    uint256 constant PUB_{{sub $i 1}}_X_LO = {{ fpstr_lo $ki.X }};
    uint256 constant PUB_{{sub $i 1}}_Y_HI = {{ fpstr_hi $ki.Y }};
    uint256 constant PUB_{{sub $i 1}}_Y_LO = {{ fpstr_lo $ki.Y }};
        {{- end }}
    {{- end }}
{{- if .Cfg.Constants }}

{{ .Cfg.Constants }}
{{- end }}
{{- if .Cfg.Constructor }}

{{ .Cfg.Constructor }}
{{- end }}

    // BLS12-381 base field modulus p, split into (hi, lo) 384-bit representation.
    // p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    uint256 constant P_HI = 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7;
    uint256 constant P_LO = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

    // (p + 1) / 4 — exponent for square root (since p ≡ 3 mod 4)
    uint256 constant EXP_SQRT_FP_HI = 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35;
    uint256 constant EXP_SQRT_FP_LO = 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab;

    // p - 2 — exponent for modular inverse (Fermat's little theorem)
    uint256 constant EXP_INVERSE_FP_HI = 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7;
    uint256 constant EXP_INVERSE_FP_LO = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaa9;

    // (p + 1) / 2 — used for halving in Fp
    uint256 constant FRACTION_1_2_FP_HI = 0x000000000000000000000000000000000d0088f51cbff34d258dd3db21a5d66b;
    uint256 constant FRACTION_1_2_FP_LO = 0xb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd556;

    /// Negation in Fp.
    /// @notice Returns (P - a) mod P, using 384-bit (hi, lo) representation.
    function negate_Fp(uint256 a_hi, uint256 a_lo)
    internal pure returns (uint256 r_hi, uint256 r_lo) {
        if (a_hi == 0 && a_lo == 0) {
            return (0, 0);
        }
        unchecked {
            // P - a (384-bit subtraction, a < P so no underflow)
            uint256 borrow;
            r_lo = P_LO - a_lo;
            borrow = (r_lo > P_LO) ? 1 : 0;
            r_hi = P_HI - a_hi - borrow;
        }
    }

    /// Addition in Fp.
    /// @notice Returns (a + b) mod P, using 384-bit (hi, lo) representation.
    function fp_add(uint256 a_hi, uint256 a_lo, uint256 b_hi, uint256 b_lo)
    internal pure returns (uint256 r_hi, uint256 r_lo) {
        unchecked {
            r_lo = a_lo + b_lo;
            uint256 carry = (r_lo < a_lo) ? 1 : 0;
            r_hi = a_hi + b_hi + carry;
            // Reduce: if result >= P, subtract P
            if (r_hi > P_HI || (r_hi == P_HI && r_lo >= P_LO)) {
                uint256 borrow;
                uint256 t_lo = r_lo - P_LO;
                borrow = (t_lo > r_lo) ? 1 : 0;
                r_hi = r_hi - P_HI - borrow;
                r_lo = t_lo;
            }
        }
    }

    /// Subtraction in Fp.
    /// @notice Returns (a - b) mod P, using 384-bit (hi, lo) representation.
    function fp_sub(uint256 a_hi, uint256 a_lo, uint256 b_hi, uint256 b_lo)
    internal pure returns (uint256 r_hi, uint256 r_lo) {
        unchecked {
            uint256 borrow;
            r_lo = a_lo - b_lo;
            borrow = (r_lo > a_lo) ? 1 : 0;
            r_hi = a_hi - b_hi - borrow;
            // If underflowed (a < b), add P back
            // Check: if original a < b, r_hi will have wrapped around (very large)
            if (a_hi < b_hi || (a_hi == b_hi && a_lo < b_lo)) {
                uint256 carry;
                r_lo = r_lo + P_LO;
                carry = (r_lo < P_LO) ? 1 : 0;
                r_hi = r_hi + P_HI + carry;
            }
        }
    }

    /// Multiplication in Fp.
    /// @notice Returns (a * b) mod P using MODEXP precompile for reduction.
    /// @notice Computes 384×384→768 bit product, then reduces mod P.
    function fp_mul(uint256 a_hi, uint256 a_lo, uint256 b_hi, uint256 b_lo)
    internal view returns (uint256 r_hi, uint256 r_lo) {
        bool success;
        assembly ("memory-safe") {
            let f := mload(0x40)

            // Schoolbook multiplication of two 384-bit numbers (each as hi:lo where hi≤128 bits).
            // a = a_hi * 2^256 + a_lo
            // b = b_hi * 2^256 + b_lo
            // product = a_hi*b_hi * 2^512 + (a_hi*b_lo + a_lo*b_hi) * 2^256 + a_lo*b_lo
            //
            // Each partial product uses mulmod(x, y, not(0)) trick:
            //   mulmod(x, y, 2^256) = x*y mod 2^256 = low 256 bits
            //   mulmod(x, y, not(0)) = x*y mod (2^256-1), from which we can recover carries.
            //
            // For our case, a_hi and b_hi are at most ~128 bits, so a_hi*b_hi fits in 256 bits.
            // We accumulate into a 768-bit result: (r5, r4, r3, r2, r1, r0) as 6 × 128-bit limbs,
            // or more practically as 3 × 256-bit words: (w2, w1, w0).

            // w0 = a_lo * b_lo (mod 2^256) — low word
            let w0 := mul(a_lo, b_lo)
            // carry0 = (a_lo * b_lo) >> 256
            // Using: if a*b mod (2^256-1) < a*b mod 2^256, then carry = a*b / 2^256
            let t := mulmod(a_lo, b_lo, not(0))
            let carry0 := sub(t, w0)
            // Adjust: mulmod(..., not(0)) gives mod (2^256-1), need to account for wrap
            // carry0 = t - w0 if t >= w0, else t - w0 + 1 (when t = (a*b - 1) mod (2^256-1))
            // Actually: a*b = carry*2^256 + w0, and t = a*b mod (2^256-1)
            // If a*b < 2^256: carry=0, t=w0 if a*b < 2^256-1, t=0 if a*b=2^256-1
            // The correction: carry0 = sub(t, w0) needs +1 when a*b is multiple of (2^256-1) but not zero.
            // Since a,b < p < 2^384, a*b < 2^768, the product a_lo*b_lo < 2^512.
            // The carry is at most 256 bits.
            // Precise formula: carry = (t < w0) ? (t - w0 + 1) : (t - w0) if a_lo*b_lo != 0
            //                         0 if a_lo*b_lo == 0
            if lt(t, w0) { carry0 := add(carry0, 1) }

            // mid1 = a_hi * b_lo
            let mid1_lo := mul(a_hi, b_lo)
            let mid1_t := mulmod(a_hi, b_lo, not(0))
            let mid1_hi := sub(mid1_t, mid1_lo)
            if lt(mid1_t, mid1_lo) { mid1_hi := add(mid1_hi, 1) }

            // mid2 = a_lo * b_hi
            let mid2_lo := mul(a_lo, b_hi)
            let mid2_t := mulmod(a_lo, b_hi, not(0))
            let mid2_hi := sub(mid2_t, mid2_lo)
            if lt(mid2_t, mid2_lo) { mid2_hi := add(mid2_hi, 1) }

            // w2 = a_hi * b_hi (fits in 256 bits since each is ≤128 bits)
            let w2 := mul(a_hi, b_hi)

            // Accumulate: w1 = carry0 + mid1_lo + mid2_lo, propagate carry to w2
            let w1 := add(carry0, mid1_lo)
            let c := 0
            if lt(w1, carry0) { c := 1 }
            let w1b := add(w1, mid2_lo)
            if lt(w1b, w1) { c := add(c, 1) }
            w1 := w1b

            // w2 += mid1_hi + mid2_hi + carry from w1
            w2 := add(w2, add(add(mid1_hi, mid2_hi), c))

            // Now product = w2 * 2^512 + w1 * 2^256 + w0 (768 bits total)
            // Pack into 96 bytes (big-endian) as base for MODEXP(product, 1, P)
            // 96 bytes = 3 × 32 bytes: [w2(32)][w1(32)][w0(32)]
            // But MODEXP base is big-endian, with base_length=96.
            // Layout: [Bsize=96][Esize=1][Msize=48][base(96)][exp(1)][mod(48)]

            // MODEXP input layout
            mstore(f, 0x60)          // base_length = 96
            mstore(add(f, 0x20), 0x01) // exp_length = 1
            mstore(add(f, 0x40), 0x30) // mod_length = 48

            // base (96 bytes = 3 × 32 bytes, big-endian)
            mstore(add(f, 0x60), w2)
            mstore(add(f, 0x80), w1)
            mstore(add(f, 0xa0), w0)

            // exponent = 1 (1 byte)
            mstore8(add(f, 0xc0), 0x01)

            // modulus = P (48 bytes)
            // Pack P as 48 bytes: [16 bytes P_HI][32 bytes P_LO]
            mstore(add(f, 0xc1), shl(128, P_HI))
            mstore(add(f, 0xd1), P_LO)

            // Call MODEXP: input starts at f, length = 0x60 + 96 + 1 + 48 = 0x60 + 0x91 = 0xf1
            // Output: 48 bytes at f
            success := staticcall(gas(), PRECOMPILE_MODEXP, f, 0xf1, f, 0x30)

            // Read 48-byte result as (r_hi, r_lo)
            r_hi := shr(128, mload(f))
            r_lo := mload(add(f, 0x10))
        }
        if (!success) {
            revert ProofInvalid();
        }
    }

    /// Exponentiation in Fp.
    /// @notice Returns a^e mod P using MODEXP precompile with 48-byte operands.
    function fp_exp(uint256 a_hi, uint256 a_lo, uint256 e_hi, uint256 e_lo)
    internal view returns (uint256 r_hi, uint256 r_lo) {
        bool success;
        assembly ("memory-safe") {
            let f := mload(0x40)

            // MODEXP layout: [Bsize(32)][Esize(32)][Msize(32)][base(48)][exp(48)][mod(48)]
            mstore(f, 0x30)          // base_length = 48
            mstore(add(f, 0x20), 0x30) // exp_length = 48
            mstore(add(f, 0x40), 0x30) // mod_length = 48

            // Pack base (48 bytes): 16 bytes hi, 32 bytes lo
            mstore(add(f, 0x60), shl(128, a_hi))
            mstore(add(f, 0x70), a_lo)

            // Pack exponent (48 bytes)
            mstore(add(f, 0x90), shl(128, e_hi))
            mstore(add(f, 0xa0), e_lo)

            // Pack modulus (48 bytes)
            mstore(add(f, 0xc0), shl(128, P_HI))
            mstore(add(f, 0xd0), P_LO)

            // Call MODEXP: total input = 0x60 + 48*3 = 0x60 + 0x90 = 0xf0
            // Output: 48 bytes
            success := staticcall(gas(), PRECOMPILE_MODEXP, f, 0xf0, f, 0x30)

            // Read result
            r_hi := shr(128, mload(f))
            r_lo := mload(add(f, 0x10))
        }
        if (!success) {
            revert ProofInvalid();
        }
    }

    /// Inverse in Fp.
    /// @notice Returns a^(p-2) mod P, and verifies a * result = 1.
    function invert_Fp(uint256 a_hi, uint256 a_lo)
    internal view returns (uint256 r_hi, uint256 r_lo) {
        (r_hi, r_lo) = fp_exp(a_hi, a_lo, EXP_INVERSE_FP_HI, EXP_INVERSE_FP_LO);
        (uint256 check_hi, uint256 check_lo) = fp_mul(a_hi, a_lo, r_hi, r_lo);
        if (check_hi != 0 || check_lo != 1) {
            revert ProofInvalid();
        }
    }

    /// Square root in Fp.
    /// @notice Returns x such that x*x = a mod P. Reverts if a is not a QR.
    function sqrt_Fp(uint256 a_hi, uint256 a_lo)
    internal view returns (uint256 r_hi, uint256 r_lo) {
        (r_hi, r_lo) = fp_exp(a_hi, a_lo, EXP_SQRT_FP_HI, EXP_SQRT_FP_LO);
        (uint256 check_hi, uint256 check_lo) = fp_mul(r_hi, r_lo, r_hi, r_lo);
        if (check_hi != a_hi || check_lo != a_lo) {
            revert ProofInvalid();
        }
    }

    /// Square test in Fp.
    /// @notice Returns true if a is a quadratic residue mod P.
    function isSquare_Fp(uint256 a_hi, uint256 a_lo) internal view returns (bool) {
        (uint256 x_hi, uint256 x_lo) = fp_exp(a_hi, a_lo, EXP_SQRT_FP_HI, EXP_SQRT_FP_LO);
        (uint256 check_hi, uint256 check_lo) = fp_mul(x_hi, x_lo, x_hi, x_lo);
        return check_hi == a_hi && check_lo == a_lo;
    }

    /// Square root in Fp2.
    /// @notice Fp2 = Fp[u]/(u²+1). Input is a0 + a1·u, result is x0 + x1·u.
    function sqrt_Fp2(uint256 a0_hi, uint256 a0_lo, uint256 a1_hi, uint256 a1_lo, bool hint)
    internal view returns (uint256 x0_hi, uint256 x0_lo, uint256 x1_hi, uint256 x1_lo) {
        // d = sqrt(a0² + a1²)
        uint256 d_hi;
        uint256 d_lo;
        {
            (uint256 a0sq_hi, uint256 a0sq_lo) = fp_mul(a0_hi, a0_lo, a0_hi, a0_lo);
            (uint256 a1sq_hi, uint256 a1sq_lo) = fp_mul(a1_hi, a1_lo, a1_hi, a1_lo);
            (uint256 sum_hi, uint256 sum_lo) = fp_add(a0sq_hi, a0sq_lo, a1sq_hi, a1sq_lo);
            (d_hi, d_lo) = sqrt_Fp(sum_hi, sum_lo);
        }
        if (hint) {
            (d_hi, d_lo) = negate_Fp(d_hi, d_lo);
        }
        // x0 = sqrt((a0 + d) / 2)
        {
            (uint256 num_hi, uint256 num_lo) = fp_add(a0_hi, a0_lo, d_hi, d_lo);
            (uint256 half_hi, uint256 half_lo) = fp_mul(num_hi, num_lo, FRACTION_1_2_FP_HI, FRACTION_1_2_FP_LO);
            (x0_hi, x0_lo) = sqrt_Fp(half_hi, half_lo);
        }
        // x1 = a1 / (2 * x0)
        {
            (uint256 dbl_hi, uint256 dbl_lo) = fp_add(x0_hi, x0_lo, x0_hi, x0_lo);
            (uint256 inv_hi, uint256 inv_lo) = invert_Fp(dbl_hi, dbl_lo);
            (x1_hi, x1_lo) = fp_mul(a1_hi, a1_lo, inv_hi, inv_lo);
        }
        // Verify: a0 == x0² - x1², a1 == 2·x0·x1
        {
            (uint256 x0sq_hi, uint256 x0sq_lo) = fp_mul(x0_hi, x0_lo, x0_hi, x0_lo);
            (uint256 x1sq_hi, uint256 x1sq_lo) = fp_mul(x1_hi, x1_lo, x1_hi, x1_lo);
            (uint256 re_hi, uint256 re_lo) = fp_sub(x0sq_hi, x0sq_lo, x1sq_hi, x1sq_lo);
            if (re_hi != a0_hi || re_lo != a0_lo) {
                revert ProofInvalid();
            }
            (uint256 im_hi, uint256 im_lo) = fp_mul(x0_hi, x0_lo, x1_hi, x1_lo);
            (im_hi, im_lo) = fp_add(im_hi, im_lo, im_hi, im_lo);
            if (im_hi != a1_hi || im_lo != a1_lo) {
                revert ProofInvalid();
            }
        }
    }

    /// Compress a G1 point.
    /// @notice The point at infinity is encoded as (0,0,0,0) and compressed to (0,0).
    /// @param x_hi High 128 bits of x coordinate.
    /// @param x_lo Low 256 bits of x coordinate.
    /// @param y_hi High 128 bits of y coordinate.
    /// @param y_lo Low 256 bits of y coordinate.
    /// @return c_hi High part of compressed point.
    /// @return c_lo Low part of compressed point.
    function compress_g1(uint256 x_hi, uint256 x_lo, uint256 y_hi, uint256 y_lo)
    internal view returns (uint256 c_hi, uint256 c_lo) {
        if (x_hi > P_HI || (x_hi == P_HI && x_lo >= P_LO) ||
            y_hi > P_HI || (y_hi == P_HI && y_lo >= P_LO)) {
            revert ProofInvalid();
        }
        if ((x_hi | x_lo | y_hi | y_lo) == 0) {
            return (0, 0);
        }
        // y² = x³ + 4
        (uint256 x2_hi, uint256 x2_lo) = fp_mul(x_hi, x_lo, x_hi, x_lo);
        (uint256 x3_hi, uint256 x3_lo) = fp_mul(x2_hi, x2_lo, x_hi, x_lo);
        (uint256 rhs_hi, uint256 rhs_lo) = fp_add(x3_hi, x3_lo, 0, 4);
        (uint256 y_pos_hi, uint256 y_pos_lo) = sqrt_Fp(rhs_hi, rhs_lo);

        // c = x << 1 | signal_bit
        // signal_bit = 0 if y == y_pos, 1 if y == -y_pos
        uint256 signal;
        if (y_hi == y_pos_hi && y_lo == y_pos_lo) {
            signal = 0;
        } else {
            (uint256 y_neg_hi, uint256 y_neg_lo) = negate_Fp(y_pos_hi, y_pos_lo);
            if (y_hi == y_neg_hi && y_lo == y_neg_lo) {
                signal = 1;
            } else {
                revert ProofInvalid();
            }
        }
        // 384-bit left shift by 1: c_hi = (x_hi << 1) | (x_lo >> 255), c_lo = (x_lo << 1) | signal
        c_hi = (x_hi << 1) | (x_lo >> 255);
        c_lo = (x_lo << 1) | signal;
    }

    /// Decompress a G1 point.
    /// @notice Reverts with ProofInvalid if the input does not represent a valid point.
    /// @param c_hi High part of compressed point.
    /// @param c_lo Low part of compressed point.
    /// @return x_hi, x_lo The X coordinate.
    /// @return y_hi, y_lo The Y coordinate.
    function decompress_g1(uint256 c_hi, uint256 c_lo)
    internal view returns (uint256 x_hi, uint256 x_lo, uint256 y_hi, uint256 y_lo) {
        if (c_hi == 0 && c_lo == 0) {
            return (0, 0, 0, 0);
        }
        bool negate_point = c_lo & 1 == 1;
        // 384-bit right shift by 1
        x_lo = (c_lo >> 1) | (c_hi << 255);
        x_hi = c_hi >> 1;
        if (x_hi > P_HI || (x_hi == P_HI && x_lo >= P_LO)) {
            revert ProofInvalid();
        }
        // y = sqrt(x³ + 4)
        (uint256 x2_hi, uint256 x2_lo) = fp_mul(x_hi, x_lo, x_hi, x_lo);
        (uint256 x3_hi, uint256 x3_lo) = fp_mul(x2_hi, x2_lo, x_hi, x_lo);
        (uint256 rhs_hi, uint256 rhs_lo) = fp_add(x3_hi, x3_lo, 0, 4);
        (y_hi, y_lo) = sqrt_Fp(rhs_hi, rhs_lo);
        if (negate_point) {
            (y_hi, y_lo) = negate_Fp(y_hi, y_lo);
        }
    }

    /// Compute G2 curve RHS: x³ + 4(1+u) in Fp2.
    /// @notice For x = (x0 + x1·u), returns (rhs0 + rhs1·u) where rhs = x³ + (4, 4).
    function _g2_rhs(uint256 x0_hi, uint256 x0_lo, uint256 x1_hi, uint256 x1_lo)
    internal view returns (uint256 rhs0_hi, uint256 rhs0_lo, uint256 rhs1_hi, uint256 rhs1_lo) {
        // x³ in Fp2: let a = x0, b = x1
        // x³_re = a³ - 3·a·b²
        // x³_im = 3·a²·b - b³
        uint256 a2_hi; uint256 a2_lo;
        uint256 b2_hi; uint256 b2_lo;
        uint256 ab_hi; uint256 ab_lo;
        (a2_hi, a2_lo) = fp_mul(x0_hi, x0_lo, x0_hi, x0_lo);
        (b2_hi, b2_lo) = fp_mul(x1_hi, x1_lo, x1_hi, x1_lo);
        (ab_hi, ab_lo) = fp_mul(x0_hi, x0_lo, x1_hi, x1_lo);

        // 3·a·b² = 3·ab·b
        uint256 three_ab_hi; uint256 three_ab_lo;
        {
            (uint256 ab2_hi, uint256 ab2_lo) = fp_add(ab_hi, ab_lo, ab_hi, ab_lo);
            (three_ab_hi, three_ab_lo) = fp_add(ab2_hi, ab2_lo, ab_hi, ab_lo);
        }

        // a³ = a²·a
        (uint256 a3_hi, uint256 a3_lo) = fp_mul(a2_hi, a2_lo, x0_hi, x0_lo);
        // b³ = b²·b
        (uint256 b3_hi, uint256 b3_lo) = fp_mul(b2_hi, b2_lo, x1_hi, x1_lo);
        // 3·a·b² = three_ab · b
        (uint256 three_ab2_hi, uint256 three_ab2_lo) = fp_mul(three_ab_hi, three_ab_lo, x1_hi, x1_lo);
        // 3·a²·b = three_ab · a
        (uint256 three_a2b_hi, uint256 three_a2b_lo) = fp_mul(three_ab_hi, three_ab_lo, x0_hi, x0_lo);

        // rhs0 = a³ - 3·a·b² + 4
        (rhs0_hi, rhs0_lo) = fp_sub(a3_hi, a3_lo, three_ab2_hi, three_ab2_lo);
        (rhs0_hi, rhs0_lo) = fp_add(rhs0_hi, rhs0_lo, 0, 4);

        // rhs1 = 3·a²·b - b³ + 4
        (rhs1_hi, rhs1_lo) = fp_sub(three_a2b_hi, three_a2b_lo, b3_hi, b3_lo);
        (rhs1_hi, rhs1_lo) = fp_add(rhs1_hi, rhs1_lo, 0, 4);
    }

    /// Compress a G2 point.
    /// @notice G2 curve: y² = x³ + 4(1+u) over Fp2 = Fp[u]/(u²+1).
    function compress_g2(
        uint256 x0_hi, uint256 x0_lo, uint256 x1_hi, uint256 x1_lo,
        uint256 y0_hi, uint256 y0_lo, uint256 y1_hi, uint256 y1_lo
    ) internal view returns (uint256 c0_hi, uint256 c0_lo, uint256 c1_hi, uint256 c1_lo) {
        if (x0_hi > P_HI || (x0_hi == P_HI && x0_lo >= P_LO) ||
            x1_hi > P_HI || (x1_hi == P_HI && x1_lo >= P_LO) ||
            y0_hi > P_HI || (y0_hi == P_HI && y0_lo >= P_LO) ||
            y1_hi > P_HI || (y1_hi == P_HI && y1_lo >= P_LO)) {
            revert ProofInvalid();
        }
        if ((x0_hi | x0_lo | x1_hi | x1_lo | y0_hi | y0_lo | y1_hi | y1_lo) == 0) {
            return (0, 0, 0, 0);
        }

        // Compute RHS = x³ + 4(1+u)
        (uint256 rhs0_hi, uint256 rhs0_lo, uint256 rhs1_hi, uint256 rhs1_lo) = _g2_rhs(x0_hi, x0_lo, x1_hi, x1_lo);

        // Determine hint bit
        bool hint;
        {
            (uint256 r0sq_hi, uint256 r0sq_lo) = fp_mul(rhs0_hi, rhs0_lo, rhs0_hi, rhs0_lo);
            (uint256 r1sq_hi, uint256 r1sq_lo) = fp_mul(rhs1_hi, rhs1_lo, rhs1_hi, rhs1_lo);
            (uint256 norm_hi, uint256 norm_lo) = fp_add(r0sq_hi, r0sq_lo, r1sq_hi, r1sq_lo);
            (uint256 d_hi, uint256 d_lo) = sqrt_Fp(norm_hi, norm_lo);
            (uint256 half_arg_hi, uint256 half_arg_lo) = fp_add(rhs0_hi, rhs0_lo, d_hi, d_lo);
            (half_arg_hi, half_arg_lo) = fp_mul(half_arg_hi, half_arg_lo, FRACTION_1_2_FP_HI, FRACTION_1_2_FP_LO);
            hint = !isSquare_Fp(half_arg_hi, half_arg_lo);
        }

        // Recover y from RHS
        (uint256 y0_pos_hi, uint256 y0_pos_lo, uint256 y1_pos_hi, uint256 y1_pos_lo) = sqrt_Fp2(rhs0_hi, rhs0_lo, rhs1_hi, rhs1_lo, hint);

        uint256 signal;
        if (y0_hi == y0_pos_hi && y0_lo == y0_pos_lo && y1_hi == y1_pos_hi && y1_lo == y1_pos_lo) {
            signal = 0;
        } else {
            (uint256 ny0_hi, uint256 ny0_lo) = negate_Fp(y0_pos_hi, y0_pos_lo);
            (uint256 ny1_hi, uint256 ny1_lo) = negate_Fp(y1_pos_hi, y1_pos_lo);
            if (y0_hi == ny0_hi && y0_lo == ny0_lo && y1_hi == ny1_hi && y1_lo == ny1_lo) {
                signal = 1;
            } else {
                revert ProofInvalid();
            }
        }

        // c0 = x0 << 2 | hint << 1 | signal
        c0_hi = (x0_hi << 2) | (x0_lo >> 254);
        c0_lo = (x0_lo << 2) | (hint ? 2 : 0) | signal;
        c1_hi = x1_hi;
        c1_lo = x1_lo;
    }

    /// Decompress a G2 point.
    /// @notice Reverts with ProofInvalid if the input does not represent a valid point.
    function decompress_g2(uint256 c0_hi, uint256 c0_lo, uint256 c1_hi, uint256 c1_lo)
    internal view returns (
        uint256 x0_hi, uint256 x0_lo, uint256 x1_hi, uint256 x1_lo,
        uint256 y0_hi, uint256 y0_lo, uint256 y1_hi, uint256 y1_lo
    ) {
        if (c0_hi == 0 && c0_lo == 0 && c1_hi == 0 && c1_lo == 0) {
            return (0, 0, 0, 0, 0, 0, 0, 0);
        }
        bool negate_point = c0_lo & 1 == 1;
        bool hint = c0_lo & 2 == 2;
        // Extract x0: right shift c0 by 2 bits
        x0_lo = (c0_lo >> 2) | (c0_hi << 254);
        x0_hi = c0_hi >> 2;
        x1_hi = c1_hi;
        x1_lo = c1_lo;

        if (x0_hi > P_HI || (x0_hi == P_HI && x0_lo >= P_LO) ||
            x1_hi > P_HI || (x1_hi == P_HI && x1_lo >= P_LO)) {
            revert ProofInvalid();
        }

        // Compute RHS and sqrt
        (uint256 rhs0_hi, uint256 rhs0_lo, uint256 rhs1_hi, uint256 rhs1_lo) = _g2_rhs(x0_hi, x0_lo, x1_hi, x1_lo);
        (y0_hi, y0_lo, y1_hi, y1_lo) = sqrt_Fp2(rhs0_hi, rhs0_lo, rhs1_hi, rhs1_lo, hint);
        if (negate_point) {
            (y0_hi, y0_lo) = negate_Fp(y0_hi, y0_lo);
            (y1_hi, y1_lo) = negate_Fp(y1_hi, y1_lo);
        }
    }

    /// Compute the public input linear combination.
    /// @notice Uses BLS12-381 G1 MSM precompile (EIP-2537) for efficient computation.
    /// @notice Computes the multi-scalar-multiplication of the public input
    /// elements and the verification key including the constant term.
    /// @param input The public inputs. These are elements of the scalar field Fr.
    {{- if gt $numCommitments 0 }}
    /// @param publicCommitments public inputs generated from pedersen commitments.
    /// @param commitments The Pedersen commitments from the proof (padded to 128 bytes each).
    {{- end }}
    /// @return x_hi The high part of the X coordinate of the resulting G1 point.
    /// @return x_lo The low part of the X coordinate.
    /// @return y_hi The high part of the Y coordinate.
    /// @return y_lo The low part of the Y coordinate.
    {{- if eq $numCommitments 0 }}
    function publicInputMSM(uint256[{{$numWitness}}] calldata input)
    {{- else }}
    function publicInputMSM(
        uint256[{{$numWitness}}] calldata input,
        uint256[{{$numCommitments}}] memory publicCommitments,
        uint256[{{mul $numCommitments 4}}] memory commitments
    )
    {{- end }}
    internal view returns (uint256 x_hi, uint256 x_lo, uint256 y_hi, uint256 y_lo) {
        // BLS12_G1MSM input: k elements of (G1_point[128 bytes] + scalar[32 bytes]) = k * 160 bytes
        // Output: one G1 point (128 bytes)
        bool success = true;
        assembly ("memory-safe") {
            let f := mload(0x40)
            let s
            // Element 0: CONSTANT with scalar 1
            mstore(f, CONSTANT_X_HI)
            mstore(add(f, 0x20), CONSTANT_X_LO)
            mstore(add(f, 0x40), CONSTANT_Y_HI)
            mstore(add(f, 0x60), CONSTANT_Y_LO)
            mstore(add(f, 0x80), 1)
            {{- range $i := intRange $numPublic }}
            // Element {{ sum $i 1 }}: PUB_{{$i}}
            mstore(add(f, {{ hex (mul (sum $i 1) 0xa0) }}), PUB_{{$i}}_X_HI)
            mstore(add(f, {{ hex (sum (mul (sum $i 1) 0xa0) 0x20) }}), PUB_{{$i}}_X_LO)
            mstore(add(f, {{ hex (sum (mul (sum $i 1) 0xa0) 0x40) }}), PUB_{{$i}}_Y_HI)
            mstore(add(f, {{ hex (sum (mul (sum $i 1) 0xa0) 0x60) }}), PUB_{{$i}}_Y_LO)
            {{- if lt $i $numWitness }}
            {{- if eq $i 0 }}
            s := calldataload(input)
            {{- else }}
            s := calldataload(add(input, {{ hex (mul $i 0x20) }}))
            {{- end }}
            {{- else }}
            {{- if eq (sub $i $numWitness) 0 }}
            s := mload(publicCommitments)
            {{- else }}
            s := mload(add(publicCommitments, {{ hex (mul 0x20 (sub $i $numWitness)) }}))
            {{- end }}
            {{- end }}
            mstore(add(f, {{ hex (sum (mul (sum $i 1) 0xa0) 0x80) }}), s)
            success := and(success, lt(s, R))
            {{- end }}

            {{- if gt $numCommitments 0 }}
            // Add commitment G1 points with scalar 1
            // Commitments are stored in memory as padded 128-byte G1 points (4 uint256 each)
            {{- range $i := intRange $numCommitments }}
            mstore(add(f, {{ hex (mul (sum $numPublic (sum $i 1)) 0xa0) }}), mload(add(commitments, {{ hex (mul $i 0x80) }})))
            mstore(add(f, {{ hex (sum (mul (sum $numPublic (sum $i 1)) 0xa0) 0x20) }}), mload(add(commitments, {{ hex (sum (mul $i 0x80) 0x20) }})))
            mstore(add(f, {{ hex (sum (mul (sum $numPublic (sum $i 1)) 0xa0) 0x40) }}), mload(add(commitments, {{ hex (sum (mul $i 0x80) 0x40) }})))
            mstore(add(f, {{ hex (sum (mul (sum $numPublic (sum $i 1)) 0xa0) 0x60) }}), mload(add(commitments, {{ hex (sum (mul $i 0x80) 0x60) }})))
            mstore(add(f, {{ hex (sum (mul (sum $numPublic (sum $i 1)) 0xa0) 0x80) }}), 1)
            {{- end }}
            {{- end }}

            success := and(success, staticcall(gas(), PRECOMPILE_BLS12_G1MSM, f, {{ hex (mul (sum (sum $numPublic 1) $numCommitments) 0xa0) }}, f, 0x80))

            x_hi := mload(f)
            x_lo := mload(add(f, 0x20))
            y_hi := mload(add(f, 0x40))
            y_lo := mload(add(f, 0x60))
        }
        if (!success) {
            // Either Public input not in field, or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert PublicInputNotInField();
        }
    }

    /// Compress a proof.
    /// @notice Will revert with ProofInvalid if the curve points are invalid,
    /// but does not verify the proof itself.
    /// @param proof the serialized uncompressed proof (384 bytes without commitments).
    {{- if gt $numCommitments 0 }}
    /// Followed by commitments and PoK.
    {{- end }}
    /// @return compressed The compressed proof as uint256[8].
    {{- if gt $numCommitments 0 }}
    /// @return compressedCommitments compressed Pedersen commitments.
    /// @return compressedCommitmentPok compressed proof of knowledge.
    {{- end }}
    {{- if eq $numCommitments 0 }}
    function compressProof(bytes calldata proof)
    public view returns (uint256[8] memory compressed) {
        require(proof.length == 384, "invalid proof length");
    {{- else }}
    function compressProof(bytes calldata proof)
    public view returns (
        uint256[8] memory compressed,
        uint256[{{mul $numCommitments 2}}] memory compressedCommitments,
        uint256[2] memory compressedCommitmentPok
    ) {
        require(proof.length == {{ sum 384 (mul (sum $numCommitments 1) 96) }}, "invalid proof length");
    {{- end }}
        // Read A (G1): 96 bytes at offset 0x00
        uint256 ax_hi; uint256 ax_lo; uint256 ay_hi; uint256 ay_lo;
        uint256 bx0_hi; uint256 bx0_lo; uint256 bx1_hi; uint256 bx1_lo;
        uint256 by0_hi; uint256 by0_lo; uint256 by1_hi; uint256 by1_lo;
        uint256 cx_hi; uint256 cx_lo; uint256 cy_hi; uint256 cy_lo;
        assembly ("memory-safe") {
            // A.x (48 bytes at offset 0x00)
            ax_hi := shr(128, calldataload(proof.offset))
            ax_lo := calldataload(add(proof.offset, 0x10))
            // A.y (48 bytes at offset 0x30)
            ay_hi := shr(128, calldataload(add(proof.offset, 0x30)))
            ay_lo := calldataload(add(proof.offset, 0x40))
            // B.x.A0 (48 bytes at offset 0x60)
            bx0_hi := shr(128, calldataload(add(proof.offset, 0x60)))
            bx0_lo := calldataload(add(proof.offset, 0x70))
            // B.x.A1 (48 bytes at offset 0x90)
            bx1_hi := shr(128, calldataload(add(proof.offset, 0x90)))
            bx1_lo := calldataload(add(proof.offset, 0xa0))
            // B.y.A0 (48 bytes at offset 0xC0)
            by0_hi := shr(128, calldataload(add(proof.offset, 0xc0)))
            by0_lo := calldataload(add(proof.offset, 0xd0))
            // B.y.A1 (48 bytes at offset 0xF0)
            by1_hi := shr(128, calldataload(add(proof.offset, 0xf0)))
            by1_lo := calldataload(add(proof.offset, 0x100))
            // C.x (48 bytes at offset 0x120)
            cx_hi := shr(128, calldataload(add(proof.offset, 0x120)))
            cx_lo := calldataload(add(proof.offset, 0x130))
            // C.y (48 bytes at offset 0x150)
            cy_hi := shr(128, calldataload(add(proof.offset, 0x150)))
            cy_lo := calldataload(add(proof.offset, 0x160))
        }

        // Compress A (G1)
        (compressed[0], compressed[1]) = compress_g1(ax_hi, ax_lo, ay_hi, ay_lo);
        // Compress B (G2)
        (compressed[2], compressed[3], compressed[4], compressed[5]) = compress_g2(
            bx0_hi, bx0_lo, bx1_hi, bx1_lo,
            by0_hi, by0_lo, by1_hi, by1_lo
        );
        // Compress C (G1)
        (compressed[6], compressed[7]) = compress_g1(cx_hi, cx_lo, cy_hi, cy_lo);

        {{- if gt $numCommitments 0 }}
        // Compress commitments
        {{- range $i := intRange $numCommitments }}
        {
            uint256 cmx_hi; uint256 cmx_lo; uint256 cmy_hi; uint256 cmy_lo;
            assembly ("memory-safe") {
                cmx_hi := shr(128, calldataload(add(proof.offset, {{ hex (sum 0x180 (mul $i 0x60)) }})))
                cmx_lo := calldataload(add(proof.offset, {{ hex (sum 0x190 (mul $i 0x60)) }}))
                cmy_hi := shr(128, calldataload(add(proof.offset, {{ hex (sum 0x1b0 (mul $i 0x60)) }})))
                cmy_lo := calldataload(add(proof.offset, {{ hex (sum 0x1c0 (mul $i 0x60)) }}))
            }
            (compressedCommitments[{{mul $i 2}}], compressedCommitments[{{sum (mul $i 2) 1}}]) = compress_g1(cmx_hi, cmx_lo, cmy_hi, cmy_lo);
        }
        {{- end }}
        // Compress commitmentPok
        {
            uint256 pkx_hi; uint256 pkx_lo; uint256 pky_hi; uint256 pky_lo;
            assembly ("memory-safe") {
                pkx_hi := shr(128, calldataload(add(proof.offset, {{ hex (sum 0x180 (mul $numCommitments 0x60)) }})))
                pkx_lo := calldataload(add(proof.offset, {{ hex (sum 0x190 (mul $numCommitments 0x60)) }}))
                pky_hi := shr(128, calldataload(add(proof.offset, {{ hex (sum 0x1b0 (mul $numCommitments 0x60)) }})))
                pky_lo := calldataload(add(proof.offset, {{ hex (sum 0x1c0 (mul $numCommitments 0x60)) }}))
            }
            (compressedCommitmentPok[0], compressedCommitmentPok[1]) = compress_g1(pkx_hi, pkx_lo, pky_hi, pky_lo);
        }
        {{- end }}
    }

    /// Verify a Groth16 proof with compressed points.
    /// @notice Reverts with ProofInvalid if the proof is invalid or
    /// with PublicInputNotInField the public input is not reduced.
    /// @notice There is no return value. If the function does not revert, the
    /// proof was successfully verified.
    /// @param compressedProof the compressed proof as uint256[8]:
    /// [A_hi, A_lo, B_c0_hi, B_c0_lo, B_c1_hi, B_c1_lo, C_hi, C_lo].
    {{- if gt $numCommitments 0 }}
    /// @param compressedCommitments compressed Pedersen commitments (2 uint256 per commitment).
    /// @param compressedCommitmentPok compressed proof of knowledge (2 uint256).
    {{- end }}
    /// @param input the public input field elements in the scalar field Fr.
    function verifyCompressedProof(
        uint256[8] calldata compressedProof,
        {{- if gt $numCommitments 0 }}
        uint256[{{mul 2 $numCommitments}}] calldata compressedCommitments,
        uint256[2] calldata compressedCommitmentPok,
        {{- end }}
        uint256[{{$numWitness}}] calldata input
    ) public view {
        {{- if gt $numCommitments 0 }}
        uint256[{{$numCommitments}}] memory publicCommitments;
        uint256[{{mul $numCommitments 4}}] memory commitments;
        {
            {{- range $i := intRange $numCommitments }}
            {
                (uint256 cmx_hi, uint256 cmx_lo, uint256 cmy_hi, uint256 cmy_lo) = decompress_g1(
                    compressedCommitments[{{mul $i 2}}], compressedCommitments[{{sum (mul $i 2) 1}}]
                );
                commitments[{{mul $i 4}}] = cmx_hi;
                commitments[{{sum (mul $i 4) 1}}] = cmx_lo;
                commitments[{{sum (mul $i 4) 2}}] = cmy_hi;
                commitments[{{sum (mul $i 4) 3}}] = cmy_lo;
            }
            {{- end }}
            (uint256 Px_hi, uint256 Px_lo, uint256 Py_hi, uint256 Py_lo) = decompress_g1(compressedCommitmentPok[0], compressedCommitmentPok[1]);

            uint256[] memory publicAndCommitmentCommitted;
            {{- range $i := intRange $numCommitments }}
            {{- $pcIndex := index $PublicAndCommitmentCommitted $i }}
            {{- if gt (len $pcIndex) 0 }}
            publicAndCommitmentCommitted = new uint256[]({{ len $pcIndex }});
            assembly ("memory-safe") {
                let publicAndCommitmentCommittedOffset := add(publicAndCommitmentCommitted, 0x20)
                {{- $segment_start := index $pcIndex 0 }}
                {{- $segment_end := index $pcIndex 0 }}
                {{- $l := 0 }}
                {{- range $k := intRange (sub (len $pcIndex) 1) }}
                    {{- $next := index $pcIndex (sum $k 1) }}
                    {{- if ne $next (sum $segment_end 1) }}
                calldatacopy(add(publicAndCommitmentCommittedOffset, {{ mul $l 0x20 }}), add(input, {{ mul 0x20 (sub $segment_start 1) }}), {{ mul 0x20 (sum 1 (sub $segment_end $segment_start)) }})
                        {{- $segment_start = $next }}
                        {{- $l = (sum $k 1) }}
                    {{- end }}
                    {{- $segment_end = $next }}
                {{- end }}
                calldatacopy(add(publicAndCommitmentCommittedOffset, {{ mul $l 0x20 }}), add(input, {{ mul 0x20 (sub $segment_start 1) }}), {{ mul 0x20 (sum 1 (sub $segment_end $segment_start)) }})
            }
            {{- end }}

            // Hash: keccak256(commitment_x_raw(48) || commitment_y_raw(48) || publicAndCommitmentCommitted) % R
            // Build raw bytes from decompressed commitment coordinates
            {
                bytes memory hashInput;
                {
                    bytes memory rawPoint = new bytes(96);
                    assembly ("memory-safe") {
                        let ptr := add(rawPoint, 0x20)
                        mstore(ptr, shl(128, mload(add(commitments, {{ hex (mul $i 0x80) }}))))
                        mstore(add(ptr, 0x10), mload(add(commitments, {{ hex (sum (mul $i 0x80) 0x20) }})))
                        mstore(add(ptr, 0x30), shl(128, mload(add(commitments, {{ hex (sum (mul $i 0x80) 0x40) }}))))
                        mstore(add(ptr, 0x40), mload(add(commitments, {{ hex (sum (mul $i 0x80) 0x60) }})))
                    }
                    hashInput = abi.encodePacked(rawPoint, publicAndCommitmentCommitted);
                }
                publicCommitments[{{$i}}] = uint256({{ hashFnName }}(hashInput)) % R;
            }
            {{- end }}

            // Verify Pedersen commitments
            {
                bool commitSuccess;
                assembly ("memory-safe") {
                    let f := mload(0x40)

                    // Pair 0: e(commitment, GSigmaNeg)
                    // Load commitment G1 point (padded to 128 bytes)
                    mstore(f, mload(commitments))
                    mstore(add(f, 0x20), mload(add(commitments, 0x20)))
                    mstore(add(f, 0x40), mload(add(commitments, 0x40)))
                    mstore(add(f, 0x60), mload(add(commitments, 0x60)))
                    // GSigmaNeg G2 point
                    mstore(add(f, 0x80), PEDERSEN_GSIGMANEG_X_0_HI)
                    mstore(add(f, 0xa0), PEDERSEN_GSIGMANEG_X_0_LO)
                    mstore(add(f, 0xc0), PEDERSEN_GSIGMANEG_X_1_HI)
                    mstore(add(f, 0xe0), PEDERSEN_GSIGMANEG_X_1_LO)
                    mstore(add(f, 0x100), PEDERSEN_GSIGMANEG_Y_0_HI)
                    mstore(add(f, 0x120), PEDERSEN_GSIGMANEG_Y_0_LO)
                    mstore(add(f, 0x140), PEDERSEN_GSIGMANEG_Y_1_HI)
                    mstore(add(f, 0x160), PEDERSEN_GSIGMANEG_Y_1_LO)

                    // Pair 1: e(Pok, G)
                    mstore(add(f, 0x180), Px_hi)
                    mstore(add(f, 0x1a0), Px_lo)
                    mstore(add(f, 0x1c0), Py_hi)
                    mstore(add(f, 0x1e0), Py_lo)
                    mstore(add(f, 0x200), PEDERSEN_G_X_0_HI)
                    mstore(add(f, 0x220), PEDERSEN_G_X_0_LO)
                    mstore(add(f, 0x240), PEDERSEN_G_X_1_HI)
                    mstore(add(f, 0x260), PEDERSEN_G_X_1_LO)
                    mstore(add(f, 0x280), PEDERSEN_G_Y_0_HI)
                    mstore(add(f, 0x2a0), PEDERSEN_G_Y_0_LO)
                    mstore(add(f, 0x2c0), PEDERSEN_G_Y_1_HI)
                    mstore(add(f, 0x2e0), PEDERSEN_G_Y_1_LO)

                    commitSuccess := staticcall(gas(), PRECOMPILE_BLS12_PAIR, f, 0x300, f, 0x20)
                    commitSuccess := and(commitSuccess, mload(f))
                }
                if (!commitSuccess) {
                    revert CommitmentInvalid();
                }
            }
        }

        (uint256 Lx_hi, uint256 Lx_lo, uint256 Ly_hi, uint256 Ly_lo) = publicInputMSM(
            input,
            publicCommitments,
            commitments
        );
        {{- else }}
        (uint256 Lx_hi, uint256 Lx_lo, uint256 Ly_hi, uint256 Ly_lo) = publicInputMSM(input);
        {{- end }}

        // Decompress proof points
        (uint256 Ax_hi, uint256 Ax_lo, uint256 Ay_hi, uint256 Ay_lo) = decompress_g1(compressedProof[0], compressedProof[1]);
        (uint256 Bx0_hi, uint256 Bx0_lo, uint256 Bx1_hi, uint256 Bx1_lo,
         uint256 By0_hi, uint256 By0_lo, uint256 By1_hi, uint256 By1_lo) = decompress_g2(
            compressedProof[2], compressedProof[3], compressedProof[4], compressedProof[5]
        );
        (uint256 Cx_hi, uint256 Cx_lo, uint256 Cy_hi, uint256 Cy_lo) = decompress_g1(compressedProof[6], compressedProof[7]);

        // Build pairing input and verify
        {{- if eq $numCommitments 0 }}
        bool success;
        {{- end }}
        assembly ("memory-safe") {
            let f := mload(0x40)

            // Pair 0: e(A, B) — G1(128 bytes) + G2(256 bytes) = 384 bytes
            mstore(f, Ax_hi)
            mstore(add(f, 0x20), Ax_lo)
            mstore(add(f, 0x40), Ay_hi)
            mstore(add(f, 0x60), Ay_lo)
            mstore(add(f, 0x80), Bx0_hi)
            mstore(add(f, 0xa0), Bx0_lo)
            mstore(add(f, 0xc0), Bx1_hi)
            mstore(add(f, 0xe0), Bx1_lo)
            mstore(add(f, 0x100), By0_hi)
            mstore(add(f, 0x120), By0_lo)
            mstore(add(f, 0x140), By1_hi)
            mstore(add(f, 0x160), By1_lo)

            // Pair 1: e(C, -δ)
            mstore(add(f, 0x180), Cx_hi)
            mstore(add(f, 0x1a0), Cx_lo)
            mstore(add(f, 0x1c0), Cy_hi)
            mstore(add(f, 0x1e0), Cy_lo)
            mstore(add(f, 0x200), DELTA_NEG_X_0_HI)
            mstore(add(f, 0x220), DELTA_NEG_X_0_LO)
            mstore(add(f, 0x240), DELTA_NEG_X_1_HI)
            mstore(add(f, 0x260), DELTA_NEG_X_1_LO)
            mstore(add(f, 0x280), DELTA_NEG_Y_0_HI)
            mstore(add(f, 0x2a0), DELTA_NEG_Y_0_LO)
            mstore(add(f, 0x2c0), DELTA_NEG_Y_1_HI)
            mstore(add(f, 0x2e0), DELTA_NEG_Y_1_LO)

            // Pair 2: e(α, -β)
            mstore(add(f, 0x300), ALPHA_X_HI)
            mstore(add(f, 0x320), ALPHA_X_LO)
            mstore(add(f, 0x340), ALPHA_Y_HI)
            mstore(add(f, 0x360), ALPHA_Y_LO)
            mstore(add(f, 0x380), BETA_NEG_X_0_HI)
            mstore(add(f, 0x3a0), BETA_NEG_X_0_LO)
            mstore(add(f, 0x3c0), BETA_NEG_X_1_HI)
            mstore(add(f, 0x3e0), BETA_NEG_X_1_LO)
            mstore(add(f, 0x400), BETA_NEG_Y_0_HI)
            mstore(add(f, 0x420), BETA_NEG_Y_0_LO)
            mstore(add(f, 0x440), BETA_NEG_Y_1_HI)
            mstore(add(f, 0x460), BETA_NEG_Y_1_LO)

            // Pair 3: e(L_pub, -γ)
            mstore(add(f, 0x480), Lx_hi)
            mstore(add(f, 0x4a0), Lx_lo)
            mstore(add(f, 0x4c0), Ly_hi)
            mstore(add(f, 0x4e0), Ly_lo)
            mstore(add(f, 0x500), GAMMA_NEG_X_0_HI)
            mstore(add(f, 0x520), GAMMA_NEG_X_0_LO)
            mstore(add(f, 0x540), GAMMA_NEG_X_1_HI)
            mstore(add(f, 0x560), GAMMA_NEG_X_1_LO)
            mstore(add(f, 0x580), GAMMA_NEG_Y_0_HI)
            mstore(add(f, 0x5a0), GAMMA_NEG_Y_0_LO)
            mstore(add(f, 0x5c0), GAMMA_NEG_Y_1_HI)
            mstore(add(f, 0x5e0), GAMMA_NEG_Y_1_LO)

            {{- if gt $numCommitments 0 }}
            let success
            {{- end }}
            success := staticcall(gas(), PRECOMPILE_BLS12_PAIR, f, 0x600, f, 0x20)
            success := and(success, mload(f))
        }
        if (!success) {
            revert ProofInvalid();
        }
    }

    /// Verify an uncompressed Groth16 proof.
    /// @notice Reverts with InvalidProof if the proof is invalid or
    /// with PublicInputNotInField the public input is not reduced.
    /// @notice There is no return value. If the function does not revert, the
    /// proof was successfully verified.
    /// @param proof the serialized proof, containing Ar (96 bytes G1), Bs (192 bytes G2),
    /// Krs (96 bytes G1) = 384 bytes total.
    {{- if gt $numCommitments 0 }}
    /// Followed by commitments ({{$numCommitments}} × 96 bytes G1) and commitmentPok (96 bytes G1).
    {{- end }}
    /// @param input the public input field elements in the scalar field Fr.
    /// Elements must be reduced.
    function verifyProof(
        bytes calldata proof,
        uint256[{{$numWitness}}] calldata input
    ) public view {
        {{- if gt $numCommitments 0 }}
        require(proof.length == {{ sum 384 (mul (sum $numCommitments 1) 96) }}, "invalid proof length");
        {{- else }}
        require(proof.length == 384, "invalid proof length");
        {{- end }}

        {{- if gt $numCommitments 0 }}
        // Load commitment points and compute public commitment hashes
        uint256[{{$numCommitments}}] memory publicCommitments;
        uint256[{{mul $numCommitments 4}}] memory commitments;

        // Load commitment points from proof (padded to 128 bytes each in memory)
        assembly ("memory-safe") {
            {{- range $i := intRange $numCommitments }}
            // Commitment {{$i}}: load raw 96-byte G1 from calldata, pad to 128 bytes
            mstore(add(commitments, {{ hex (mul $i 0x80) }}), 0)
            calldatacopy(add(commitments, {{ hex (sum (mul $i 0x80) 0x10) }}), add(proof.offset, {{ hex (sum 0x180 (mul $i 0x60)) }}), 0x30)
            mstore(add(commitments, {{ hex (sum (mul $i 0x80) 0x40) }}), 0)
            calldatacopy(add(commitments, {{ hex (sum (mul $i 0x80) 0x50) }}), add(proof.offset, {{ hex (sum 0x1b0 (mul $i 0x60)) }}), 0x30)
            {{- end }}
        }

        // Compute public commitment hashes
        uint256[] memory publicAndCommitmentCommitted;
        {{- range $i := intRange $numCommitments }}
        {{- $pcIndex := index $PublicAndCommitmentCommitted $i }}
        {{- if gt (len $pcIndex) 0 }}
        publicAndCommitmentCommitted = new uint256[]({{ len $pcIndex }});
        assembly ("memory-safe") {
            let publicAndCommitmentCommittedOffset := add(publicAndCommitmentCommitted, 0x20)
            {{- $segment_start := index $pcIndex 0 }}
            {{- $segment_end := index $pcIndex 0 }}
            {{- $l := 0 }}
            {{- range $k := intRange (sub (len $pcIndex) 1) }}
                {{- $next := index $pcIndex (sum $k 1) }}
                {{- if ne $next (sum $segment_end 1) }}
            calldatacopy(add(publicAndCommitmentCommittedOffset, {{ mul $l 0x20 }}), add(input, {{ mul 0x20 (sub $segment_start 1) }}), {{ mul 0x20 (sum 1 (sub $segment_end $segment_start)) }})
                    {{- $segment_start = $next }}
                    {{- $l = (sum $k 1) }}
                {{- end }}
                {{- $segment_end = $next }}
            {{- end }}
            calldatacopy(add(publicAndCommitmentCommittedOffset, {{ mul $l 0x20 }}), add(input, {{ mul 0x20 (sub $segment_start 1) }}), {{ mul 0x20 (sum 1 (sub $segment_end $segment_start)) }})
        }
        {{- end }}

        // Hash: keccak256(commitment_raw_bytes || publicAndCommitmentCommitted) % R
        // The commitment raw bytes are 96 bytes from calldata
        {
            bytes memory hashInput = abi.encodePacked(
                proof[{{ sum 0x180 (mul $i 0x60) }}:{{ sum 0x1e0 (mul $i 0x60) }}],
                publicAndCommitmentCommitted
            );
            publicCommitments[{{$i}}] = uint256({{ hashFnName }}(hashInput)) % R;
        }
        {{- end }}

        // Verify Pedersen commitments
        {
            bool commitSuccess;
            assembly ("memory-safe") {
                let f := mload(0x40)

                // Pair 0: e(commitment, GSigmaNeg)
                // Load commitment G1 point (already padded in commitments memory)
                mcopy(f, commitments, 0x80)
                // GSigmaNeg G2 point
                mstore(add(f, 0x80), PEDERSEN_GSIGMANEG_X_0_HI)
                mstore(add(f, 0xa0), PEDERSEN_GSIGMANEG_X_0_LO)
                mstore(add(f, 0xc0), PEDERSEN_GSIGMANEG_X_1_HI)
                mstore(add(f, 0xe0), PEDERSEN_GSIGMANEG_X_1_LO)
                mstore(add(f, 0x100), PEDERSEN_GSIGMANEG_Y_0_HI)
                mstore(add(f, 0x120), PEDERSEN_GSIGMANEG_Y_0_LO)
                mstore(add(f, 0x140), PEDERSEN_GSIGMANEG_Y_1_HI)
                mstore(add(f, 0x160), PEDERSEN_GSIGMANEG_Y_1_LO)

                // Pair 1: e(Pok, G)
                // Load PoK from proof calldata (96 bytes at offset after commitments)
                mstore(add(f, 0x180), 0)
                calldatacopy(add(f, 0x190), add(proof.offset, {{ hex (sum 0x180 (mul $numCommitments 0x60)) }}), 0x30)
                mstore(add(f, 0x1c0), 0)
                calldatacopy(add(f, 0x1d0), add(proof.offset, {{ hex (sum 0x1b0 (mul $numCommitments 0x60)) }}), 0x30)
                // G point
                mstore(add(f, 0x200), PEDERSEN_G_X_0_HI)
                mstore(add(f, 0x220), PEDERSEN_G_X_0_LO)
                mstore(add(f, 0x240), PEDERSEN_G_X_1_HI)
                mstore(add(f, 0x260), PEDERSEN_G_X_1_LO)
                mstore(add(f, 0x280), PEDERSEN_G_Y_0_HI)
                mstore(add(f, 0x2a0), PEDERSEN_G_Y_0_LO)
                mstore(add(f, 0x2c0), PEDERSEN_G_Y_1_HI)
                mstore(add(f, 0x2e0), PEDERSEN_G_Y_1_LO)

                // BLS12_PAIR: 2 pairs × 384 bytes = 768 bytes
                commitSuccess := staticcall(gas(), PRECOMPILE_BLS12_PAIR, f, 0x300, f, 0x20)
                commitSuccess := and(commitSuccess, mload(f))
            }
            if (!commitSuccess) {
                revert CommitmentInvalid();
            }
        }

        (uint256 Lx_hi, uint256 Lx_lo, uint256 Ly_hi, uint256 Ly_lo) = publicInputMSM(
            input,
            publicCommitments,
            commitments
        );
        {{- else }}
        (uint256 Lx_hi, uint256 Lx_lo, uint256 Ly_hi, uint256 Ly_lo) = publicInputMSM(input);
        {{- end }}

        // Verify the Groth16 pairing equation:
        // e(A, B) · e(C, -δ) · e(α, -β) · e(L_pub, -γ) = 1
        //
        // Pairing input: 4 pairs × (G1[128] + G2[256]) = 4 × 384 = 1536 bytes
        {{- if eq $numCommitments 0 }}
        bool success;
        {{- end }}
        assembly ("memory-safe") {
            let f := mload(0x40)

            // Pair 0: e(A, B)
            // A (G1): 96 bytes at proof offset 0x00
            mstore(f, 0)
            calldatacopy(add(f, 0x10), proof.offset, 0x30)
            mstore(add(f, 0x40), 0)
            calldatacopy(add(f, 0x50), add(proof.offset, 0x30), 0x30)
            // B (G2): 192 bytes at proof offset 0x60
            // X.A0
            mstore(add(f, 0x80), 0)
            calldatacopy(add(f, 0x90), add(proof.offset, 0x60), 0x30)
            // X.A1
            mstore(add(f, 0xc0), 0)
            calldatacopy(add(f, 0xd0), add(proof.offset, 0x90), 0x30)
            // Y.A0
            mstore(add(f, 0x100), 0)
            calldatacopy(add(f, 0x110), add(proof.offset, 0xc0), 0x30)
            // Y.A1
            mstore(add(f, 0x140), 0)
            calldatacopy(add(f, 0x150), add(proof.offset, 0xf0), 0x30)

            // Pair 1: e(C, -δ)
            // C (G1): 96 bytes at proof offset 0x120
            mstore(add(f, 0x180), 0)
            calldatacopy(add(f, 0x190), add(proof.offset, 0x120), 0x30)
            mstore(add(f, 0x1c0), 0)
            calldatacopy(add(f, 0x1d0), add(proof.offset, 0x150), 0x30)
            // -δ (constant G2)
            mstore(add(f, 0x200), DELTA_NEG_X_0_HI)
            mstore(add(f, 0x220), DELTA_NEG_X_0_LO)
            mstore(add(f, 0x240), DELTA_NEG_X_1_HI)
            mstore(add(f, 0x260), DELTA_NEG_X_1_LO)
            mstore(add(f, 0x280), DELTA_NEG_Y_0_HI)
            mstore(add(f, 0x2a0), DELTA_NEG_Y_0_LO)
            mstore(add(f, 0x2c0), DELTA_NEG_Y_1_HI)
            mstore(add(f, 0x2e0), DELTA_NEG_Y_1_LO)

            // Pair 2: e(α, -β)
            mstore(add(f, 0x300), ALPHA_X_HI)
            mstore(add(f, 0x320), ALPHA_X_LO)
            mstore(add(f, 0x340), ALPHA_Y_HI)
            mstore(add(f, 0x360), ALPHA_Y_LO)
            mstore(add(f, 0x380), BETA_NEG_X_0_HI)
            mstore(add(f, 0x3a0), BETA_NEG_X_0_LO)
            mstore(add(f, 0x3c0), BETA_NEG_X_1_HI)
            mstore(add(f, 0x3e0), BETA_NEG_X_1_LO)
            mstore(add(f, 0x400), BETA_NEG_Y_0_HI)
            mstore(add(f, 0x420), BETA_NEG_Y_0_LO)
            mstore(add(f, 0x440), BETA_NEG_Y_1_HI)
            mstore(add(f, 0x460), BETA_NEG_Y_1_LO)

            // Pair 3: e(L_pub, -γ)
            mstore(add(f, 0x480), Lx_hi)
            mstore(add(f, 0x4a0), Lx_lo)
            mstore(add(f, 0x4c0), Ly_hi)
            mstore(add(f, 0x4e0), Ly_lo)
            mstore(add(f, 0x500), GAMMA_NEG_X_0_HI)
            mstore(add(f, 0x520), GAMMA_NEG_X_0_LO)
            mstore(add(f, 0x540), GAMMA_NEG_X_1_HI)
            mstore(add(f, 0x560), GAMMA_NEG_X_1_LO)
            mstore(add(f, 0x580), GAMMA_NEG_Y_0_HI)
            mstore(add(f, 0x5a0), GAMMA_NEG_Y_0_LO)
            mstore(add(f, 0x5c0), GAMMA_NEG_Y_1_HI)
            mstore(add(f, 0x5e0), GAMMA_NEG_Y_1_LO)

            // BLS12_PAIR: 4 pairs × 384 bytes = 1536 bytes
            {{- if gt $numCommitments 0 }}
            let success
            {{- end }}
            success := staticcall(gas(), PRECOMPILE_BLS12_PAIR, f, 0x600, f, 0x20)
            success := and(success, mload(f))
        }
        if (!success) {
            // Either proof or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert ProofInvalid();
        }
    }
{{- if .Cfg.Functions }}

{{ .Cfg.Functions }}
{{- end }}
}
`

// MarshalSolidity converts a proof to a byte array that can be used in a
// Solidity contract.
// The proof is encoded as:
//   - Ar (G1): 96 bytes (uncompressed)
//   - Bs (G2): 192 bytes (uncompressed)
//   - Krs (G1): 96 bytes (uncompressed)
//
// Total: 384 bytes without commitments.
// If commitments are present, they are appended as:
//   - Commitments: numCommitments × 96 bytes (G1 points)
//   - CommitmentPok: 96 bytes (G1 point)
func (proof *Proof) MarshalSolidity() []byte {
	var buf bytes.Buffer
	_, err := proof.WriteRawTo(&buf)
	if err != nil {
		panic(err)
	}

	// If there are no commitments, we can return only Ar | Bs | Krs
	if len(proof.Commitments) > 0 {
		return buf.Bytes()
	} else {
		return buf.Bytes()[:8*fp.Bytes]
	}
}
