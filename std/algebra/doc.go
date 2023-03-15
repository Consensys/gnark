// Package algebra implements:
//   - base finite field 𝔽p arithmetic,
//   - extension finite fields arithmetic (𝔽p², 𝔽p⁴, 𝔽p⁶, 𝔽p¹², 𝔽p²⁴),
//   - short Weierstrass curve arithmetic over G1 (E/𝔽p) and G2 (Eₜ/𝔽p² or Eₜ/𝔽p⁴)
//   - twisted Edwards curve arithmetic
//
// These arithmetic operations are implemented
//   - using native field via the 2-chains BLS12-377/BW6-761 and BLS24-315/BW-633
//     (`native/`) or associated twisted Edwards (e.g. Jubjub/BLS12-381) and
//   - using nonnative field via field emulation (`emulated/`). This allows to
//     use any curve over any (SNARK) field (e.g. secp256k1 curve arithmetic over
//     BN254 SNARK field or BN254 pairing over BN254 SNARK field).  The drawback
//     of this approach is the extreme cost of the operations.
package algebra
