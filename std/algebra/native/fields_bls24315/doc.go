// Package fields_bls24315 implements the fields arithmetic of the Fp24 tower
// used to compute the pairing over the BLS24-315 curve.
//
//	𝔽p²[u] = 𝔽p/u²-13
//	𝔽p⁴[v] = 𝔽p²/v²-u
//	𝔽p¹²[w] = 𝔽p⁴/w³-v
//	𝔽p²⁴[i] = 𝔽p¹²/i²-w
//
// Reference: https://eprint.iacr.org/2022/1162
package fields_bls24315
