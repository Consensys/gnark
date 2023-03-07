// Package fields_bls12377 implements the fields arithmetic of the Fp12 tower
// used to compute the pairing over the BLS12-377 curve.
//
//	𝔽p²[u] = 𝔽p/u²+5
//	𝔽p⁶[v] = 𝔽p²/v³-u
//	𝔽p¹²[w] = 𝔽p⁶/w²-v
//
// Reference: https://eprint.iacr.org/2022/1162
package fields_bls12377
