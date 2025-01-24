// Package fields_bls12381 implements the fields arithmetic of the direct 𝔽p¹² extension
// used to compute the pairing over the BLS12-381 curve.
//
//	𝔽p¹²[i] = 𝔽p/i¹²-2i⁶+2
//
// This direct tower is isomorphic to the 2-3-2 tower:
//
//	𝔽p²[u] = 𝔽p/u²+1
//	𝔽p⁶[v] = 𝔽p²/v³-1-u
//	𝔽p¹²[w] = 𝔽p⁶/w²-v
package fields_bls12381
