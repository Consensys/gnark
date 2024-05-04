// Package eddsa implements EdDSA signature verification over twisted Edwards
// elliptic curves available in gnark and gnark-crypto. These are the so-called
// "embedded curves" (e.g. Baby-Jubjub, Bandersnatch...) defined over the scalar
// field of the pairing-friendly SNARK curves (e.g. BN254, BLS12-381...)
//
// The package depends on the [native/twistededwards] package for elliptic
// curve group operations in twisted Edwards form using native arithmetic. The
// cost for a single baby-jubjub signature verification in a BN254-SNARK is
// approximately 7k constraints in R1CS and 11k constraints in PLONKish.
//
// See [EdDSA] for the signature verification algorithm.
//
// [EdDSA]:
// https://en.wikipedia.org/wiki/EdDSA
package eddsa
