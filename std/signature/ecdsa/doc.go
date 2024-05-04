// Package ecdsa implements ECDSA signature verification over any elliptic curve.
//
// The package depends on the [emulated/sw_emulated] package for elliptic curve
// group operations using non-native arithmetic. Thus we can verify ECDSA
// signatures over any curve. The cost for a single secp256k1 signature
// verification in a BN254-SNARK is approximately 122k constraints in R1CS and
// 453k constraints in PLONKish.
//
// See [ECDSA] for the signature verification algorithm.
//
// [ECDSA]:
// https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
package ecdsa
