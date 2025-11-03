// Package bls implements a subset of the BLS (Boneh-Lynn-Shacham) signature
// scheme.
//
// BLS signature scheme is a pairing-based signature scheme with aggregration.
// It allows to aggregate multiple signatures or multiple public keys into a
// single signature or public key.
//
// This package implements the scheme over the BLS12-381 curve. It currently
// implements the minimal public key size variation, where the public key is a
// single G1 point and the signature is a single G2 point. It uses the SSWU map
// for mapping messages to G2 points.
//
// See [IETF BLS draft] for more details on the BLS signature scheme.
//
// NB! This is experimental and work in progress gadget. The API is not stable
// and will be extended to support minimal-signature variant.
//
// NB! We currently don't have the native implmentation for signing in
// gnark-crypto. See [PR 314].
//
// [IETF draft]:
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature
//
// [PR 314]: https://github.com/Consensys/gnark-crypto/pull/314
package bls
