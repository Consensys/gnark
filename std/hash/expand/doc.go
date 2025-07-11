// Package expand implements message expansion according to RFC9380.
//
// This package implements the expand_message_xmd function from [RFC9380]
// Section 5.3.1. The package uses hard-coded hash function SHA2-256.
//
// Please open issue in [gnark repository] in case there is a need for using
// other hash functions beyond SHA2-256 or expand_message_xof using
// extendable-output function (SHAKE3 family etc.). We currently have
// implemented only specific instance for compatibility with gnark-crypto, which
// is available at [github.com/consensys/gnark-crypto/field/hash].
//
// [RFC9380]: https://datatracker.ietf.org/doc/html/rfc9380#name-expand_message_xmd
// [gnark repository]: https://github.com/consensys/gnark
// [github.com/consensys/gnark-crypto/field/hash]: https://pkg.go.dev/github.com/consensys/gnark-crypto@master/field/hash
package expand
