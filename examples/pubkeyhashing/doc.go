// Package pubkeyhashing implements a simple example of ECDSA public key hashing using SHA2.
//
// This example demonstrates how we can verify ECDSA signature in a circuit and
// compare that the hash of the public key matches the expected hash. It also
// illustrates how to minimize the public inputs by packing hash into two
// 16-byte variables to fit into the BN254 field.
package pubkeyhashing
