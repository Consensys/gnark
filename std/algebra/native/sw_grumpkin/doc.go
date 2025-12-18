// Package sw_grumpkin implements the the Grumpkin curve in-circuit.
//
// Grumpkin curve forms a 2-cycle over BN254 so the operations can use the
// native field arithmetics. Grumpkin curve is not pairing friendly, so it is
// not suitable for pairing based proof system recursion.
//
// References:
// https://aztecprotocol.github.io/aztec-connect/primitives.html/
package sw_grumpkin
