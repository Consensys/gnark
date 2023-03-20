// Package sw_bls12377 implements the arithmetics of G1, G2 and the pairing
// computation on BLS12-377 as a SNARK circuit over BW6-761. These two curves
// form a 2-chain so the operations use native field arithmetic.
//
// References:
// BW6-761: https://eprint.iacr.org/2020/351
// Pairings in R1CS: https://eprint.iacr.org/2022/1162
package sw_bls12377
