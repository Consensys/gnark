// Package keccakf implements the KeccakF-1600 permutation function.
//
// This package exposes only the permutation primitive. For SHA3, SHAKE3 etc.
// functions it is necessary to apply the sponge construction. The constructions
// will be implemented in future in [github.com/consensys/gnark/std/hash/sha3]
// package.
//
// The cost for a single application of permutation is:
//   - 193650 constraints in Groth16
//   - 292032 constraints in Plonk
package keccakf

import (
	"github.com/consensys/gnark/std/math/uints"
)

var rc = [24]uints.U64{
	uints.NewU64(0x0000000000000001),
	uints.NewU64(0x0000000000008082),
	uints.NewU64(0x800000000000808A),
	uints.NewU64(0x8000000080008000),
	uints.NewU64(0x000000000000808B),
	uints.NewU64(0x0000000080000001),
	uints.NewU64(0x8000000080008081),
	uints.NewU64(0x8000000000008009),
	uints.NewU64(0x000000000000008A),
	uints.NewU64(0x0000000000000088),
	uints.NewU64(0x0000000080008009),
	uints.NewU64(0x000000008000000A),
	uints.NewU64(0x000000008000808B),
	uints.NewU64(0x800000000000008B),
	uints.NewU64(0x8000000000008089),
	uints.NewU64(0x8000000000008003),
	uints.NewU64(0x8000000000008002),
	uints.NewU64(0x8000000000000080),
	uints.NewU64(0x000000000000800A),
	uints.NewU64(0x800000008000000A),
	uints.NewU64(0x8000000080008081),
	uints.NewU64(0x8000000000008080),
	uints.NewU64(0x0000000080000001),
	uints.NewU64(0x8000000080008008),
}
var rotc = [24]int{
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
	27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
}
var piln = [24]int{
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
	15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
}

// Permute applies Keccak-F permutation on the input and returns the permuted vector.
// Original input is not modified.
func Permute(uapi *uints.BinaryField[uints.U64], input [25]uints.U64) [25]uints.U64 {
	var state [25]uints.U64
	copy(state[:], input[:])
	return permute(uapi, state)
}

func permute(uapi *uints.BinaryField[uints.U64], st [25]uints.U64) [25]uints.U64 {
	var t uints.U64
	var bc [5]uints.U64
	for r := 0; r < 24; r++ {
		// theta
		for i := 0; i < 5; i++ {
			bc[i] = uapi.Xor(st[i], st[i+5], st[i+10], st[i+15], st[i+20])
		}
		for i := 0; i < 5; i++ {
			t = uapi.Xor(bc[(i+4)%5], uapi.Lrot(bc[(i+1)%5], 1))
			for j := 0; j < 25; j += 5 {
				st[j+i] = uapi.Xor(st[j+i], t)
			}
		}
		// rho pi
		t = st[1]
		for i := 0; i < 24; i++ {
			j := piln[i]
			bc[0] = st[j]
			st[j] = uapi.Lrot(t, rotc[i])
			t = bc[0]
		}

		// chi
		for j := 0; j < 25; j += 5 {
			for i := 0; i < 5; i++ {
				bc[i] = st[j+i]
			}
			for i := 0; i < 5; i++ {
				st[j+i] = uapi.Xor(st[j+i], uapi.And(uapi.Not(bc[(i+1)%5]), bc[(i+2)%5]))
			}
		}
		// iota
		st[0] = uapi.Xor(st[0], rc[r])
	}
	return st
}
