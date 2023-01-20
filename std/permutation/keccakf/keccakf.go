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
	"github.com/consensys/gnark/frontend"
)

var rc = [24]xuint64{
	constUint64(0x0000000000000001),
	constUint64(0x0000000000008082),
	constUint64(0x800000000000808A),
	constUint64(0x8000000080008000),
	constUint64(0x000000000000808B),
	constUint64(0x0000000080000001),
	constUint64(0x8000000080008081),
	constUint64(0x8000000000008009),
	constUint64(0x000000000000008A),
	constUint64(0x0000000000000088),
	constUint64(0x0000000080008009),
	constUint64(0x000000008000000A),
	constUint64(0x000000008000808B),
	constUint64(0x800000000000008B),
	constUint64(0x8000000000008089),
	constUint64(0x8000000000008003),
	constUint64(0x8000000000008002),
	constUint64(0x8000000000000080),
	constUint64(0x000000000000800A),
	constUint64(0x800000008000000A),
	constUint64(0x8000000080008081),
	constUint64(0x8000000000008080),
	constUint64(0x0000000080000001),
	constUint64(0x8000000080008008),
}
var rotc = [24]int{
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
	27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
}
var piln = [24]int{
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
	15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
}

// Permute applies Keccak-F permutation on the input a and returns the permuted
// vector. The input array must consist of 64-bit (unsigned) integers. The
// returned array also contains 64-bit unsigned integers.
func Permute(api frontend.API, a [25]frontend.Variable) [25]frontend.Variable {
	var in [25]xuint64
	uapi := newUint64API(api)
	for i := range a {
		in[i] = uapi.asUint64(a[i])
	}
	res := permute(api, in)
	var out [25]frontend.Variable
	for i := range out {
		out[i] = uapi.fromUint64(res[i])
	}
	return out
}

func permute(api frontend.API, st [25]xuint64) [25]xuint64 {
	uapi := newUint64API(api)
	var t xuint64
	var bc [5]xuint64
	for r := 0; r < 24; r++ {
		// theta
		for i := 0; i < 5; i++ {
			bc[i] = uapi.xor(st[i], st[i+5], st[i+10], st[i+15], st[i+20])
		}
		for i := 0; i < 5; i++ {
			t = uapi.xor(bc[(i+4)%5], uapi.lrot(bc[(i+1)%5], 1))
			for j := 0; j < 25; j += 5 {
				st[j+i] = uapi.xor(st[j+i], t)
			}
		}
		// rho pi
		t = st[1]
		for i := 0; i < 24; i++ {
			j := piln[i]
			bc[0] = st[j]
			st[j] = uapi.lrot(t, rotc[i])
			t = bc[0]
		}

		// chi
		for j := 0; j < 25; j += 5 {
			for i := 0; i < 5; i++ {
				bc[i] = st[j+i]
			}
			for i := 0; i < 5; i++ {
				st[j+i] = uapi.xor(st[j+i], uapi.and(uapi.not(bc[(i+1)%5]), bc[(i+2)%5]))
			}
		}
		// iota
		st[0] = uapi.xor(st[0], rc[r])
	}
	return st
}
