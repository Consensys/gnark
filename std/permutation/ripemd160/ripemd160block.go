// Package ripemd160 implements the permutation used in the ripemd160 hash function.
package ripemd160

import (
	"github.com/consensys/gnark/std/math/uints"
)

var rLeft = [80]uint{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
	3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
	1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
	4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
}

var rRight = [80]uint{
	5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
	6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
	15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
	8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
	12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
}

var sLeft = [80]uint{
	11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
	7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
	11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
	11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
	9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
}

var sRight = [80]uint{
	8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
	9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
	9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
	15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
	8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
}

var kLeft = [4]uints.U32(uints.NewU32Array([]uint32{
	0x5a827999,
	0x6ed9eba1,
	0x8f1bbcdc,
	0xa953fd4e,
}))

var kRight = [4]uints.U32(uints.NewU32Array([]uint32{
	0x50a28be6,
	0x5c4dd124,
	0x6d703ef3,
	0x7a6d76e9,
}))

func Permute(uapi *uints.BinaryField[uints.U32], currentHash [5]uints.U32, p [64]uints.U8) (newHash [5]uints.U32) {
	var x [16]uints.U32
	a, b, c, d, e := currentHash[0], currentHash[1], currentHash[2], currentHash[3], currentHash[4]
	aa, bb, cc, dd, ee := a, b, c, d, e
	for i := 0; i < 16; i++ {
		x[i] = uapi.PackLSB(p[4*i], p[4*i+1], p[4*i+2], p[4*i+3])
	}
	for j := 0; j < 80; j++ {
		a, b, c, d, e = round(uapi, j, true, a, b, c, d, e, x, rLeft, sLeft, kLeft)
		aa, bb, cc, dd, ee = round(uapi, j, false, aa, bb, cc, dd, ee, x, rRight, sRight, kRight)
	}
	newHash[0] = uapi.Add(currentHash[1], c, dd)
	newHash[1] = uapi.Add(currentHash[2], d, ee)
	newHash[2] = uapi.Add(currentHash[3], e, aa)
	newHash[3] = uapi.Add(currentHash[4], a, bb)
	newHash[4] = uapi.Add(currentHash[0], b, cc)
	return
}

func f(uapi *uints.BinaryField[uints.U32], j int, x, y, z uints.U32) uints.U32 {
	if j < 16 {
		// x ^ y ^ z
		return uapi.Xor(x, y, z)
	}
	if j < 32 {
		// (x & y) | (~x & z)
		return uapi.Or(uapi.And(x, y), uapi.And(uapi.Not(x), z))
	}
	if j < 48 {
		// (x | ~y) ^ z
		return uapi.Xor(
			uapi.Or(x, uapi.Not(y)),
			z,
		)
	}
	if j < 64 {
		// (x & z) | (y & ~z)
		return uapi.Or(
			uapi.And(x, z),
			uapi.And(y, uapi.Not(z)),
		)
	}
	// x ^ (y | ~z)
	return uapi.Xor(
		x,
		uapi.Or(y, uapi.Not(z)),
	)
}

func round(uapi *uints.BinaryField[uints.U32], j int, isLeft bool, A, B, C, D, E uints.U32, X_i [16]uints.U32, r, s [80]uint, K [4]uints.U32) (AA, BB, CC, DD, EE uints.U32) {
	var tmp1 uints.U32
	jj := j
	jjj := j / 16
	if !isLeft {
		jj = 79 - j
	} else {
		jjj = jjj - 1
	}
	ff := f(uapi, jj, B, C, D)
	if (isLeft && j < 16) || (!isLeft && j >= 64) {
		tmp1 = uapi.Add(
			A,
			ff,
			X_i[r[j]],
		)
	} else {
		tmp1 = uapi.Add(
			A,
			ff,
			X_i[r[j]],
			K[jjj],
		)
	}
	T := uapi.Add(
		uapi.Lrot(tmp1, int(s[j])),
		E,
	)
	AA = E
	BB = T
	CC = B
	DD = uapi.Lrot(C, 10)
	EE = D
	return
}
