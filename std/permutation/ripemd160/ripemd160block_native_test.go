package ripemd160

// implementation from golang.org/x/crypto/ripemd160

import (
	"math/bits"
)

const blockSize = 64

// digest represents the partial evaluation of a checksum.
type digest struct {
	s [5]uint32 // running context
}

func blockGeneric(md *digest, p []byte) int {
	n := 0
	var x [16]uint32
	var alpha, beta uint32
	for len(p) >= blockSize {
		a, b, c, d, e := md.s[0], md.s[1], md.s[2], md.s[3], md.s[4]
		aa, bb, cc, dd, ee := a, b, c, d, e
		j := 0
		for i := 0; i < 16; i++ {
			x[i] = uint32(p[j]) | uint32(p[j+1])<<8 | uint32(p[j+2])<<16 | uint32(p[j+3])<<24
			j += 4
		}

		// round 1
		i := 0
		for i < 16 {
			alpha = a + (b ^ c ^ d) + x[_n[i]]
			s := int(_r[i])
			alpha = bits.RotateLeft32(alpha, s) + e
			beta = bits.RotateLeft32(c, 10)
			a, b, c, d, e = e, alpha, b, beta, d

			// parallel line
			alpha = aa + (bb ^ (cc | ^dd)) + x[n_[i]] + 0x50a28be6
			s = int(r_[i])
			alpha = bits.RotateLeft32(alpha, s) + ee
			beta = bits.RotateLeft32(cc, 10)
			aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd

			i++
		}

		// round 2
		for i < 32 {
			alpha = a + (b&c | ^b&d) + x[_n[i]] + 0x5a827999
			s := int(_r[i])
			alpha = bits.RotateLeft32(alpha, s) + e
			beta = bits.RotateLeft32(c, 10)
			a, b, c, d, e = e, alpha, b, beta, d

			// parallel line
			alpha = aa + (bb&dd | cc&^dd) + x[n_[i]] + 0x5c4dd124
			s = int(r_[i])
			alpha = bits.RotateLeft32(alpha, s) + ee
			beta = bits.RotateLeft32(cc, 10)
			aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd

			i++
		}

		// round 3
		for i < 48 {
			alpha = a + (b | ^c ^ d) + x[_n[i]] + 0x6ed9eba1
			s := int(_r[i])
			alpha = bits.RotateLeft32(alpha, s) + e
			beta = bits.RotateLeft32(c, 10)
			a, b, c, d, e = e, alpha, b, beta, d

			// parallel line
			alpha = aa + (bb | ^cc ^ dd) + x[n_[i]] + 0x6d703ef3
			s = int(r_[i])
			alpha = bits.RotateLeft32(alpha, s) + ee
			beta = bits.RotateLeft32(cc, 10)
			aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd

			i++
		}

		// round 4
		for i < 64 {
			alpha = a + (b&d | c&^d) + x[_n[i]] + 0x8f1bbcdc
			s := int(_r[i])
			alpha = bits.RotateLeft32(alpha, s) + e
			beta = bits.RotateLeft32(c, 10)
			a, b, c, d, e = e, alpha, b, beta, d

			// parallel line
			alpha = aa + (bb&cc | ^bb&dd) + x[n_[i]] + 0x7a6d76e9
			s = int(r_[i])
			alpha = bits.RotateLeft32(alpha, s) + ee
			beta = bits.RotateLeft32(cc, 10)
			aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd

			i++
		}

		// round 5
		for i < 80 {
			alpha = a + (b ^ (c | ^d)) + x[_n[i]] + 0xa953fd4e
			s := int(_r[i])
			alpha = bits.RotateLeft32(alpha, s) + e
			beta = bits.RotateLeft32(c, 10)
			a, b, c, d, e = e, alpha, b, beta, d

			// parallel line
			alpha = aa + (bb ^ cc ^ dd) + x[n_[i]]
			s = int(r_[i])
			alpha = bits.RotateLeft32(alpha, s) + ee
			beta = bits.RotateLeft32(cc, 10)
			aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd

			i++
		}

		// combine results
		dd += c + md.s[1]
		md.s[1] = md.s[2] + d + ee
		md.s[2] = md.s[3] + e + aa
		md.s[3] = md.s[4] + a + bb
		md.s[4] = md.s[0] + b + cc
		md.s[0] = dd

		p = p[blockSize:]
		n += blockSize
	}
	return n
}
