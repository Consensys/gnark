/*
Copyright © 2023 Jan Lauinger

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sha256

import (
	"github.com/consensys/gnark/frontend"
)

type SHA256 struct {
	api frontend.API
}

// retuns SHA256 instance which can be used inside a circuit
func NewSHA256(api frontend.API) SHA256 {
	return SHA256{api: api}
}

func (sha *SHA256) Hash(preimage []frontend.Variable) [32]frontend.Variable {

	// K values
	var K = [64]frontend.Variable{0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2}

	// H values
	var H [8]frontend.Variable
	H[0] = frontend.Variable(0x6A09E667)
	H[1] = frontend.Variable(0xBB67AE85)
	H[2] = frontend.Variable(0x3C6EF372)
	H[3] = frontend.Variable(0xA54FF53A)
	H[4] = frontend.Variable(0x510E527F)
	H[5] = frontend.Variable(0x9B05688C)
	H[6] = frontend.Variable(0x1F83D9AB)
	H[7] = frontend.Variable(0x5BE0CD19)

	// padding
	paddedInput := padding(sha.api, preimage)

	// chunk processing of padded input
	numberChunks := int(len(paddedInput) / 64)
	for epoch := 0; epoch < numberChunks; epoch++ {

		eIndex := epoch * 64

		// w values init
		var w [64]frontend.Variable

		// first 16 w values is set based on input data
		for i := 0; i < 16; i++ {

			j := i * 4

			// same as in go except that | is replaced with api.Add for multi-bit operation
			leftShift24 := shiftLeft(sha.api, paddedInput[eIndex+j], 24)
			leftShift16 := shiftLeft(sha.api, paddedInput[eIndex+j+1], 16)
			leftShift8 := shiftLeft(sha.api, paddedInput[eIndex+j+2], 8)
			leftShiftNone := sha.api.FromBinary(sha.api.ToBinary(paddedInput[eIndex+j+3], 32)...)
			w[i] = trimBits(sha.api, sha.api.Add(sha.api.Add(sha.api.Add(leftShift24, leftShift16), leftShift8), leftShiftNone), 34)
		}

		// remaining w values computation
		for i := 16; i < 64; i++ {

			// t1 := (bits.RotateLeft32(v1, -17)) ^ (bits.RotateLeft32(v1, -19)) ^ (v1 >> 10)
			v1 := w[i-2]

			rotateRight17 := rotateRight(sha.api, v1, 17)
			rotateRight19 := rotateRight(sha.api, v1, 19)
			rightShift10 := shiftRight(sha.api, v1, 10)
			// t1Slice := sha.api.ToBinary(0, 32)
			t1Slice := make([]frontend.Variable, 32)
			for l := 0; l < 32; l++ {
				t1Slice[l] = sha.api.Xor(sha.api.Xor(rotateRight17[l], rotateRight19[l]), rightShift10[l])
			}
			t1 := sha.api.FromBinary(t1Slice...)

			// t2 := (bits.RotateLeft32(v2, -7)) ^ (bits.RotateLeft32(v2, -18)) ^ (v2 >> 3)
			v2 := w[i-15]
			rotateRight7 := rotateRight(sha.api, v2, 7)
			rotateRight18 := rotateRight(sha.api, v2, 18)
			rightShift3 := shiftRight(sha.api, v2, 3) // api.Div(v1, 3)
			// t2Slice := sha.api.ToBinary(0, 32)
			t2Slice := make([]frontend.Variable, 32)
			for l := 0; l < 32; l++ {
				t2Slice[l] = sha.api.Xor(sha.api.Xor(rotateRight7[l], rotateRight18[l]), rightShift3[l])
			}
			t2 := sha.api.FromBinary(t2Slice...)

			w7 := w[i-7]
			w16 := w[i-16]
			w[i] = trimBits(sha.api, sha.api.Add(sha.api.Add(sha.api.Add(t1, w7), t2), w16), 34) // addition mod 2^32 ==> cut number to 32 bit
		}

		// a to h values
		var a frontend.Variable
		var b frontend.Variable
		var c frontend.Variable
		var d frontend.Variable
		var e frontend.Variable
		var f frontend.Variable
		var g frontend.Variable
		var h frontend.Variable

		a = H[0]
		b = H[1]
		c = H[2]
		d = H[3]
		e = H[4]
		f = H[5]
		g = H[6]
		h = H[7]

		// computation of alphabet values
		for i := 0; i < 64; i++ {

			// ^e is a not
			// t1 := h + ((bits.RotateLeft32(e, -6)) ^ (bits.RotateLeft32(e, -11)) ^ (bits.RotateLeft32(e, -25))) + ((e & f) ^ (^e & g)) + _K[i] + w[i]
			rotateRight6 := rotateRight(sha.api, e, 6)
			rotateRight11 := rotateRight(sha.api, e, 11)
			rotateRight25 := rotateRight(sha.api, e, 25)
			tmp1Slice := sha.api.ToBinary(0, 32)
			for k := 0; k < 32; k++ {
				tmp1Slice[k] = sha.api.Xor(sha.api.Xor(rotateRight6[k], rotateRight11[k]), rotateRight25[k])
			}
			tmp1 := sha.api.FromBinary(tmp1Slice...)

			tmp2Slice := sha.api.ToBinary(0, 32)
			eBits := sha.api.ToBinary(e, 32)
			fBits := sha.api.ToBinary(f, 32)
			gBits := sha.api.ToBinary(g, 32)
			for k := 0; k < 32; k++ {
				tmp2Slice[k] = sha.api.Xor(sha.api.And(eBits[k], fBits[k]), sha.api.And(sha.api.Xor(eBits[k], frontend.Variable(1)), gBits[k]))
			}
			tmp2 := sha.api.FromBinary(tmp2Slice...)

			// t1 computation
			t1 := sha.api.Add(sha.api.Add(sha.api.Add(sha.api.Add(h, tmp1), tmp2), K[i]), w[i])

			// t2 := ((bits.RotateLeft32(a, -2)) ^ (bits.RotateLeft32(a, -13)) ^ (bits.RotateLeft32(a, -22))) + ((a & b) ^ (a & c) ^ (b & c))
			rotateRight2 := rotateRight(sha.api, a, 2)
			rotateRight13 := rotateRight(sha.api, a, 13)
			rotateRight22 := rotateRight(sha.api, a, 22)
			tmp3Slice := sha.api.ToBinary(0, 32)
			for l := 0; l < 32; l++ {
				tmp3Slice[l] = sha.api.Xor(sha.api.Xor(rotateRight2[l], rotateRight13[l]), rotateRight22[l])
			}
			tmp3 := sha.api.FromBinary(tmp3Slice...)

			aBits := sha.api.ToBinary(a, 32)
			bBits := sha.api.ToBinary(b, 32)
			cBits := sha.api.ToBinary(c, 32)
			tmp4Slice := sha.api.ToBinary(0, 32)
			for l := 0; l < 32; l++ {
				tmp4Slice[l] = sha.api.Xor(sha.api.Xor(sha.api.And(aBits[l], bBits[l]), sha.api.And(aBits[l], cBits[l])), sha.api.And(bBits[l], cBits[l]))
			}
			tmp4 := sha.api.FromBinary(tmp4Slice...)

			// t2 computation
			t2 := sha.api.Add(tmp3, tmp4)

			h = g
			g = f
			f = e
			e = trimBits(sha.api, sha.api.Add(t1, d), 35)
			d = c
			c = b
			b = a
			a = trimBits(sha.api, sha.api.Add(t1, t2), 35)
		}

		// updating H values
		H[0] = trimBits(sha.api, sha.api.Add(H[0], a), 33)
		H[1] = trimBits(sha.api, sha.api.Add(H[1], b), 33)
		H[2] = trimBits(sha.api, sha.api.Add(H[2], c), 33)
		H[3] = trimBits(sha.api, sha.api.Add(H[3], d), 33)
		H[4] = trimBits(sha.api, sha.api.Add(H[4], e), 33)
		H[5] = trimBits(sha.api, sha.api.Add(H[5], f), 33)
		H[6] = trimBits(sha.api, sha.api.Add(H[6], g), 33)
		H[7] = trimBits(sha.api, sha.api.Add(H[7], h), 33)

	}

	// reorder bits
	var out [32]frontend.Variable
	ctr := 0
	for i := 0; i < 8; i++ {
		bits := sha.api.ToBinary(H[i], 32)
		for j := 3; j >= 0; j-- {
			start := 8 * j
			// little endian order chunk parsing from back to front
			out[ctr] = sha.api.FromBinary(bits[start : start+8]...)
			ctr += 1
		}
	}

	return out

}

func trimBits(api frontend.API, a frontend.Variable, size int) frontend.Variable {

	requiredSize := 32
	aBits := api.ToBinary(a, size)
	x := make([]frontend.Variable, requiredSize)

	for i := requiredSize; i < size; i++ {
		aBits[i] = 0
	}
	for i := 0; i < requiredSize; i++ {
		x[i] = aBits[i]
	}

	return api.FromBinary(x...)
}

func shiftRight(api frontend.API, a frontend.Variable, shift int) []frontend.Variable {

	bits := api.ToBinary(a, 32)
	// x := api.ToBinary(0, 32)
	x := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		if i >= 32-shift {
			x[i] = 0
		} else {
			x[i] = bits[i+shift]
		}
	}
	return x
}

func shiftLeft(api frontend.API, a frontend.Variable, shift int) frontend.Variable {

	bits := api.ToBinary(a, 32)
	// x := api.ToBinary(0, 32)
	x := make([]frontend.Variable, 32)

	for i := 0; i < 32; i++ {
		if i >= shift {
			x[i] = bits[i-shift]
		} else {
			x[i] = 0
		}
	}

	return api.FromBinary(x...)
}

func rotateRight(api frontend.API, a frontend.Variable, rotation int) []frontend.Variable {

	bits := api.ToBinary(a, 32)
	// x := api.ToBinary(0, 32)
	x := make([]frontend.Variable, 32)
	split := 32 - rotation

	for i := 0; i < 32; i++ {
		if i >= split {
			x[i] = bits[i-split]
		} else {
			x[i] = bits[i+rotation]
		}
	}

	return x
}

func variableXor(api frontend.API, a frontend.Variable, b frontend.Variable, size int) frontend.Variable {
	bitsA := api.ToBinary(a, size)
	bitsB := api.ToBinary(b, size)
	x := make([]frontend.Variable, size)
	for i := 0; i < size; i++ {
		x[i] = api.Xor(bitsA[i], bitsB[i])
	}
	return api.FromBinary(x...)
}

func padding(api frontend.API, a []frontend.Variable) []frontend.Variable {

	// helpers
	inputLen := len(a)
	paddingLen := inputLen % 64

	// t is start index of intputBitLen encoding
	var t int
	if inputLen%64 < 56 {
		t = 56 - inputLen%64
	} else {
		t = 64 + 56 - inputLen%64
	}

	// total length of padded input
	totalLen := inputLen + t + 8

	// encode every byte in frontend.Variable
	out := make([]frontend.Variable, totalLen)

	// return if no padding required
	if paddingLen == 0 {

		// overwrite into fixed size slice
		for i := 0; i < inputLen; i++ {
			out[i] = a[i]
		}
		return out
	}

	// existing bytes into out
	for i := 0; i < inputLen; i++ {
		out[i] = a[i]
	}

	// padding, first byte is always a 128=2^7=10000000
	out[inputLen] = frontend.Variable(128)

	// zero padding
	for i := 0; i < t; i++ {
		out[inputLen+1+i] = frontend.Variable(0)
	}

	// bit size of number of input bytes
	inputBitLen := inputLen << 3

	// fill last 8 byte in reverse because of little endian
	bits := api.ToBinary(inputBitLen, 64) // 64 bit = 8 byte
	ctr := inputLen + t
	for i := 7; i >= 0; i-- {
		start := i * 8
		out[ctr] = api.FromBinary(bits[start : start+8]...)
		ctr += 1
	}

	return out
}
