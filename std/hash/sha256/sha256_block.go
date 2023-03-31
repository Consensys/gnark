package sha256

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/permutation/keccakf"
)

type Sha256 struct {
	api    frontend.API
	uapi64 *keccakf.Uint64api
	uapi32 *keccakf.Uint32api
	uapi8  *keccakf.Uint8api
}

func newSha256(api frontend.API) Sha256 {
	return Sha256{
		api:    api,
		uapi8:  keccakf.NewUint8API(api),
		uapi32: keccakf.NewUint32API(api),
		uapi64: keccakf.NewUint64API(api),
	}
}

var _K = [64]frontend.Variable{
	frontend.Variable(0x428a2f98), frontend.Variable(0x71374491), frontend.Variable(0xb5c0fbcf), frontend.Variable(0xe9b5dba5), frontend.Variable(0x3956c25b), frontend.Variable(0x59f111f1), frontend.Variable(0x923f82a4), frontend.Variable(0xab1c5ed5),
	frontend.Variable(0xd807aa98), frontend.Variable(0x12835b01), frontend.Variable(0x243185be), frontend.Variable(0x550c7dc3), frontend.Variable(0x72be5d74), frontend.Variable(0x80deb1fe), frontend.Variable(0x9bdc06a7), frontend.Variable(0xc19bf174),
	frontend.Variable(0xe49b69c1), frontend.Variable(0xefbe4786), frontend.Variable(0x0fc19dc6), frontend.Variable(0x240ca1cc), frontend.Variable(0x2de92c6f), frontend.Variable(0x4a7484aa), frontend.Variable(0x5cb0a9dc), frontend.Variable(0x76f988da),
	frontend.Variable(0x983e5152), frontend.Variable(0xa831c66d), frontend.Variable(0xb00327c8), frontend.Variable(0xbf597fc7), frontend.Variable(0xc6e00bf3), frontend.Variable(0xd5a79147), frontend.Variable(0x06ca6351), frontend.Variable(0x14292967),
	frontend.Variable(0x27b70a85), frontend.Variable(0x2e1b2138), frontend.Variable(0x4d2c6dfc), frontend.Variable(0x53380d13), frontend.Variable(0x650a7354), frontend.Variable(0x766a0abb), frontend.Variable(0x81c2c92e), frontend.Variable(0x92722c85),
	frontend.Variable(0xa2bfe8a1), frontend.Variable(0xa81a664b), frontend.Variable(0xc24b8b70), frontend.Variable(0xc76c51a3), frontend.Variable(0xd192e819), frontend.Variable(0xd6990624), frontend.Variable(0xf40e3585), frontend.Variable(0x106aa070),
	frontend.Variable(0x19a4c116), frontend.Variable(0x1e376c08), frontend.Variable(0x2748774c), frontend.Variable(0x34b0bcb5), frontend.Variable(0x391c0cb3), frontend.Variable(0x4ed8aa4a), frontend.Variable(0x5b9cca4f), frontend.Variable(0x682e6ff3),
	frontend.Variable(0x748f82ee), frontend.Variable(0x78a5636f), frontend.Variable(0x84c87814), frontend.Variable(0x8cc70208), frontend.Variable(0x90befffa), frontend.Variable(0xa4506ceb), frontend.Variable(0xbef9a3f7), frontend.Variable(0xc67178f2)}

func blockGeneric(dig *Digest, data ...keccakf.Xuint8) {
	sha := newSha256(dig.api)
	uapi8 := sha.uapi8
	uapi32 := sha.uapi32
	gnark := sha.api

	h0, h1, h2, h3, h4, h5, h6, h7 := dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4], dig.h[5], dig.h[6], dig.h[7]

	for len(data) >= chunk {
		var w []keccakf.Xuint32
		for i := 0; i < 16; i++ {
			chunk32 := []keccakf.Xuint8{data[i*4], data[i*4+1], data[i*4+2], data[i*4+3]}
			w = append(w, uapi8.DecodeToXuint32BigEndian(chunk32))
		}
		w = append(w, make([]keccakf.Xuint32, 48)...)
		for i := 16; i < 64; i++ {
			w[i] = keccakf.ConstUint32(0)
		}

		for i := 16; i < 64; i++ {
			// s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
			s0 := uapi32.Xor(sha.rightRotate(w[i-15], 7), sha.rightRotate(w[i-15], 18), sha.rightShift(w[i-15], 3))

			// s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
			s1 := uapi32.Xor(sha.rightRotate(w[i-2], 17), sha.rightRotate(w[i-2], 19), sha.rightShift(w[i-2], 10))

			sum1 := gnark.Add(uapi32.FromUint32(w[i-16]), uapi32.FromUint32(s0))
			sum2 := gnark.Add(uapi32.FromUint32(w[i-7]), uapi32.FromUint32(s1))

			// w[i] := w[i-16] + s0 + w[i-7] + s1
			w[i] = sha.trimBitsToXuint32(gnark.Add(sum1, sum2), 34)
		}

		a := h0
		b := h1
		c := h2
		d := h3
		e := h4
		f := h5
		g := h6
		h := h7

		var tempMaj1, tempMaj2 keccakf.Xuint32
		for i := 0; i < 64; i++ {
			// S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
			S1 := uapi32.Xor(sha.rightRotate(e, 6), sha.rightRotate(e, 11), sha.rightRotate(e, 25))

			// ch := (e and f) xor ((not e) and g)
			//ch := uapi32.Xor(uapi32.And(e, f), uapi32.And(uapi32.Not(e), g))
			ch := sha.computeCh(e, f, g)

			sum1 := gnark.Add(uapi32.FromUint32(h), uapi32.FromUint32(S1))
			sum2 := gnark.Add(uapi32.FromUint32(ch), _K[i])
			sum3 := gnark.Add(sum2, uapi32.FromUint32(w[i]))

			// temp1 := h + S1 + ch + k[i] + w[i]
			temp1 := gnark.Add(sum1, sum3)

			// S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
			S0 := uapi32.Xor(sha.rightRotate(a, 2), sha.rightRotate(a, 13), sha.rightRotate(a, 22))

			var maj keccakf.Xuint32
			if i%2 == 1 {
				maj = sha.computeMaj(c, b, a, &tempMaj1, &tempMaj2, true)
			} else {
				maj = sha.computeMaj(a, b, c, &tempMaj1, &tempMaj2, false)
			}

			// t2 computation
			temp2 := gnark.Add(uapi32.FromUint32(S0), uapi32.FromUint32(maj))

			/*
			   h := g
			   g := f
			   f := e
			   e := d + temp1
			   d := c
			   c := b
			   b := a
			   a := temp1 + temp2
			*/
			h = g
			g = f
			f = e
			e = sha.trimBitsToXuint32(gnark.Add(uapi32.FromUint32(d), temp1), 35)
			d = c
			c = b
			b = a
			a = sha.trimBitsToXuint32(gnark.Add(temp1, temp2), 35)
		}

		/*
		   Add the compressed chunk to the current hash value:
		   h0 := h0 + a
		   h1 := h1 + b
		   h2 := h2 + c
		   h3 := h3 + d
		   h4 := h4 + e
		   h5 := h5 + f
		   h6 := h6 + g
		   h7 := h7 + h
		*/
		h0 = sha.trimBitsToXuint32(gnark.Add(uapi32.FromUint32(h0), uapi32.FromUint32(a)), 33)
		h1 = sha.trimBitsToXuint32(gnark.Add(uapi32.FromUint32(h1), uapi32.FromUint32(b)), 33)
		h2 = sha.trimBitsToXuint32(gnark.Add(uapi32.FromUint32(h2), uapi32.FromUint32(c)), 33)
		h3 = sha.trimBitsToXuint32(gnark.Add(uapi32.FromUint32(h3), uapi32.FromUint32(d)), 33)
		h4 = sha.trimBitsToXuint32(gnark.Add(uapi32.FromUint32(h4), uapi32.FromUint32(e)), 33)
		h5 = sha.trimBitsToXuint32(gnark.Add(uapi32.FromUint32(h5), uapi32.FromUint32(f)), 33)
		h6 = sha.trimBitsToXuint32(gnark.Add(uapi32.FromUint32(h6), uapi32.FromUint32(g)), 33)
		h7 = sha.trimBitsToXuint32(gnark.Add(uapi32.FromUint32(h7), uapi32.FromUint32(h)), 33)

		data = data[chunk:]
	}

	dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4], dig.h[5], dig.h[6], dig.h[7] = h0, h1, h2, h3, h4, h5, h6, h7
}

func (h *Sha256) rightRotate(n keccakf.Xuint32, shift int) keccakf.Xuint32 {
	return h.uapi32.Rrot(n, shift)
}

func (h *Sha256) computeMaj(a, b, c keccakf.Xuint32, tempMaj1, tempMaj2 *keccakf.Xuint32, useLazy bool) keccakf.Xuint32 {
	var res keccakf.Xuint32
	for i := range res {
		if useLazy {
			res[i] = h.api.Add(tempMaj1[i], h.api.Mul(tempMaj2[i], c[i]))
		} else {
			tempMaj1[i] = h.api.Mul(a[i], b[i])
			tempMaj2[i] = h.api.Add(a[i], b[i], h.api.Mul(tempMaj1[i], -2))
			res[i] = h.api.Add(tempMaj1[i], h.api.Mul(tempMaj2[i], c[i]))
		}
	}
	return res
}

func (h *Sha256) computeCh(e, f, g keccakf.Xuint32) keccakf.Xuint32 {
	var res keccakf.Xuint32
	for i := range res {
		res[i] = h.api.Select(e[i], f[i], g[i])
	}
	return res
}

func (h *Sha256) rightShift(n keccakf.Xuint32, shift int) keccakf.Xuint32 {
	return h.uapi32.Rshift(n, shift)
}

// https://github.com/akosba/jsnark/blob/master/JsnarkCircuitBuilder/src/examples/gadgets/hash/SHA256Gadget.java
func (h *Sha256) trimBitsToXuint32(a frontend.Variable, size int) keccakf.Xuint32 {
	requiredSize := 32
	aBits := h.api.ToBinary(a, size)
	x := make([]frontend.Variable, requiredSize)

	for i := requiredSize; i < size; i++ {
		aBits[i] = 0
	}
	for i := 0; i < requiredSize; i++ {
		x[i] = aBits[i]
	}

	res := keccakf.Xuint32{}
	copy(res[:], x[:])
	return res
}
