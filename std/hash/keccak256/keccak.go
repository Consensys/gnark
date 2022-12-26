package keccak

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	keccakf2 "github.com/consensys/gnark/std/permutation/keccakf"
)

const Size = 256 / 8

const BlockSize = 1600/8 - Size*2

// Keccak256 implements hash.Hash
type Keccak256 struct {
	a      [25]keccakf2.Xuint64
	buf    [200]keccakf2.Xuint64
	dsbyte keccakf2.Xuint64
	len    int
	size   int
	uapi   keccakf2.Uint64api
	api    frontend.API
}

func (h *Keccak256) Api() frontend.API {
	return h.api
}

func newKeccak256() *Keccak256 {
	return &Keccak256{
		size:   256 / 8,
		dsbyte: keccakf2.ConstUint64(0x0000000000000001),
	}
}

func (h *Keccak256) Size() int      { return h.size }
func (h *Keccak256) BlockSize() int { return BlockSize }

func (h *Keccak256) Reset() {
	h.a = [25]keccakf2.Xuint64{}
	h.buf = [200]keccakf2.Xuint64{}
	h.len = 0
}

func (h *Keccak256) Write(data ...frontend.Variable) {
	bs := h.BlockSize()

	var in []keccakf2.Xuint64
	for i := range data {
		in[i] = h.uapi.AsUint64(data[i])
	}

	for len(data) > 0 {
		n := copy(h.buf[h.len:bs], in)
		h.len += n
		data = data[n:]
		/* for every block Pi in P */
		if h.len == bs {
			h.flush(in)
		}
	}
}

func (h *Keccak256) flush(b []keccakf2.Xuint64) {
	b = h.buf[:h.len]
	uapi := keccakf2.NewUint64API(h.api)
	for i := range h.a {
		if len(b) == 0 {
			break
		}
		/* S[x, y] = S[x, y] ⊕ Pi[x + 5y],   ∀(x, y) such that x + 5y < r/w */
		h.a[i] = uapi.Xor(uapi.AsUint64(h.a[i]), h.le64dec(b))
		b = b[8:]
	}
	keccakf(&h.a, &h)
	h.len = 0
}

func keccakf(a *[25]keccakf2.Xuint64, d **Keccak256) {
	keccakf2.Permute((*d).api, a)
}

func (h *Keccak256) Sum(data ...frontend.Variable) []frontend.Variable {
	d := *h
	d.buf[d.len] = d.dsbyte
	bs := d.BlockSize()
	for i := d.len + 1; i < bs; i++ {
		d.buf[i] = keccakf2.ConstUint64(0)
	}
	uapi := keccakf2.NewUint64API(h.api)
	uapi.And(d.buf[bs-1], keccakf2.ConstUint64(0x80))
	d.len = bs

	d.flush(d.buf[:])

	for i := 0; i < d.size/8; i++ {
		data = h.le64enc(data, d.a[i])
	}
	return data
}

func (h *Keccak256) le64dec(b []keccakf2.Xuint64) keccakf2.Xuint64 {
	return h.uapi.AsUint64FromBytes(b[0:8])
}

func (h *Keccak256) le64enc(b []frontend.Variable, x keccakf2.Xuint64) []frontend.Variable {
	return append(b, bits.ToBinary(h.api, x, bits.WithNbDigits(64)))
}
