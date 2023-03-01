package keccak

import (
	"github.com/consensys/gnark/frontend"
	keccakf2 "github.com/consensys/gnark/std/permutation/keccakf"
)

const Size = 256 / 8

const BlockSize = 1600/8 - Size*2

// Keccak256 implements hash.Hash
// variable == single byte
type Keccak256 struct {
	a      [25]keccakf2.Xuint64
	buf    [200]keccakf2.Xuint8
	dsbyte keccakf2.Xuint8
	len    int
	size   int
	api    frontend.API
	uapi64 *keccakf2.Uint64api
	uapi8  *keccakf2.Uint8api
}

func (h *Keccak256) Api() frontend.API {
	return h.api
}

func Keccak256Api(api frontend.API, data ...frontend.Variable) (res frontend.Variable) {
	keccak256 := newKeccak256(api)
	keccak256.Reset()
	keccak256.Write(data[:]...)
	keccakBytes := keccak256.Sum(nil)
	var keccakBits []frontend.Variable
	for i := len(keccakBytes) - 1; i >= 0; i-- {
		keccakBits = append(keccakBits, keccakBytes[i][:]...)
	}
	return api.FromBinary(keccakBits[:]...)
}

func newKeccak256(api frontend.API) Keccak256 {
	return Keccak256{
		dsbyte: keccakf2.ConstUint8(0x01),
		size:   256 / 8,
		api:    api,
		uapi64: keccakf2.NewUint64API(api),
		uapi8:  keccakf2.NewUint8API(api),
	}
}

func (h *Keccak256) Size() int      { return h.size }
func (h *Keccak256) BlockSize() int { return BlockSize }

func (h *Keccak256) Reset() {
	h.a = [25]keccakf2.Xuint64{}
	for i := range h.a {
		h.a[i] = keccakf2.ConstUint64(0)
	}
	h.buf = [200]keccakf2.Xuint8{}
	h.len = 0
}

func (h *Keccak256) Write(data ...frontend.Variable) {
	bs := h.BlockSize()

	in := make([]keccakf2.Xuint8, len(data))
	for i := range data {
		in[i] = h.uapi8.AsUint8(data[i])
	}

	for len(in) > 0 {
		n := copy(h.buf[h.len:bs], in)
		h.len += n
		in = in[n:]
		/* for every block Pi in P */
		if h.len == bs {
			h.flush()
		}
	}
}

func (h *Keccak256) flush() {
	b := h.buf[:h.len]
	for i := range h.a {
		if len(b) == 0 {
			break
		}
		pi := h.uapi8.DecodeToXuint64(b)
		/* S[x, y] = S[x, y] ⊕ Pi[x + 5y],   ∀(x, y) such that x + 5y < r/w */
		h.a[i] = h.uapi64.Xor(h.a[i], pi)
		b = b[8:]
	}
	h.a = h.keccakf()
	h.len = 0
}

func (h *Keccak256) keccakf() [25]keccakf2.Xuint64 {
	return keccakf2.Permute(h.api, h.a)
}

func (h *Keccak256) Sum(data ...frontend.Variable) []keccakf2.Xuint8 {
	d := *h
	d.buf[d.len] = keccakf2.ConstUint8(0x01)
	bs := d.BlockSize()
	for i := d.len + 1; i < bs; i++ {
		d.buf[i] = keccakf2.ConstUint8(0x00)
	}
	d.buf[bs-1] = h.uapi8.Or(d.buf[bs-1], keccakf2.ConstUint8(0x80))
	d.len = bs

	d.flush()

	var res []keccakf2.Xuint8
	for i := 0; i < d.size/8; i++ {
		res = h.uapi64.EncodeToXuint8(res, d.a[i])
	}

	return res
}
