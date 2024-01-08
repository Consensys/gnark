package tofield

import (
	"errors"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	block_size = 64
)

// ExpandMsgXmd expands msg to a slice of lenInBytes bytes according to RFC9380 (section 5.3.1)
// Spec: https://datatracker.ietf.org/doc/html/rfc9380#name-expand_message_xmd (hashutils.go)
// Implementation was adapted from gnark-crypto/field/hash.ExpandMsgXmd.
func ExpandMsgXmd(api frontend.API, msg []uints.U8, dst []byte, lenInBytes int) ([]uints.U8, error) {
	h, e := sha2.New(api)
	if e != nil {
		return nil, e
	}

	ell := (lenInBytes + h.Size() - 1) / h.Size() // ceil(len_in_bytes / b_in_bytes)
	if ell > 255 {
		return nil, errors.New("invalid lenInBytes")
	}
	if len(dst) > 255 {
		return nil, errors.New("invalid domain size (>255 bytes)")
	}
	sizeDomain := uint8(len(dst))

	dst_prime := make([]uints.U8, len(dst)+1)
	copy(dst_prime, uints.NewU8Array(dst))
	dst_prime[len(dst)] = uints.NewU8(uint8(sizeDomain))

	Z_pad_raw := make([]uint8, block_size)
	Z_pad := uints.NewU8Array(Z_pad_raw)
	h.Write(Z_pad)
	h.Write(msg)
	h.Write([]uints.U8{uints.NewU8(uint8(lenInBytes >> 8)), uints.NewU8(uint8(lenInBytes)), uints.NewU8(0)})
	h.Write(dst_prime)
	b0 := h.Sum()

	h, e = sha2.New(api)
	if e != nil {
		return nil, e
	}
	h.Write(b0)
	h.Write([]uints.U8{uints.NewU8(1)})
	h.Write(dst_prime)
	b1 := h.Sum()

	res := make([]uints.U8, lenInBytes)
	copy(res[:h.Size()], b1)

	for i := 2; i <= ell; i++ {
		h, e = sha2.New(api)
		if e != nil {
			return nil, e
		}

		// b_i = H(strxor(b₀, b_(i - 1)) ∥ I2OSP(i, 1) ∥ DST_prime)
		strxor := make([]uints.U8, h.Size())
		for j := 0; j < h.Size(); j++ {
			strxor[j], e = xor(api, b0[j], b1[j])
			if e != nil {
				return res, e
			}
		}
		h.Write(strxor)
		h.Write([]uints.U8{uints.NewU8(uint8(i))})
		h.Write(dst_prime)
		b1 = h.Sum()
		copy(res[h.Size()*(i-1):min(h.Size()*i, len(res))], b1)
	}

	return res, nil
}

func xor(api frontend.API, a, b uints.U8) (uints.U8, error) {
	aBits := api.ToBinary(a.Val, 8)
	bBits := api.ToBinary(b.Val, 8)
	cBits := make([]frontend.Variable, 8)

	for i := 0; i < 8; i++ {
		cBits[i] = api.Xor(aBits[i], bBits[i])
	}

	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return uints.NewU8(255), err
	}
	return uapi.ByteValueOf(api.FromBinary(cBits...)), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
