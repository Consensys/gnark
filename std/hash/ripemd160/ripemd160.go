package ripemd160

import (
	"encoding/binary"
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/permutation/ripemd160"
)

var _seed = uints.NewU32Array([]uint32{
	0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
})

type digest struct {
	uapi *uints.BinaryField[uints.U32]
	in   []uints.U8
}

func New(api frontend.API) (hash.BinaryHasher, error) {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return nil, fmt.Errorf("new uapi: %w", err)
	}
	return &digest{uapi: uapi}, nil
}

func (d *digest) Write(data []uints.U8) {
	d.in = append(d.in, data...)
}

func (d *digest) padded(bytesLen int) []uints.U8 {
	zeroPadLen := 55 - bytesLen%64
	if zeroPadLen < 0 {
		zeroPadLen += 64
	}
	if cap(d.in) < len(d.in)+9+zeroPadLen {
		// in case this is the first time this method is called increase the
		// capacity of the slice to fit the padding.
		d.in = append(d.in, make([]uints.U8, 9+zeroPadLen)...)
		d.in = d.in[:len(d.in)-9-zeroPadLen]
	}
	buf := d.in
	buf = append(buf, uints.NewU8(0x80))
	buf = append(buf, uints.NewU8Array(make([]uint8, zeroPadLen))...)
	lenbuf := make([]uint8, 8)
	binary.LittleEndian.PutUint64(lenbuf, uint64(8*bytesLen))
	buf = append(buf, uints.NewU8Array(lenbuf)...)
	return buf
}

func (d *digest) Sum() []uints.U8 {
	var runningDigest [5]uints.U32
	var buf [64]uints.U8
	copy(runningDigest[:], _seed)
	padded := d.padded(len(d.in))
	for i := 0; i < len(padded)/64; i++ {
		copy(buf[:], padded[i*64:(i+1)*64])
		runningDigest = ripemd160.Permute(d.uapi, runningDigest, buf)
	}
	var ret []uints.U8
	for i := range runningDigest {
		ret = append(ret, d.uapi.UnpackLSB(runningDigest[i])...)
	}
	return ret
}

func (d *digest) Reset() {
	d.in = nil
}

func (d *digest) Size() int {
	return 20
}
