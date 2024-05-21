package sha3

import (
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/permutation/keccakf"
)

type digest struct {
	uapi      *uints.BinaryField[uints.U64]
	state     [25]uints.U64 // 1600 bits state: 25 x 64
	in        []uints.U8    // input to be digested
	dsbyte    byte          // dsbyte contains the "domain separation" bits and the first bit of the padding
	rate      int           // the number of bytes of state to use
	outputLen int           // the default output size in bytes
}

func (d *digest) Write(in []uints.U8) {
	d.in = append(d.in, in...)
}

func (d *digest) Size() int { return d.outputLen }

func (d *digest) Reset() {
	d.in = nil
	d.state = newState()
}

func (d *digest) Sum() []uints.U8 {
	padded := d.padding()
	blocks := d.composeBlocks(padded)
	d.absorbing(blocks)
	return d.squeezeBlocks()
}

func (d *digest) padding() []uints.U8 {
	padded := make([]uints.U8, len(d.in))
	copy(padded[:], d.in[:])

	switch q := d.rate - (len(padded) % d.rate); q {
	case 1:
		padded = append(padded, uints.NewU8(d.dsbyte^0x80))
	case 2:
		padded = append(padded, uints.NewU8(d.dsbyte))
		padded = append(padded, uints.NewU8(0x80))
	default:
		padded = append(padded, uints.NewU8(d.dsbyte))
		padded = append(padded, uints.NewU8Array(make([]uint8, q-2))...)
		padded = append(padded, uints.NewU8(0x80))
	}

	return padded
}

func (d *digest) composeBlocks(padded []uints.U8) [][]uints.U64 {
	blocks := make([][]uints.U64, len(padded)/d.rate)

	for i := range blocks {
		block := make([]uints.U64, d.rate/8)
		for j := range block {
			u64 := padded[j*8 : j*8+8]
			block[j] = d.uapi.PackLSB(u64...)
		}
		blocks[i] = block
		padded = padded[d.rate:]
	}

	return blocks
}

func (d *digest) absorbing(blocks [][]uints.U64) {
	for _, block := range blocks {
		for i := range block {
			d.state[i] = d.uapi.Xor(d.state[i], block[i])
		}
		d.state = keccakf.Permute(d.uapi, d.state)
	}
}

func (d *digest) squeezeBlocks() (result []uints.U8) {
	for i := 0; i < d.outputLen/8; i++ {
		result = append(result, d.uapi.UnpackLSB(d.state[i])...)
	}
	return
}

func newState() (state [25]uints.U64) {
	for i := range state {
		state[i] = uints.NewU64(0)
	}
	return
}
