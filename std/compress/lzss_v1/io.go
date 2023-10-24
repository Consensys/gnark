package lzss_v1

import (
	"bytes"
	"errors"
	"github.com/consensys/gnark-crypto/utils"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/compress"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/icza/bitio"
	"math/big"
)

func CompressedToBytes(c compress.Stream, settings Settings) (_bytes []byte, nbBits int) {
	var bb bytes.Buffer
	w := bitio.NewWriter(&bb)
	write := func(i int, _nbBits uint) {
		if err := w.WriteBits(uint64(i), uint8(_nbBits)); err != nil {
			panic(err)
		}
		nbBits += int(_nbBits)
	}
	for i := 0; i < len(c.D); i++ {
		write(c.D[i], 8)
		if c.D[i] == 0 {
			write(c.D[i+1], settings.NbBitsAddress)
			write(c.D[i+2], settings.NbBitsLength)
			i += 2
		}
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return bb.Bytes(), nbBits
}

func Pack(c compress.Stream, fieldLen int, settings Settings) [][]byte {
	wordLen := Gcd(8, int(settings.NbBitsAddress), int(settings.NbBitsLength))
	wordPerElem := (fieldLen - 1) / wordLen
	bitPerElem := wordPerElem * wordLen

	_bytes, nbBits := CompressedToBytes(c, settings)

	res := make([][]byte, nbBits/bitPerElem)

	r := bitio.NewReader(bytes.NewReader(_bytes))
	elemI := 0
	elemByteI := 0
	for nbBits > 0 {
		toRead := utils.Min(8, bitPerElem-elemByteI*8)
		if b, err := r.ReadBits(uint8(toRead)); err != nil {
			panic(err)
		} else {
			res[elemI][elemByteI] = byte(b)
		}
		if elemByteI*8+toRead == bitPerElem {
			elemI++
			elemByteI = 0
		} else {
			elemByteI++
		}
	}
	return res
}

func Gcd(a ...int) int {
	if len(a) == 0 {
		return -1
	}

	for len(a) > 1 {
		if a[1] < a[0] {
			a[0], a[1] = a[1], a[0]
		}
		for a[0] != 0 {
			a[1], a[0] = a[0], a[1]%a[0]
		}
		a = a[1:]
	}

	return a[0]
}

func Decompose(mod *big.Int, ins, outs []*big.Int) error {
	if len(ins) != 1 {
		return errors.New("decompose only works on one variable")
	}
	outPerIn := len(outs) / len(ins)
	bitsPerOut := (mod.BitLen() - 1) / outPerIn
	for i := range ins {
		for outInI := 0; outInI < outPerIn; outInI++ {
			for j := 0; j < bitsPerOut; j++ {
				if ins[i].Bit(j) == 1 {
					outs[i*outPerIn+outInI].SetBit(outs[i*outPerIn+outInI], j, 1)
				} else {
					outs[i*outPerIn+outInI].SetBit(outs[i*outPerIn+outInI], j, 0)
				}
			}
		}
	}
	return nil
}

func Unpack(api frontend.API, packed []frontend.Variable, settings Settings) ([]frontend.Variable, error) {
	wordLen := Gcd(8, int(settings.NbBitsAddress), int(settings.NbBitsLength))
	wordPerElem := (api.Compiler().FieldBitLen() - 1) / wordLen

	unpacked, err := api.Compiler().NewHint(Decompose, len(packed)*wordPerElem, packed...)
	if err != nil {
		return nil, err
	}

	// verify correctness of decompositions

	table := logderivlookup.New(api)
	for i := 0; i < 1<<wordLen; i++ {
		table.Insert(0)
	}
	_ = table.Lookup(unpacked...)

	for i := range packed {
		repacked := frontend.Variable(0)
		for j := 0; j < wordPerElem; j++ {
			repacked = api.Add(repacked, api.Mul(1<<(j*wordLen), unpacked[i*wordPerElem+j]))
		}
		api.AssertIsEqual(packed[i], repacked)
	}

	return unpacked, nil
}
