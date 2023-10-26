package lzss_v1

import (
	"bytes"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/compress"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/icza/bitio"
	"math/big"
)

func bitioWriteLittleE(w *bitio.Writer, r uint64, wordLen, nbBits uint8) {
	for i := uint8(0); i < nbBits; i += wordLen {
		if err := w.WriteBits(r, wordLen); err != nil {
			panic(err)
		}
		r >>= wordLen
	}
}

func bitioReadLittleE(r *bitio.Reader, wordLen, nbBits uint8) uint64 {
	res := uint64(0)

	for i := uint8(0); i < nbBits; i += wordLen {
		n, err := r.ReadBits(wordLen)
		if err != nil {
			panic(err)
		}
		res |= n << i
	}
	return res
}

func CompressedToBytes(c compress.Stream, settings Settings) (_bytes []byte, nbBits int) {
	var bb bytes.Buffer
	wordLen := uint8(settings.WordNbBits())
	w := bitio.NewWriter(&bb)
	write := func(i int, _nbBits uint) {
		bitioWriteLittleE(w, uint64(i), wordLen, uint8(_nbBits))
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

func Pack(c compress.Stream, fieldLen int, settings Settings) []frontend.Variable {
	wordLen := Gcd(8, int(settings.NbBitsAddress), int(settings.NbBitsLength))
	wordPerElem := (fieldLen - 1) / wordLen
	bitPerElem := wordPerElem * wordLen

	_bytes, nbBits := CompressedToBytes(c, settings)

	res := make([]frontend.Variable, (nbBits+bitPerElem-1)/bitPerElem)

	r := bitio.NewReader(bytes.NewReader(_bytes))

	for i := range res {
		toRead := bitPerElem
		if i == len(res)-1 {
			toRead = nbBits % bitPerElem
		}
		res[i] = big.NewInt(int64(bitioReadLittleE(r, uint8(wordLen), uint8(toRead))))
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
	outPerIn := len(outs) / len(ins)
	bitsPerOut := (mod.BitLen() - 1) / outPerIn
	for i := range ins {
		for outInI := 0; outInI < outPerIn; outInI++ {
			for j := 0; j < bitsPerOut; j++ {
				outAbsI := i*outPerIn + outInI
				inJ := outInI*bitsPerOut + j
				if ins[i].Bit(inJ) == 1 {
					outs[outAbsI].SetBit(outs[outAbsI], j, 1)
				} else {
					outs[outAbsI].SetBit(outs[outAbsI], j, 0)
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
			repacked = api.Add(repacked, api.Mul(1<<(j*wordLen), unpacked[i*wordPerElem+j])) // TODO Cache these?
		}
		api.AssertIsEqual(packed[i], repacked)
	}

	return unpacked, nil
}
