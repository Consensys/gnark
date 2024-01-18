package compress

import (
	"errors"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/compress/internal/plonk_helpers"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"hash"
	"math/big"
)

// Pack packs the words as tightly as possible, and works Big Endian: i.e. the first word is the most significant in the packed elem
func Pack(api frontend.API, words []frontend.Variable, bitsPerWord int) []frontend.Variable {
	return PackN(api, words, bitsPerWord, (api.Compiler().FieldBitLen()-1)/bitsPerWord)
}

func PackN(api frontend.API, words []frontend.Variable, bitsPerWord, wordsPerElem int) []frontend.Variable {
	res := make([]frontend.Variable, (len(words)+wordsPerElem-1)/wordsPerElem)

	r := make([]big.Int, wordsPerElem)
	r[wordsPerElem-1].SetInt64(1)
	for i := wordsPerElem - 2; i >= 0; i-- {
		r[i].Lsh(&r[i+1], uint(bitsPerWord))
	}

	for elemI := range res {
		res[elemI] = 0
		for wordI := 0; wordI < wordsPerElem; wordI++ {
			absWordI := elemI*wordsPerElem + wordI
			if absWordI >= len(words) {
				break
			}
			res[elemI] = api.Add(res[elemI], api.Mul(words[absWordI], r[wordI]))
		}
	}
	return res
}

func AssertChecksumEquals(api frontend.API, e []frontend.Variable, checksum frontend.Variable) error {
	hsh, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hsh.Write(e...)
	api.AssertIsEqual(hsh.Sum(), checksum)
	return nil
}

func ChecksumBytes(b []byte, hsh hash.Hash, fieldNbBits int) []byte {
	usableBytesPerElem := (fieldNbBits+7)/8 - 1
	buf := make([]byte, usableBytesPerElem+1)
	for i := 0; i < len(b); i += usableBytesPerElem {
		copy(buf[1:], b[i:])
		hsh.Write(buf)
	}
	big.NewInt(int64(len(b))).FillBytes(buf)
	hsh.Write(buf)

	return hsh.Sum(nil)
}

// UnpackIntoBytes does not prove that the data in unpacked are actually bytes
func UnpackIntoBytes(api frontend.API, bytePerElem int, packed []frontend.Variable) (unpacked []frontend.Variable, nbBytes frontend.Variable, err error) {
	if unpacked, err = api.Compiler().NewHint(UnpackIntoBytesHint, bytePerElem*len(packed), packed...); err != nil {
		return
	}
	found := frontend.Variable(0)
	nbBytes = frontend.Variable(0)
	for i := len(unpacked) - 1; i >= 0; i-- {

		z := api.IsZero(unpacked[i])

		lastNonZero := plonk_helpers.EvaluatePlonkExpression(api, z, found, -1, -1, 1, 1) // nz - found
		nbBytes = api.Add(nbBytes, api.Mul(lastNonZero, frontend.Variable(i)))            // the last nonzero byte itself is useless

		//api.AssertIsEqual(api.Mul(api.Sub(bytePerElem-i%bytePerElem, unpacked[i]), lastNonZero), 0) // sanity check, technically unnecessary TODO @Tabaie make sure it's one constraint only or better yet, remove

		found = plonk_helpers.EvaluatePlonkExpression(api, z, found, -1, 0, 1, 1) // found ? 1 : nz = nz + found (1 - nz) = 1 - z + found z
	}
	return
}

func UnpackIntoBytesHint(_ *big.Int, ins, outs []*big.Int) error {
	bytesPerElem := len(outs) / len(ins)
	if len(ins)*bytesPerElem != len(outs) {
		return errors.New("in length must divide out length")
	}
	_256 := big.NewInt(256)
	var v big.Int
	for i := range ins {
		v.Set(ins[i])
		for j := bytesPerElem - 1; j >= 0; j-- {
			v.DivMod(&v, _256, outs[i*bytesPerElem+j])
		}
	}
	return nil
}

func ReadNum(api frontend.API, c []frontend.Variable, nbWords, stepCoeff int) frontend.Variable {
	if nbWords < 0 {
		panic("nbWords cannot be negative")
	} else if nbWords == 0 {
		return 0
	}

	// nbWords \geq 1

	res := c[0]
	for i := 1; i < nbWords && i < len(c); i++ {
		res = api.Add(c[i], api.Mul(res, stepCoeff))
	}

	return res
}

// ShiftLeft erases shiftAmount many elements from the left of Slice and replaces them in the right with zeros
// it is the caller's responsibility to make sure that 0 \le shift < len(c)
func ShiftLeft(api frontend.API, slice []frontend.Variable, shiftAmount frontend.Variable) []frontend.Variable {
	res := make([]frontend.Variable, len(slice))
	l := logderivlookup.New(api)
	for i := range slice {
		l.Insert(slice[i])
	}
	for range slice {
		l.Insert(0)
	}
	for i := range slice {
		res[i] = l.Lookup(api.Add(i, shiftAmount))[0]
	}
	return res
}
