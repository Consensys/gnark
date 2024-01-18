package compress

import (
	"errors"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/compress/internal"
	"github.com/consensys/gnark/std/hash/mimc"
	"math/big"
)

// Pack works Big Endian: i.e. the first word is the most significant in the packed elem
func Pack(api frontend.API, words []frontend.Variable, wordLen int) []frontend.Variable {
	wordsPerElem := (api.Compiler().FieldBitLen() - 1) / wordLen
	res := make([]frontend.Variable, (len(words)+wordsPerElem-1)/wordsPerElem)
	for elemI := range res {
		res[elemI] = 0
		for wordI := 0; wordI < wordsPerElem; wordI++ {
			absWordI := (elemI+1)*wordsPerElem - wordI - 1
			if absWordI >= len(words) {
				break
			}
			res[elemI] = api.Add(res[elemI], api.Mul(words[absWordI], 1<<uint(wordLen*wordI)))
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

// UnpackIntoBytes does not prove that the data in unpacked are actually bytes
func UnpackIntoBytes(api frontend.API, bytePerElem int, packed []frontend.Variable) (unpacked []frontend.Variable, nbBytes frontend.Variable, err error) {
	if unpacked, err = api.Compiler().NewHint(UnpackIntoBytesHint, bytePerElem*len(packed), packed...); err != nil {
		return
	}
	found := frontend.Variable(0)
	nbBytes = frontend.Variable(0)
	for i := len(unpacked) - 1; i >= 0; i-- {

		z := api.IsZero(unpacked[i])

		lastNonZero := internal.EvaluatePlonkExpression(api, z, found, -1, -1, 0, 1) // nz - found
		nbBytes = api.Add(nbBytes, api.Mul(lastNonZero, frontend.Variable(i)))       // the last nonzero byte itself is useless

		//api.AssertIsEqual(api.Mul(api.Sub(bytePerElem-i%bytePerElem, unpacked[i]), lastNonZero), 0) // sanity check, technically unnecessary TODO @Tabaie make sure it's one constraint only or better yet, remove

		found = internal.EvaluatePlonkExpression(api, z, found, -1, 0, 1, 1) // found ? 1 : nz = nz + found (1 - nz) = 1 - z + found z
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
