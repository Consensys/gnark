package compress

import (
	"github.com/consensys/gnark/frontend"
)

func Pack(api frontend.API, words []frontend.Variable, wordLen int) []frontend.Variable {
	wordsPerElem := (api.Compiler().FieldBitLen() - 1) / wordLen
	res := make([]frontend.Variable, 1+(len(words)-1)/wordsPerElem)
	for elemI := range res {
		res[elemI] = 0
		for wordI := 0; wordI < wordsPerElem; wordI++ {
			absWordI := elemI*wordsPerElem + wordI
			if absWordI >= len(words) {
				break
			}
			res[elemI] = api.Add(res[elemI], api.Mul(words[absWordI], 1<<uint(wordLen*wordI)))
		}
	}
	return res
}

type NumReader struct {
	api       frontend.API
	c         []frontend.Variable
	stepCoeff int
	maxCoeff  int
	nbWords   int
	nxt       frontend.Variable
}

func NewNumReader(api frontend.API, c []frontend.Variable, numNbBits, wordNbBits int) *NumReader {
	nbWords := numNbBits / wordNbBits
	stepCoeff := 1 << wordNbBits
	nxt := ReadNum(api, c, nbWords, stepCoeff)
	return &NumReader{
		api:       api,
		c:         c,
		stepCoeff: stepCoeff,
		maxCoeff:  1 << numNbBits,
		nxt:       nxt,
		nbWords:   nbWords,
	}
}

func ReadNum(api frontend.API, c []frontend.Variable, nbWords, stepCoeff int) frontend.Variable {
	res := frontend.Variable(0)
	for i := 0; i < nbWords && i < len(c); i++ {
		res = api.Add(c[i], api.Mul(res, stepCoeff))
	}
	return res
}

// Next returns the next number in the sequence. assumes bits past the end of the slice are 0
func (nr *NumReader) Next() frontend.Variable {
	res := nr.nxt

	if len(nr.c) != 0 {
		nr.nxt = nr.api.Sub(nr.api.Mul(nr.nxt, nr.stepCoeff), nr.api.Mul(nr.c[0], nr.maxCoeff))

		if nr.nbWords < len(nr.c) {
			nr.nxt = nr.api.Add(nr.nxt, nr.c[nr.nbWords])
		}

		nr.c = nr.c[1:]
	}

	return res
}
