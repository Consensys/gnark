package internal

import (
	"errors"
	hint "github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"math/big"
)

type NumReader struct {
	api         frontend.API
	c           []frontend.Variable
	stepCoeff   int
	maxCoeff    int
	wordsPerNum int
	last        frontend.Variable
}

func NewNumReader(api frontend.API, c []frontend.Variable, numNbBits, wordNbBits int) *NumReader {
	wordsPerNum := numNbBits / wordNbBits

	if wordsPerNum*wordNbBits != numNbBits {
		panic("wordNbBits must be a divisor of 8")
	}

	stepCoeff := 1 << wordNbBits
	return &NumReader{
		api:         api,
		c:           c,
		stepCoeff:   stepCoeff,
		maxCoeff:    1 << numNbBits,
		wordsPerNum: wordsPerNum,
	}
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

func AssertNumEquals(api frontend.API, c []frontend.Variable, stepCoeff int, num frontend.Variable) {

	if len(c) == 0 {
		api.AssertIsEqual(num, 0)
		return
	} else if len(c) == 1 {
		api.AssertIsEqual(num, c[0])
		return
	}

	// nbWords \geq 2

	res := c[0]
	for i := 1; i < len(c)-1 && i < len(c); i++ {
		res = api.Add(c[i], api.Mul(res, stepCoeff))
	}
	addPlonkConstraint(api, c[len(c)-1], res, num, 1, stepCoeff, -1, 0, 0)
}

// TODO perf @tabaie AssertNextEquals

// Next returns the next number in the sequence. assumes bits past the end of the slice are 0
func (nr *NumReader) Next() frontend.Variable {
	return nr.next(nil)
}

func (nr *NumReader) AssertNextEquals(v frontend.Variable) {
	nr.next(v)
}

func (nr *NumReader) next(v frontend.Variable) frontend.Variable {
	if len(nr.c) == 0 {
		return 0
	}

	if nr.last == nil { // the very first call
		nr.last = ReadNum(nr.api, nr.c, nr.wordsPerNum, nr.stepCoeff)
		if v != nil {
			nr.api.AssertIsEqual(nr.last, v)
		}
		return nr.last
	}

	nr.last = nr.api.Sub(nr.api.Mul(nr.last, nr.stepCoeff), nr.api.Mul(nr.c[0], nr.maxCoeff))
	if nr.wordsPerNum < len(nr.c) {
		if v == nil {
			nr.last = nr.api.Add(nr.last, nr.c[nr.wordsPerNum])
		} else {
			addPlonkConstraint(nr.api, nr.last, nr.c[nr.wordsPerNum], v, 1, 1, -1, 0, 0)
			nr.last = v
		}
	} else if v != nil {
		panic("todo refactoring required")
	}

	nr.c = nr.c[1:]
	return nr.last
}

// TODO Migrate to std/rangecheck
type RangeChecker struct {
	api    frontend.API
	tables map[uint]*logderivlookup.Table
}

func NewRangeChecker(api frontend.API) *RangeChecker {
	return &RangeChecker{api: api, tables: make(map[uint]*logderivlookup.Table)}
}

func (r *RangeChecker) AssertLessThan(bound uint, c ...frontend.Variable) {

	var check func(frontend.Variable)
	switch bound {
	case 1:
		check = func(v frontend.Variable) { r.api.AssertIsEqual(v, 0) }
	case 2:
		check = r.api.AssertIsBoolean
	case 4:
		check = r.api.AssertIsCrumb
	default:
		cRangeTable, ok := r.tables[bound]
		if !ok {
			cRangeTable := logderivlookup.New(r.api)
			for i := uint(0); i < bound; i++ {
				cRangeTable.Insert(0)
			}
		}
		_ = cRangeTable.Lookup(c...)
		return
	}
	for i := range c {
		check(c[i])
	}
}

// LessThan returns a variable that is 1 if 0 \leq c < bound, 0 otherwise
// TODO perf @Tabaie see if we can get away with a weaker contract, where the return value is 0 iff 0 \leq c < bound
func (r *RangeChecker) LessThan(bound uint, c frontend.Variable) frontend.Variable {
	switch bound {
	case 1:
		return r.api.IsZero(c)
	}

	if bound%2 != 0 {
		panic("odd bounds not yet supported")
	}
	v := EvaluatePlonkExpression(r.api, c, c, -int(bound-1), 0, 1, 0) // c^2 - (bound-1)*c
	res := v
	for i := uint(1); i < bound/2; i++ {
		res = EvaluatePlonkExpression(r.api, res, v, int(i*(bound-i-1)), 0, 1, 0)
	}

	return r.api.IsZero(res)
}

var wordNbBitsToHint = map[int]hint.Hint{1: BreakUpBytesIntoBitsHint, 2: BreakUpBytesIntoCrumbsHint, 4: BreakUpBytesIntoHalfHint}

// BreakUpBytesIntoWords breaks up bytes into words of size wordNbBits
// It also returns a slice of bytes which are a reading of the input byte slice starting from each of the words, thus a super-slice of the input
// It has the side effect of checking that the input does in fact consist of bytes
func (r *RangeChecker) BreakUpBytesIntoWords(wordNbBits int, bytes ...frontend.Variable) (words, recombined []frontend.Variable) {

	wordsPerByte := 8 / wordNbBits
	if wordsPerByte*wordNbBits != 8 {
		panic("wordNbBits must be a divisor of 8")
	}

	// solving: break up bytes into words
	words = bytes
	if wordsPerByte != 1 {
		var err error
		// todo @tabaie use named hints so different wordNbBits can be used in the same circuit
		if words, err = r.api.Compiler().NewHint(wordNbBitsToHint[wordNbBits], wordsPerByte*len(bytes), bytes...); err != nil {
			panic(err)
		}
	}

	// proving: check that words are in range
	r.AssertLessThan(1<<wordNbBits, words...)

	reader := NewNumReader(r.api, words, 8, wordNbBits)
	recombined = make([]frontend.Variable, len(words))
	for i := range bytes {
		reader.AssertNextEquals(bytes[i])
		recombined[i*wordsPerByte] = bytes[i]
		for j := 1; j < wordsPerByte; j++ {
			recombined[i*wordsPerByte+j] = reader.Next()
		}
	}

	return words, recombined
}

func breakUpBytesIntoWords(wordNbBits int, ins, outs []*big.Int) error {

	if 8%wordNbBits != 0 {
		return errors.New("wordNbBits must be a divisor of 8")
	}

	if len(outs) != 8/wordNbBits*len(ins) {
		return errors.New("incongruent number of ins/outs")
	}

	_256 := big.NewInt(256)
	wordMod := big.NewInt(1 << uint(wordNbBits))

	var v big.Int
	for i := range ins {
		v.Set(ins[i])
		if v.Cmp(_256) >= 0 {
			return errors.New("not a byte")
		}
		for j := 8/wordNbBits - 1; j >= 0; j-- {
			outs[i*8/wordNbBits+j].Mod(&v, wordMod) // todo @tabaie more efficiently
			v.Rsh(&v, uint(wordNbBits))
		}
	}

	return nil
}

func BreakUpBytesIntoBitsHint(_ *big.Int, ins, outs []*big.Int) error {
	return breakUpBytesIntoWords(1, ins, outs)
}

func BreakUpBytesIntoCrumbsHint(_ *big.Int, ins, outs []*big.Int) error {
	return breakUpBytesIntoWords(2, ins, outs)
}

func BreakUpBytesIntoHalfHint(_ *big.Int, ins, outs []*big.Int) error { // todo find catchy name for 4 bits
	return breakUpBytesIntoWords(4, ins, outs)
}

func addPlonkConstraint(api frontend.API, a, b, o frontend.Variable, qL, qR, qO, qM, qC int) {
	if papi, ok := api.(frontend.PlonkAPI); ok {
		papi.AddPlonkConstraint(a, b, o, qL, qR, qO, qM, qC)
	} else {
		api.AssertIsEqual(
			api.Add(
				api.Mul(a, qL),
				api.Mul(b, qR),
				api.Mul(a, b, qM),
				api.Mul(o, qO),
				qC,
			),
			0,
		)
	}
}
