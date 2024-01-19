package internal

import (
	"errors"
	hint "github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/compress"
	"github.com/consensys/gnark/std/compress/internal/plonk"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"math/big"
)

// NumReader takes a sequence of words [ b₀ b₁ ... ], along with a base r and length n
// and returns the numbers (b₀ b₁ ... bₙ₋₁)ᵣ, (b₁ b₂ ... bₙ)ᵣ, ... upon successive calls to Next()
type NumReader struct {
	api         frontend.API
	toRead      []frontend.Variable
	radix       int
	maxCoeff    int
	wordsPerNum int
	last        frontend.Variable
}

// NewNumReader returns a new NumReader
// toRead is the slice of words to read from
// numNbBits defines the radix as r = 2ⁿᵘᵐᴺᵇᴮⁱᵗˢ (or rather numNbBits = log₂(r) )
// wordNbBits defines the number of bits in each word such that n = numNbBits/wordNbBits
// it is the caller's responsibility to check 0 ≤ bᵢ < r ∀ i
func NewNumReader(api frontend.API, toRead []frontend.Variable, numNbBits, wordNbBits int) *NumReader {
	wordsPerNum := numNbBits / wordNbBits

	if wordsPerNum*wordNbBits != numNbBits {
		panic("wordNbBits must be a divisor of 8")
	}

	radix := 1 << wordNbBits
	return &NumReader{
		api:         api,
		toRead:      toRead,
		radix:       radix,
		maxCoeff:    1 << numNbBits,
		wordsPerNum: wordsPerNum,
	}
}

// Next returns the next number in the sequence and advances the reader head by one word. assumes bits past the end of the Slice are 0
func (nr *NumReader) Next() frontend.Variable {
	return nr.next(nil)
}

// AssertNextEquals is functionally equivalent to
//
//	z := nr.Next()
//	api.AssertIsEqual(v, z)
//
// while saving exactly one constraint
func (nr *NumReader) AssertNextEquals(v frontend.Variable) {
	nr.next(v)
}

// next returns the next number in the sequence.
// if v != nil, it returns v and asserts it is equal to the next number in the sequence (making a petty saving of one constraint by not creating a new variable)
func (nr *NumReader) next(v frontend.Variable) frontend.Variable {
	if len(nr.toRead) == 0 {
		return 0
	}

	if nr.last == nil { // the very first call
		nr.last = compress.ReadNum(nr.api, nr.toRead[:min(len(nr.toRead), nr.wordsPerNum)], nr.radix)
		if v != nil {
			nr.api.AssertIsEqual(nr.last, v)
		}
		return nr.last
	}

	// let r := nr.radix, n := log(nr.maxCoeff)ᵣ
	// then (b₁ b₂ ... bₙ)ᵣ = r × (b₀ b₁ ... bₙ₋₁)ᵣ - rⁿ × b₀ + bₙ
	nr.last = nr.api.Sub(nr.api.Mul(nr.last, nr.radix), nr.api.Mul(nr.toRead[0], nr.maxCoeff)) // r × (b₀ b₁ ... bₙ₋₁)ᵣ - rⁿ × b₀
	if nr.wordsPerNum < len(nr.toRead) {
		if v == nil { // return r × (b₀ b₁ ... bₙ₋₁)ᵣ - rⁿ × b₀ + bₙ
			nr.last = nr.api.Add(nr.last, nr.toRead[nr.wordsPerNum])
		} else { // assert v = r × (b₀ b₁ ... bₙ₋₁)ᵣ - rⁿ × b₀ + bₙ
			plonk.AddConstraint(nr.api, nr.last, nr.toRead[nr.wordsPerNum], v, 1, 1, -1, 0, 0)
			nr.last = v
		}
	} else if v != nil {
		panic("todo refactoring required")
	}

	nr.toRead = nr.toRead[1:]
	return nr.last
}

// TODO Use std/rangecheck instead
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

// IsLessThan returns a variable that is 1 if 0 ≤ c < bound, 0 otherwise
// TODO perf @Tabaie see if we can get away with a weaker contract, where the return value is 0 iff 0 ≤ c < bound
func (r *RangeChecker) IsLessThan(bound uint, c frontend.Variable) frontend.Variable {
	switch bound {
	case 1:
		return r.api.IsZero(c)
	}

	if bound%2 != 0 {
		panic("odd bounds not yet supported")
	}
	v := plonk.EvaluateExpression(r.api, c, c, -int(bound-1), 0, 1, 0) // toRead² - (bound-1)× toRead
	res := v
	for i := uint(1); i < bound/2; i++ {
		res = plonk.EvaluateExpression(r.api, res, v, int(i*(bound-i-1)), 0, 1, 0)
	}

	return r.api.IsZero(res)
}

var wordNbBitsToHint = map[int]hint.Hint{1: BreakUpBytesIntoBitsHint, 2: BreakUpBytesIntoCrumbsHint, 4: BreakUpBytesIntoHalfHint}

// BreakUpBytesIntoWords breaks up bytes into words of size wordNbBits
// It also returns a Slice of bytes which are a reading of the input byte Slice starting from each of the words, thus a super-Slice of the input
// It has the side effect of checking that the input does in fact consist of bytes
// As an example, let the words be bits and the input be the bytes [b₀ b₁ b₂ b₃ b₄ b₅ b₆ b₇], [b₈ b₉ b₁₀ b₁₁ b₁₂ b₁₃ b₁₄ b₁₅]
// Then the output words are b₀, b₁, b₂, b₃, b₄, b₅, b₆, b₇, b₈, b₉, b₁₀, b₁₁, b₁₂, b₁₃, b₁₄, b₁₅
// The "recombined" output is the slice {[b₀ b₁ b₂ b₃ b₄ b₅ b₆ b₇], [b₁ b₂ b₃ b₄ b₅ b₆ b₇ b₈], ...}
// Note that for any i in range we get recombined[8*i] = bytes[i]
func (r *RangeChecker) BreakUpBytesIntoWords(wordNbBits int, bytes ...frontend.Variable) (words, recombined []frontend.Variable) {

	wordsPerByte := 8 / wordNbBits
	if wordsPerByte*wordNbBits != 8 {
		panic("wordNbBits must be a divisor of 8")
	}

	// solving: break up bytes into words
	words = bytes
	if wordsPerByte != 1 {
		var err error
		if words, err = r.api.Compiler().NewHint(wordNbBitsToHint[wordNbBits], wordsPerByte*len(bytes), bytes...); err != nil {
			panic(err)
		}
	}

	// proving: check that words are in range
	r.AssertLessThan(1<<wordNbBits, words...)

	reader := NewNumReader(r.api, words, 8, wordNbBits) // "fill in" the spaces in between the given bytes
	recombined = make([]frontend.Variable, len(words))
	for i := range bytes {
		reader.AssertNextEquals(bytes[i]) // see that the words do recombine to the original bytes; the only real difference between this and the inner loop is a single constraint saved
		recombined[i*wordsPerByte] = bytes[i]
		for j := 1; j < wordsPerByte; j++ {
			recombined[i*wordsPerByte+j] = reader.Next() //
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
