package compress

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/compress/internal/plonk"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"hash"
	"math/big"
)

// Pack packs the words as tightly as possible, and works Big Endian: i.e. the first word is the most significant in the packed elem
// it is on the caller to make sure the words are within range
func Pack(api frontend.API, words []frontend.Variable, bitsPerWord int) []frontend.Variable {
	return PackN(api, words, bitsPerWord, (api.Compiler().FieldBitLen()-1)/bitsPerWord)
}

// PackN packs the words wordsPerElem at a time into field elements, and works Big Endian: i.e. the first word is the most significant in the packed elem
// it is on the caller to make sure the words are within range
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

// AssertChecksumEquals takes a MiMC hash of e and asserts it is equal to checksum
func AssertChecksumEquals(api frontend.API, e []frontend.Variable, checksum frontend.Variable) error {
	hsh, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hsh.Write(e...)
	api.AssertIsEqual(hsh.Sum(), checksum)
	return nil
}

// ChecksumPaddedBytes packs b into field elements, then hashes the field elements along with validLength (encoded into a field element of its own)
func ChecksumPaddedBytes(b []byte, validLength int, hsh hash.Hash, fieldNbBits int) []byte {
	if validLength < 0 || validLength > len(b) {
		panic("invalid length")
	}
	usableBytesPerElem := (fieldNbBits+7)/8 - 1
	buf := make([]byte, usableBytesPerElem+1)
	for i := 0; i < len(b); i += usableBytesPerElem {
		copy(buf[1:], b[i:])
		for j := usableBytesPerElem; j+i > len(b) && j > 0; j-- {
			buf[j] = 0
		}
		hsh.Write(buf)
	}
	big.NewInt(int64(validLength)).FillBytes(buf)
	hsh.Write(buf)

	return hsh.Sum(nil)
}

// ReadNum reads the slice c as a big endian number in base radix
func ReadNum(api frontend.API, c []frontend.Variable, radix *big.Int) frontend.Variable {
	if len(c) == 0 {
		return 0
	}

	res := c[0]
	for i := 1; i < len(c); i++ {
		res = api.Add(c[i], api.Mul(res, radix))
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

// NumReader takes a sequence of words [ b₀ b₁ ... ], along with a base r and length n
// and returns the numbers (b₀ b₁ ... bₙ₋₁)ᵣ, (b₁ b₂ ... bₙ)ᵣ, ... upon successive calls to Next()
type NumReader struct {
	api         frontend.API
	toRead      []frontend.Variable
	radix       *big.Int
	numBound    *big.Int
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

	return &NumReader{
		api:         api,
		toRead:      toRead,
		radix:       twoPow(wordNbBits),
		numBound:    twoPow(numNbBits),
		wordsPerNum: wordsPerNum,
	}
}

func (nr *NumReader) SetNumNbBits(numNbBits int) {
	wordNbBits := nr.radix.BitLen() - 1
	wordsPerNum := numNbBits / wordNbBits
	if wordsPerNum*wordNbBits != numNbBits {
		panic("numNbBits must be divisible by wordNbBits")
	}
	if wordsPerNum < nr.wordsPerNum {
		panic("decreasing wordsPerNum not supported")
	}

	if nr.last != nil { // nothing to compensate for if no values have yet been read
		nbToRead := min(len(nr.toRead), wordsPerNum-nr.wordsPerNum)
		delta := ReadNum(nr.api, nr.toRead[:nbToRead], nr.radix)
		nr.toRead = nr.toRead[:nbToRead]
		nr.last = nr.api.Add(nr.api.Mul(nr.last, twoPow(wordsPerNum-nr.wordsPerNum)), delta)
	}

	nr.wordsPerNum, nr.numBound = wordsPerNum, twoPow(numNbBits)
}

func twoPow(n int) *big.Int {
	res := big.NewInt(1)
	return res.Lsh(res, uint(n))
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
		nr.last = ReadNum(nr.api, nr.toRead[:min(len(nr.toRead), nr.wordsPerNum)], nr.radix)
		if v != nil {
			nr.api.AssertIsEqual(nr.last, v)
		}
		return nr.last
	}

	// let r := nr.radix, n := log(nr.maxCoeff)ᵣ
	// then (b₁ b₂ ... bₙ)ᵣ = r × (b₀ b₁ ... bₙ₋₁)ᵣ - rⁿ × b₀ + bₙ
	nr.last = nr.api.Sub(nr.api.Mul(nr.last, nr.radix), nr.api.Mul(nr.toRead[0], nr.numBound)) // r × (b₀ b₁ ... bₙ₋₁)ᵣ - rⁿ × b₀
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
