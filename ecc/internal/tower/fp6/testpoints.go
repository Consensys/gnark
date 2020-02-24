package fp6

import (
	"crypto/rand"
	"fmt"
	"math/big"
	mrand "math/rand"

	"github.com/consensys/gnark/ecc/internal/curve"
	"github.com/consensys/gnark/ecc/internal/testpoints"
	"github.com/consensys/gnark/ecc/internal/tower"
)

var Methods = [...]tower.Method{
	{Name: "Add", Type: tower.Binary},
	{Name: "Sub", Type: tower.Binary},
	{Name: "Mul", Type: tower.Binary},
	{Name: "MulByE2", Type: tower.Custom},
	{Name: "MulByGen", Type: tower.Unary},
	// {Name: "MulByNonResidue", Type: tower.Unary},
	{Name: "Square", Type: tower.Unary},
	{Name: "Inverse", Type: tower.Unary},
}

// Degree is the extension degree of fp6 over the base field
const Degree = 6

func GenerateTestInputs(p string) []tower.TestPoint {

	var modulus big.Int
	modulus.SetString(p, 10)

	var minusOneBigInt big.Int
	minusOneBigInt.SetUint64(1)
	minusOneBigInt.Sub(&modulus, &minusOneBigInt)
	minusOne := minusOneBigInt.String()

	// hard-coded edge cases
	ptsFixed := [...]tower.TestPoint{
		{In: tower.FStringPair{
			{"0", "0", "0", "0", "0", "0"},
			{"0", "0", "0", "0", "0", "0"},
		}},
		{In: tower.FStringPair{
			{"1", "0", "1", "0", "1", "0"},
			{"1", "0", "1", "0", "1", "0"},
		}},
		{In: tower.FStringPair{
			{"0", "1", "1", "0", "0", "1"},
			{"1", "0", "0", "1", "1", "0"},
		}},
		{In: tower.FStringPair{
			{"1", "1", "1", "0", "1", "1"},
			{"1", "0", "1", "1", "1", "0"},
		}},
		{In: tower.FStringPair{
			{minusOne, "0", "1", "0", minusOne, "0"},
			{"1", "0", minusOne, "0", "1", "0"},
		}},
		{In: tower.FStringPair{
			{"0", minusOne, "1", "0", "0", minusOne},
			{"1", "0", "0", minusOne, "1", "0"},
		}},
		{In: tower.FStringPair{
			{minusOne, minusOne, "1", "0", minusOne, minusOne},
			{"1", "0", minusOne, minusOne, "1", "0"},
		}},
	}

	// pseudorandom points from a fixed seed
	seed := int64(modulus.Bits()[len(modulus.Bits())-1]) // use the high word of modulus as a fixed seed
	randReader := mrand.New(mrand.NewSource(seed))

	var ptsRandom [3]tower.TestPoint
	for i := range ptsRandom {
		for j := range ptsRandom[i].In {
			ptsRandom[i].In[j] = make(tower.FString, Degree)
			for k := range ptsRandom[i].In[j] {
				randBigInt, err := rand.Int(randReader, &modulus)
				if err != nil {
					panic(err)
				}
				ptsRandom[i].In[j][k] = randBigInt.String()
			}
		}
	}

	result := append(ptsFixed[:], ptsRandom[:]...)
	for i := range result {
		result[i].Out = make([]tower.FString, len(Methods))
		for j := range result[i].Out {
			result[i].Out[j] = make(tower.FString, Degree)
		}
	}
	return result
}

const customTests = `
//-------------------------------------//
// custom helpers for {{.Name}} methods
//-------------------------------------//

// MulByE2Binary a binary wrapper for MulByE2
func (z *{{.Name}}) MulByE2Binary(x, y *{{.Name}}) *{{.Name}} {
	return z.MulByE2(x, &y.B0)
}
`

type Input curve.Data

const PointTupleSize = 2

func NewInputSource(c *curve.Data) *Input {
	return (*Input)(c)
}

func (z *Input) FixedInputs() []testpoints.PointTuple {
	r := []testpoints.PointTuple{
		testpoints.PointTuple{
			{"0", "0", "0", "0", "0", "0"},
			{"0", "0", "0", "0", "0", "0"},
		},
		testpoints.PointTuple{
			{"1", "0", "1", "0", "1", "0"},
			{"1", "0", "1", "0", "1", "0"},
		},
		testpoints.PointTuple{
			{"0", "1", "1", "0", "0", "1"},
			{"1", "0", "0", "1", "1", "0"},
		},
		testpoints.PointTuple{
			{"1", "1", "1", "0", "1", "1"},
			{"1", "0", "1", "1", "1", "0"},
		},
		// {In: tower.FStringPair{
		// 	{minusOne, "0", "1", "0", minusOne, "0"},
		// 	{"1", "0", minusOne, "0", "1", "0"},
		// }},
	}

	// sanity check
	// TODO copied code, refactor
	for i := range r {
		if len(r[i]) != PointTupleSize {
			panic(fmt.Sprintf("fixed input tuple %d has length %d, should be %d", i, len(r[i]), PointTupleSize))
		}
		for j := range r {
			if len(r[i][j]) != Degree {
				panic(fmt.Sprintf("fixed input point (%d,%d) has length %d, should be %d", i, j, len(r[i][j]), Degree))
			}
		}
	}

	return r
}

// TODO copied code, refactor into... tower??
func (z *Input) RandomInput() testpoints.PointTuple {
	r := make(testpoints.PointTuple, PointTupleSize)
	for i := range r {
		r[i] = make(testpoints.Point, Degree)
		for j := range r[i] {
			randBigInt, err := rand.Int(z.RandReader, z.P)
			if err != nil {
				panic(err)
			}
			r[i][j] = randBigInt.String()
		}
	}
	return r
}
