package fp2

import (
	"crypto/rand"
	"math/big"
	mrand "math/rand"

	"github.com/consensys/gnark/ecc/internal/tower"
)

var Methods = [...]tower.Method{
	{Name: "Add", Type: tower.Binary},
	{Name: "Sub", Type: tower.Binary},
	{Name: "Mul", Type: tower.Binary},
	{Name: "MulByElement", Type: tower.Custom},
	// {Name: "MulByNonResidue", Type: tower.Unary},
	{Name: "Square", Type: tower.Unary},
	{Name: "Inverse", Type: tower.Unary},
	{Name: "Conjugate", Type: tower.Unary},
}

// Degree is the extension degree of fp2 over the base field
const Degree = 2

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
			{"0", "0"},
			{"0", "0"},
		}},
		{In: tower.FStringPair{
			{"1", "0"},
			{"1", "0"},
		}},
		{In: tower.FStringPair{
			{"0", "1"},
			{"1", "0"},
		}},
		{In: tower.FStringPair{
			{"1", "1"},
			{"1", "0"},
		}},
		{In: tower.FStringPair{
			{minusOne, "0"},
			{"1", "0"},
		}},
		{In: tower.FStringPair{
			{"0", minusOne},
			{"1", "0"},
		}},
		{In: tower.FStringPair{
			{minusOne, minusOne},
			{"1", "0"},
		}},
	}

	// TODO repeated code, put in tower
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

	// TODO repeated code, put in tower
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

// MulByElementBinary a binary wrapper for MulByElement
func (z *{{.Name}}) MulByElementBinary(x, y *{{.Name}}) *{{.Name}} {
	return z.MulByElement(x, &y.A0)
}
`
