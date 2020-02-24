package fp12

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
	{Name: "MulByV", Type: tower.Custom},
	{Name: "MulByVW", Type: tower.Custom},
	{Name: "MulByV2W", Type: tower.Custom},
	{Name: "MulByV2NRInv", Type: tower.Custom},
	{Name: "MulByVWNRInv", Type: tower.Custom},
	{Name: "MulByWNRInv", Type: tower.Custom},
	{Name: "Square", Type: tower.Unary},
	{Name: "Inverse", Type: tower.Unary},
	{Name: "Conjugate", Type: tower.Unary},
	{Name: "Frobenius", Type: tower.Unary},
	{Name: "FrobeniusSquare", Type: tower.Unary},
	{Name: "FrobeniusCube", Type: tower.Unary},
	{Name: "Expt", Type: tower.Custom},
	{Name: "FinalExponentiation", Type: tower.Unary},
}

// Degree is the extension degree of fp12 over the base field
const Degree = 12

func GenerateTestInputs(p string) []tower.TestPoint {

	var modulus big.Int
	modulus.SetString(p, 10)

	var minusOneBigInt big.Int
	minusOneBigInt.SetUint64(1)
	minusOneBigInt.Sub(&modulus, &minusOneBigInt)
	// minusOne := minusOneBigInt.String()

	// hard-coded edge cases
	ptsFixed := [...]tower.TestPoint{
		// {In: tower.FStringPair{
		// 	{
		// 		"1382424129690940106527336948935335363935127549146605398842626667204683483408227749",
		// 		"121296909401065273369489353353639351275491466053988426266672046834834082277499690",
		// 		"7336948129690940106527336948935335363935127549146605398842626667204683483408227749",
		// 		"6393512129690940106527336948935335363935127549146605398842626667204683483408227749",
		// 		"2581296909401065273369489353353639351275491466053988426266672046834834082277496644",
		// 		"5331296909401065273369489353353639351275491466053988426266672046834834082277495363",
		// 		"1296909401065273369489353353639351275491466053988426266672046834834082277491382424",
		// 		"129612969094010652733694893533536393512754914660539884262666720468348340822774990",
		// 		"7336948129690940106527336948935335363935127549146605398842626667204683483408227749",
		// 		"6393129690940106527336948935335363935127549146605398842626667204683483408227749512",
		// 		"2586641296909401065273369489353353639351275491466053988426266672046834834082277494",
		// 		"5312969094010652733694893533536393512754914660539884262666720468348340822774935363",
		// 	},
		// 	{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
		// }},
		{In: tower.FStringPair{
			{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
			{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
		}},
		{In: tower.FStringPair{
			{"0", "0", "1", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
			{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
		}},
		{In: tower.FStringPair{
			{"0", "0", "0", "0", "1", "0", "0", "0", "0", "0", "0", "0"},
			{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
		}},
		{In: tower.FStringPair{
			{"0", "0", "0", "0", "0", "0", "1", "0", "0", "0", "0", "0"},
			{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
		}},
		{In: tower.FStringPair{
			{"0", "0", "0", "0", "0", "0", "0", "0", "1", "0", "0", "0"},
			{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
		}},
		{In: tower.FStringPair{
			{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "1", "0"},
			{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"},
		}},
		// {In: tower.FStringPair{
		// 	{"1", "0", "1", "0", "1", "0"},
		// 	{"1", "0", "1", "0", "1", "0"},
		// }},
		// {In: tower.FStringPair{
		// 	{"0", "1", "1", "0", "0", "1"},
		// 	{"1", "0", "0", "1", "1", "0"},
		// }},
		// {In: tower.FStringPair{
		// 	{"1", "1", "1", "0", "1", "1"},
		// 	{"1", "0", "1", "1", "1", "0"},
		// }},
		// {In: tower.FStringPair{
		// 	{minusOne, "0", "1", "0", minusOne, "0"},
		// 	{"1", "0", minusOne, "0", "1", "0"},
		// }},
		// {In: tower.FStringPair{
		// 	{"0", minusOne, "1", "0", "0", minusOne},
		// 	{"1", "0", "0", minusOne, "1", "0"},
		// }},
		// {In: tower.FStringPair{
		// 	{minusOne, minusOne, "1", "0", minusOne, minusOne},
		// 	{"1", "0", minusOne, minusOne, "1", "0"},
		// }},
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

// ExptBinary a binary wrapper for Expt
func (z *{{.Name}}) ExptBinary(x, y *{{.Name}}) *{{.Name}} {
	z.Expt(x)

	// if tAbsVal is negative then need to undo the conjugation in order to match the test point
	{{- if .TNeg }}
		z.Conjugate(z) // because tAbsVal is negative
	{{- end }}

	return z
}

// MulByVBinary a binary wrapper for MulByV
func (z *{{.Name}}) MulByVBinary(x, y *{{.Name}}) *{{.Name}} {
	yCopy := y.C0.B1
	z.MulByV(x, &yCopy)
	return z
}
// MulByVWBinary a binary wrapper for MulByVW
func (z *{{.Name}}) MulByVWBinary(x, y *{{.Name}}) *{{.Name}} {
	yCopy := y.C1.B1
	z.MulByVW(x, &yCopy)
	return z
}
// MulByV2WBinary a binary wrapper for MulByV2W
func (z *{{.Name}}) MulByV2WBinary(x, y *{{.Name}}) *{{.Name}} {
	yCopy := y.C1.B2
	z.MulByV2W(x, &yCopy)
	return z
}

// MulByV2NRInvBinary a binary wrapper for MulByV2NRInv
func (z *{{.Name}}) MulByV2NRInvBinary(x, y *{{.Name}}) *{{.Name}} {
	yCopy := y.C0.B2
	z.MulByV2NRInv(x, &yCopy)
	return z
}

// MulByVWNRInvBinary a binary wrapper for MulByVWNRInv
func (z *{{.Name}}) MulByVWNRInvBinary(x, y *{{.Name}}) *{{.Name}} {
	yCopy := y.C1.B1
	z.MulByVWNRInv(x, &yCopy)
	return z
}

// MulByWNRInvBinary a binary wrapper for MulByWNRInv
func (z *{{.Name}}) MulByWNRInvBinary(x, y *{{.Name}}) *{{.Name}} {
	yCopy := y.C1.B0
	z.MulByWNRInv(x, &yCopy)
	return z
}
`
