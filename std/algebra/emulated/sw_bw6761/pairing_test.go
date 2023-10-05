package sw_bw6761

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bw6761"
	"github.com/consensys/gnark/test"
)

const testCurve = ecc.BN254

func randomG1G2Affines() (bw6761.G1Affine, bw6761.G2Affine) {
	_, _, G1AffGen, G2AffGen := bw6761.Generators()
	mod := bw6761.ID.ScalarField()
	s1, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	s2, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	var p bw6761.G1Affine
	p.ScalarMultiplication(&G1AffGen, s1)
	var q bw6761.G2Affine
	q.ScalarMultiplication(&G2AffGen, s2)
	return p, q
}

type finalExponentiationBW6761 struct {
	A GT
	B GT
}

func (circuit *finalExponentiationBW6761) Define(api frontend.API) error {
	pr, err := NewPairing(api)
	if err != nil {
		panic(err)
	}
	expected := pr.FinalExponentiation(&circuit.A)
	if err != nil {
		return err
	}

	pr.AssertIsEqual(expected, &circuit.B)

	return nil
}

func TestFinalExponentiationBW6761(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var (
		a     bw6761.G1Affine
		b     bw6761.G2Affine
		c     bw6761.GT
		r1, _ = rand.Int(rand.Reader, fr.Modulus())
		r2, _ = rand.Int(rand.Reader, fr.Modulus())
	)
	_, _, g1, g2 := bw6761.Generators()

	a.ScalarMultiplication(&g1, r1)
	b.ScalarMultiplication(&g2, r2)
	c, err := bw6761.MillerLoop([]bw6761.G1Affine{a}, []bw6761.G2Affine{b})
	if err != nil {
		panic(err)
	}

	d := bw6761.FinalExponentiation(&c)

	witness := finalExponentiationBW6761{
		A: fields_bw6761.FromE6(&c),
		B: fields_bw6761.FromE6(&d),
	}

	err = test.IsSolved(&finalExponentiationBW6761{}, &witness, testCurve.ScalarField())
	assert.NoError(err)

	_, err = frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &finalExponentiationBW6761{}, frontend.IgnoreUnconstrainedInputs())
	assert.NoError(err)
}

type PairCircuit struct {
	InG1 G1Affine
	InG2 G2Affine
	Res  GT
}

func (c *PairCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	res, err := pairing.Pair(&c.InG1, &c.InG2)
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	pairing.AssertIsEqual(res, &c.Res)
	return nil
}

func TestPairTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	p, q := randomG1G2Affines()
	res, err := bw6761.Pair([]bw6761.G1Affine{p}, []bw6761.G2Affine{q})
	assert.NoError(err)
	witness := PairCircuit{
		InG1: NewG1Affine(p),
		InG2: NewG2Affine(q),
		Res:  NewGT(res),
	}
	err = test.IsSolved(&PairCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
