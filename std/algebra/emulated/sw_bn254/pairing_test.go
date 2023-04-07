package sw_bn254

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func randomG1G2Affines(assert *test.Assert) (bn254.G1Affine, bn254.G2Affine) {
	_, _, G1AffGen, G2AffGen := bn254.Generators()
	mod := bn254.ID.ScalarField()
	s1, err := rand.Int(rand.Reader, mod)
	assert.NoError(err)
	s2, err := rand.Int(rand.Reader, mod)
	assert.NoError(err)
	var p bn254.G1Affine
	p.ScalarMultiplication(&G1AffGen, s1)
	var q bn254.G2Affine
	q.ScalarMultiplication(&G2AffGen, s2)
	return p, q
}

type FinalExponentiationCircuit struct {
	InGt GTEl
	Res  GTEl
}

func (c *FinalExponentiationCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	res1 := pairing.FinalExponentiation(&c.InGt)
	pairing.AssertIsEqual(res1, &c.Res)
	res2 := pairing.FinalExponentiationUnsafe(&c.InGt)
	pairing.AssertIsEqual(res2, &c.Res)
	return nil
}

func TestFinalExponentiationTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	var gt bn254.GT
	gt.SetRandom()
	res := bn254.FinalExponentiation(&gt)
	witness := FinalExponentiationCircuit{
		InGt: NewGTEl(gt),
		Res:  NewGTEl(res),
	}
	err := test.IsSolved(&FinalExponentiationCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type PairCircuit struct {
	InG1 G1Affine
	InG2 G2Affine
	Res  GTEl
}

func (c *PairCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	pairing.AssertIsOnG1(&c.InG1)
	pairing.AssertIsOnG2(&c.InG2)
	res, err := pairing.Pair([]*G1Affine{&c.InG1}, []*G2Affine{&c.InG2})
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	pairing.AssertIsEqual(res, &c.Res)
	return nil
}

func TestPairTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	p, q := randomG1G2Affines(assert)
	res, err := bn254.Pair([]bn254.G1Affine{p}, []bn254.G2Affine{q})
	assert.NoError(err)
	witness := PairCircuit{
		InG1: NewG1Affine(p),
		InG2: NewG2Affine(q),
		Res:  NewGTEl(res),
	}
	err = test.IsSolved(&PairCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type MultiPairCircuit struct {
	In1G1 G1Affine
	In2G1 G1Affine
	In1G2 G2Affine
	In2G2 G2Affine
	Res   GTEl
}

func (c *MultiPairCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	pairing.AssertIsOnG1(&c.In1G1)
	pairing.AssertIsOnG1(&c.In2G1)
	pairing.AssertIsOnG2(&c.In1G2)
	pairing.AssertIsOnG2(&c.In2G2)
	res, err := pairing.Pair([]*G1Affine{&c.In1G1, &c.In1G1, &c.In2G1, &c.In2G1}, []*G2Affine{&c.In1G2, &c.In2G2, &c.In1G2, &c.In2G2})
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	pairing.AssertIsEqual(res, &c.Res)
	return nil
}

func TestMultiPairTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	p1, q1 := randomG1G2Affines(assert)
	p2, q2 := randomG1G2Affines(assert)
	res, err := bn254.Pair([]bn254.G1Affine{p1, p1, p2, p2}, []bn254.G2Affine{q1, q2, q1, q2})
	assert.NoError(err)
	witness := MultiPairCircuit{
		In1G1: NewG1Affine(p1),
		In1G2: NewG2Affine(q1),
		In2G1: NewG1Affine(p2),
		In2G2: NewG2Affine(q2),
		Res:   NewGTEl(res),
	}
	err = test.IsSolved(&MultiPairCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type PairingCheckCircuit struct {
	In1G1 G1Affine
	In2G1 G1Affine
	In1G2 G2Affine
	In2G2 G2Affine
}

func (c *PairingCheckCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	err = pairing.PairingCheck([]*G1Affine{&c.In1G1, &c.In1G1, &c.In2G1, &c.In2G1}, []*G2Affine{&c.In1G2, &c.In2G2, &c.In1G2, &c.In2G2})
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	return nil
}

func TestPairingCheckTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	p1, q1 := randomG1G2Affines(assert)
	_, q2 := randomG1G2Affines(assert)
	var p2 bn254.G1Affine
	p2.Neg(&p1)
	witness := PairingCheckCircuit{
		In1G1: NewG1Affine(p1),
		In1G2: NewG2Affine(q1),
		In2G1: NewG1Affine(p2),
		In2G2: NewG2Affine(q2),
	}
	err := test.IsSolved(&PairingCheckCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type FinalExponentiationSafeCircuit struct {
	P1, P2 G1Affine
	Q1, Q2 G2Affine
}

func (c *FinalExponentiationSafeCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return err
	}
	res, err := pairing.MillerLoop([]*G1Affine{&c.P1, &c.P2}, []*G2Affine{&c.Q1, &c.Q2})
	if err != nil {
		return err
	}
	res2 := pairing.FinalExponentiation(res)
	one := pairing.Ext12.One()
	pairing.AssertIsEqual(one, res2)
	return nil
}

func TestFinalExponentiationSafeCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, p1, q1 := bn254.Generators()
	var p2 bn254.G1Affine
	var q2 bn254.G2Affine
	p2.Neg(&p1)
	q2.Set(&q1)
	err := test.IsSolved(&FinalExponentiationSafeCircuit{}, &FinalExponentiationSafeCircuit{
		P1: NewG1Affine(p1),
		P2: NewG1Affine(p2),
		Q1: NewG2Affine(q1),
		Q2: NewG2Affine(q2),
	}, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type GroupMembershipCircuit struct {
	InG1 G1Affine
	InG2 G2Affine
}

func (c *GroupMembershipCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	pairing.AssertIsOnG1(&c.InG1)
	pairing.AssertIsOnG2(&c.InG2)
	return nil
}

func TestGroupMembershipSolve(t *testing.T) {
	assert := test.NewAssert(t)
	p, q := randomG1G2Affines(assert)
	witness := GroupMembershipCircuit{
		InG1: NewG1Affine(p),
		InG2: NewG2Affine(q),
	}
	err := test.IsSolved(&GroupMembershipCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
