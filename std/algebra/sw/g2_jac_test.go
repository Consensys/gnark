package sw

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/tower"
	"github.com/consensys/gnark/std/algebra/tower/fp2"
	"github.com/consensys/gnark/test"
)

type g2AddAssign[T tower.Basis, PT tower.BasisPt[T]] struct {
	A, B G2Jac[T, PT]
	C    G2Jac[T, PT] `gnark:",public"`
}

func (circuit *g2AddAssign[T, PT]) Define(api frontend.API) error {
	expected, err := NewG2Jac[T, PT](api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expected.Set(circuit.A)
	expected.AddAssign(circuit.B)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestAddAssignG2(t *testing.T) {

	// sample 2 random points
	a := randomPointG2()
	b := randomPointG2()

	// create the cs
	var circuit, witness g2AddAssign[fp2.E2, *fp2.E2]

	// assign the inputs
	witness.A = FromG2Jac2(a)
	witness.B = FromG2Jac2(b)

	// compute the result
	a.AddAssign(&b)
	witness.C = FromG2Jac2(a)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

type g2DoubleAssign[T tower.Basis, PT tower.BasisPt[T]] struct {
	A G2Jac[T, PT]
	C G2Jac[T, PT] `gnark:",public"`
}

func (circuit *g2DoubleAssign[T, PT]) Define(api frontend.API) error {
	expected, err := NewG2Jac[T, PT](api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expected.Set(circuit.A)
	expected.Double()
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestDoubleAssignG2(t *testing.T) {

	// sample 2 random points
	a := randomPointG2()

	// create the cs
	var circuit, witness g2DoubleAssign[fp2.E2, *fp2.E2]

	// assign the inputs
	witness.A = FromG2Jac2(a)

	// compute the result
	a.DoubleAssign()
	witness.C = FromG2Jac2(a)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

type g2Neg[T tower.Basis, PT tower.BasisPt[T]] struct {
	A G2Jac[T, PT]
	C G2Jac[T, PT] `gnark:",public"`
}

func (circuit *g2Neg[T, PT]) Define(api frontend.API) error {
	expected, err := NewG2Jac[T, PT](api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expected.Neg(circuit.A)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestNegG2(t *testing.T) {

	// sample 2 random points
	a := randomPointG2()

	// create the cs
	var circuit, witness g2Neg[fp2.E2, *fp2.E2]

	// assign the inputs
	witness.A = FromG2Jac2(a)

	// compute the result
	a.Neg(&a)
	witness.C = FromG2Jac2(a)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}
