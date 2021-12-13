package sw

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type g1AddAssign struct {
	A, B G1Jac
	C    G1Jac `gnark:",public"`
}

func (circuit *g1AddAssign) Define(api frontend.API) error {
	expected, err := NewG1Jac(api)
	if err != nil {
		return fmt.Errorf("new G1Affine")
	}
	expected.Set(circuit.A)
	expected.AddAssign(circuit.B)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestAddAssignG1(t *testing.T) {

	// sample 2 random points
	a := randomPointG1()
	b := randomPointG1()

	// create the cs
	var circuit, witness g1AddAssign

	// assign the inputs
	witness.A = FromG1Jac(a)
	witness.B = FromG1Jac(b)

	// compute the result
	a.AddAssign(&b)
	witness.C = FromG1Jac(a)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

type g1DoubleAssign struct {
	A G1Jac
	C G1Jac `gnark:",public"`
}

func (circuit *g1DoubleAssign) Define(api frontend.API) error {
	expected, err := NewG1Jac(api)
	if err != nil {
		return fmt.Errorf("new G1Affine")
	}
	expected.Set(circuit.A)
	expected.DoubleAssign(api)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestDoubleAssignG1(t *testing.T) {

	// sample 2 random points
	a := randomPointG1()

	// create the cs
	var circuit, witness g1DoubleAssign

	// assign the inputs
	witness.A = FromG1Jac(a)

	// compute the result
	a.DoubleAssign()
	witness.C = FromG1Jac(a)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

type g1Neg struct {
	A G1Jac
	C G1Jac `gnark:",public"`
}

func (circuit *g1Neg) Define(api frontend.API) error {
	expected, err := NewG1Jac(api)
	if err != nil {
		return fmt.Errorf("new G1Affine")
	}
	expected.Set(circuit.A)
	expected.Neg(circuit.A)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestNegG1(t *testing.T) {

	// sample 2 random points
	a := randomPointG1()

	// assign the inputs
	var witness g1Neg
	witness.A = FromG1Jac(a)
	a.Neg(&a)
	witness.C = FromG1Jac(a)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&g1Neg{}, &witness, test.WithCurves(ecc.BW6_761))

}
