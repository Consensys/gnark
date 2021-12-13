package sw

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// -------------------------------------------------------------------------------------------------
// Add jacobian

// -------------------------------------------------------------------------------------------------
// Add affine

type g1AddAssignAffine struct {
	A, B G1Affine
	C    G1Affine `gnark:",public"`
}

func (circuit *g1AddAssignAffine) Define(api frontend.API) error {
	expected, err := NewG1Affine(api)
	if err != nil {
		return fmt.Errorf("new G1Affine")
	}
	expected.Set(circuit.A)
	expected.AddAssign(circuit.B)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestAddAssignAffineG1(t *testing.T) {

	// sample 2 random points
	_a := randomPointG1()
	_b := randomPointG1()
	var a, b, c bls12377.G1Affine
	a.FromJacobian(&_a)
	b.FromJacobian(&_b)

	// create the cs
	var circuit, witness g1AddAssignAffine

	// assign the inputs
	witness.A = FromG1Affine(a)
	witness.B = FromG1Affine(b)

	// compute the result
	_a.AddAssign(&_b)
	c.FromJacobian(&_a)
	witness.C = FromG1Affine(c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

// -------------------------------------------------------------------------------------------------
// Double Jacobian

// -------------------------------------------------------------------------------------------------
// Double affine

type g1DoubleAffine struct {
	A G1Affine
	C G1Affine `gnark:",public"`
}

func (circuit *g1DoubleAffine) Define(api frontend.API) error {
	expected, err := NewG1Affine(api)
	if err != nil {
		return fmt.Errorf("new G1Affine")
	}
	expected.Set(circuit.A)
	expected.Double(circuit.A)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestDoubleAffineG1(t *testing.T) {

	// sample 2 random points
	_a, _, a, _ := bls12377.Generators()
	var c bls12377.G1Affine

	// create the cs
	var circuit, witness g1DoubleAffine

	// assign the inputs and compute the result
	witness.A = FromG1Affine(a)
	_a.DoubleAssign()
	c.FromJacobian(&_a)
	witness.C = FromG1Affine(c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

// -------------------------------------------------------------------------------------------------
// DoubleAndAdd affine

type g1DoubleAndAddAffine struct {
	A, B G1Affine
	C    G1Affine `gnark:",public"`
}

func (circuit *g1DoubleAndAddAffine) Define(api frontend.API) error {
	expected, err := NewG1Affine(api)
	if err != nil {
		return fmt.Errorf("new G1Affine")
	}
	expected.Set(circuit.A)
	expected.DoubleAndAdd(&circuit.A, &circuit.B)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestDoubleAndAddAffineG1(t *testing.T) {

	// sample 2 random points
	_a := randomPointG1()
	_b := randomPointG1()
	var a, b, c bls12377.G1Affine
	a.FromJacobian(&_a)
	b.FromJacobian(&_b)

	// create the cs
	var circuit, witness g1DoubleAndAddAffine

	// assign the inputs
	witness.A = FromG1Affine(a)
	witness.B = FromG1Affine(b)

	// compute the result
	_a.Double(&_a).AddAssign(&_b)
	c.FromJacobian(&_a)
	witness.C = FromG1Affine(c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

// -------------------------------------------------------------------------------------------------
// Neg

// -------------------------------------------------------------------------------------------------
// Scalar multiplication

type g1constantScalarMul struct {
	A G1Affine
	C G1Affine `gnark:",public"`
	R *big.Int
}

func (circuit *g1constantScalarMul) Define(api frontend.API) error {
	expected, err := NewG1Affine(api)
	if err != nil {
		return fmt.Errorf("new G1Affine")
	}
	//expected.Set(circuit.A)
	expected.constScalarMul(circuit.A, circuit.R)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestConstantScalarMulG1(t *testing.T) {
	// sample random point
	_a := randomPointG1()
	var a, c bls12377.G1Affine
	a.FromJacobian(&_a)

	// create the cs
	var circuit, witness g1constantScalarMul
	var r fr.Element
	r.SetRandom()
	// assign the inputs
	witness.A = FromG1Affine(a)
	// compute the result
	br := new(big.Int)
	r.ToBigIntRegular(br)
	// br is a circuit parameter
	circuit.R = br
	_a.ScalarMultiplication(&_a, br)
	c.FromJacobian(&_a)
	witness.C = FromG1Affine(c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

type g1varScalarMul struct {
	A G1Affine
	C G1Affine `gnark:",public"`
	R frontend.Variable
}

func (circuit *g1varScalarMul) Define(api frontend.API) error {
	expected, err := NewG1Affine(api)
	if err != nil {
		return fmt.Errorf("new G1Affine")
	}
	expected.Set(circuit.A)
	expected.varScalarMul(circuit.A, circuit.R)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestVarScalarMulG1(t *testing.T) {
	// sample random point
	_a := randomPointG1()
	var a, c bls12377.G1Affine
	a.FromJacobian(&_a)

	// create the cs
	var circuit, witness g1varScalarMul
	var r fr.Element
	r.SetRandom()
	witness.R = r.String()
	// assign the inputs
	witness.A = FromG1Affine(a)
	// compute the result
	var br big.Int
	_a.ScalarMultiplication(&_a, r.ToBigIntRegular(&br))
	c.FromJacobian(&_a)
	witness.C = FromG1Affine(c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type g1ScalarMul struct {
	A    G1Affine
	C    G1Affine `gnark:",public"`
	Rvar frontend.Variable
	Rcon fr.Element
}

func (circuit *g1ScalarMul) Define(api frontend.API) error {
	expected, err := NewG1Affine(api)
	if err != nil {
		return fmt.Errorf("new G1Affine")
	}
	expected2, err := NewG1Affine(api)
	if err != nil {
		return fmt.Errorf("new G1Affine")
	}
	expected.ScalarMul(circuit.A, circuit.Rvar)
	expected.MustBeEqual(circuit.C)
	expected2.ScalarMul(circuit.A, circuit.Rcon)
	expected2.MustBeEqual(circuit.C)
	return nil
}

func TestScalarMulG1(t *testing.T) {
	// sample random point
	_a := randomPointG1()
	var a, c bls12377.G1Affine
	a.FromJacobian(&_a)

	// create the cs
	var circuit, witness g1ScalarMul
	var r fr.Element
	r.SetRandom()
	witness.Rvar = r.String()
	circuit.Rcon = r
	// assign the inputs
	witness.A = FromG1Affine(a)
	// compute the result
	var br big.Int
	_a.ScalarMultiplication(&_a, r.ToBigIntRegular(&br))
	c.FromJacobian(&_a)
	witness.C = FromG1Affine(c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

func randomPointG1() bls12377.G1Jac {

	p1, _, _, _ := bls12377.Generators()

	var r1 fr.Element
	var b big.Int
	r1.SetRandom()
	p1.ScalarMultiplication(&p1, r1.ToBigIntRegular(&b))

	return p1
}

var ccsBench frontend.CompiledConstraintSystem

func BenchmarkConstScalarMulG1(b *testing.B) {
	var c g1constantScalarMul
	// this is q - 1
	r, ok := new(big.Int).SetString("660539884262666720468348340822774968888139573360124440321458176", 10)
	if !ok {
		b.Fatal("invalid integer")
	}
	c.R = r
	b.Run("groth16", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccsBench, _ = frontend.Compile(ecc.BW6_761, backend.GROTH16, &c)
		}

	})
	b.Log("groth16", ccsBench.GetNbConstraints())
	b.Run("plonk", func(b *testing.B) {
		var err error
		for i := 0; i < b.N; i++ {
			ccsBench, err = frontend.Compile(ecc.BW6_761, backend.PLONK, &c)
			if err != nil {
				b.Fatal(err)
			}
		}

	})
	b.Log("plonk", ccsBench.GetNbConstraints())

}

func BenchmarkVarScalarMulG1(b *testing.B) {
	var c g1varScalarMul
	// this is q - 1
	r, ok := new(big.Int).SetString("660539884262666720468348340822774968888139573360124440321458176", 10)
	if !ok {
		b.Fatal("invalid integer")
	}
	c.R = r
	b.Run("groth16", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccsBench, _ = frontend.Compile(ecc.BW6_761, backend.GROTH16, &c)
		}

	})
	b.Log("groth16", ccsBench.GetNbConstraints())
	b.Run("plonk", func(b *testing.B) {
		var err error
		for i := 0; i < b.N; i++ {
			ccsBench, err = frontend.Compile(ecc.BW6_761, backend.PLONK, &c)
			if err != nil {
				b.Fatal(err)
			}
		}

	})
	b.Log("plonk", ccsBench.GetNbConstraints())

}
