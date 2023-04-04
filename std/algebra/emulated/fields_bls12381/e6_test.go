package fields_bls12381

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type e6Add struct {
	A, B, C E6
}

func (circuit *e6Add) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.Add(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestAddFp6(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bls12381.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	witness := e6Add{
		A: FromE6(&a),
		B: FromE6(&b),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6Add{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6Sub struct {
	A, B, C E6
}

func (circuit *e6Sub) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.Sub(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestSubFp6(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bls12381.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)

	witness := e6Sub{
		A: FromE6(&a),
		B: FromE6(&b),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6Sub{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6Mul struct {
	A, B, C E6
}

func (circuit *e6Mul) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.Mul(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestMulFp6(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bls12381.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	witness := e6Mul{
		A: FromE6(&a),
		B: FromE6(&b),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6Mul{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6Square struct {
	A, C E6
}

func (circuit *e6Square) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.Square(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestSquareFp6(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E6
	_, _ = a.SetRandom()
	c.Square(&a)

	witness := e6Square{
		A: FromE6(&a),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6Square{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6Div struct {
	A, B, C E6
}

func (circuit *e6Div) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.DivUnchecked(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestDivFp6(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bls12381.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Div(&a, &b)

	witness := e6Div{
		A: FromE6(&a),
		B: FromE6(&b),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6Div{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6MulByNonResidue struct {
	A E6
	C E6 `gnark:",public"`
}

func (circuit *e6MulByNonResidue) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.MulByNonResidue(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestMulFp6ByNonResidue(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E6
	_, _ = a.SetRandom()
	c.MulByNonResidue(&a)

	witness := e6MulByNonResidue{
		A: FromE6(&a),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6MulByNonResidue{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6MulByE2 struct {
	A E6
	B E2
	C E6 `gnark:",public"`
}

func (circuit *e6MulByE2) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.MulByE2(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestMulFp6ByE2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E6
	var b bls12381.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.MulByE2(&a, &b)

	witness := e6MulByE2{
		A: FromE6(&a),
		B: FromE2(&b),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6MulByE2{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6MulBy01 struct {
	A      E6
	C0, C1 E2
	C      E6 `gnark:",public"`
}

func (circuit *e6MulBy01) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.MulBy01(&circuit.A, &circuit.C0, &circuit.C1)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestMulFp6By01(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E6
	var C0, C1 bls12381.E2
	_, _ = a.SetRandom()
	_, _ = C0.SetRandom()
	_, _ = C1.SetRandom()
	c.Set(&a)
	c.MulBy01(&C0, &C1)

	witness := e6MulBy01{
		A:  FromE6(&a),
		C0: FromE2(&C0),
		C1: FromE2(&C1),
		C:  FromE6(&c),
	}

	err := test.IsSolved(&e6MulBy01{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6Neg struct {
	A E6
	C E6 `gnark:",public"`
}

func (circuit *e6Neg) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.Neg(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestNegFp6(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E6
	_, _ = a.SetRandom()
	c.Neg(&a)

	witness := e6Neg{
		A: FromE6(&a),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6Neg{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6Inverse struct {
	A E6
	C E6 `gnark:",public"`
}

func (circuit *e6Inverse) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.Inverse(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestInverseFp6(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E6
	_, _ = a.SetRandom()
	c.Inverse(&a)

	witness := e6Inverse{
		A: FromE6(&a),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6Inverse{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
