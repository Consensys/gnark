package fields_bls12381

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type e2Add struct {
	A, B, C E2
}

func (circuit *e2Add) Define(api frontend.API) error {
	e := NewExt2(api)
	expected := e.Add(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestAddFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bls12381.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	witness := e2Add{
		A: FromE2(&a),
		B: FromE2(&b),
		C: FromE2(&c),
	}

	err := test.IsSolved(&e2Add{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2Sub struct {
	A, B, C E2
}

func (circuit *e2Sub) Define(api frontend.API) error {
	e := NewExt2(api)
	expected := e.Sub(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestSubFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bls12381.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)

	witness := e2Sub{
		A: FromE2(&a),
		B: FromE2(&b),
		C: FromE2(&c),
	}

	err := test.IsSolved(&e2Sub{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2Double struct {
	A, C E2
}

func (circuit *e2Double) Define(api frontend.API) error {
	e := NewExt2(api)
	expected := e.Double(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestDoubleFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bls12381.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Double(&a)

	witness := e2Double{
		A: FromE2(&a),
		C: FromE2(&c),
	}

	err := test.IsSolved(&e2Double{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2Mul struct {
	A, B, C E2
}

func (circuit *e2Mul) Define(api frontend.API) error {
	e := NewExt2(api)
	expected := e.Mul(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestMulFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bls12381.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	witness := e2Mul{
		A: FromE2(&a),
		B: FromE2(&b),
		C: FromE2(&c),
	}

	err := test.IsSolved(&e2Mul{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2Square struct {
	A, C E2
}

func (circuit *e2Square) Define(api frontend.API) error {
	e := NewExt2(api)
	expected := e.Square(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestSquareFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E2
	_, _ = a.SetRandom()
	c.Square(&a)

	witness := e2Square{
		A: FromE2(&a),
		C: FromE2(&c),
	}

	err := test.IsSolved(&e2Square{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2Div struct {
	A, B, C E2
}

func (circuit *e2Div) Define(api frontend.API) error {
	e := NewExt2(api)
	expected := e.DivUnchecked(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestDivFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bls12381.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Div(&a, &b)

	witness := e2Div{
		A: FromE2(&a),
		B: FromE2(&b),
		C: FromE2(&c),
	}

	err := test.IsSolved(&e2Div{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2MulByElement struct {
	A E2
	B baseEl
	C E2 `gnark:",public"`
}

func (circuit *e2MulByElement) Define(api frontend.API) error {
	e := NewExt2(api)
	expected := e.MulByElement(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestMulByElement(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E2
	var b fp.Element
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.MulByElement(&a, &b)

	witness := e2MulByElement{
		A: FromE2(&a),
		B: emulated.ValueOf[emulated.BLS12381Fp](b),
		C: FromE2(&c),
	}

	err := test.IsSolved(&e2MulByElement{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2MulByNonResidue struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *e2MulByNonResidue) Define(api frontend.API) error {
	e := NewExt2(api)
	expected := e.MulByNonResidue(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestMulFp2ByNonResidue(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E2
	_, _ = a.SetRandom()
	c.MulByNonResidue(&a)

	witness := e2MulByNonResidue{
		A: FromE2(&a),
		C: FromE2(&c),
	}

	err := test.IsSolved(&e2MulByNonResidue{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2Neg struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *e2Neg) Define(api frontend.API) error {
	e := NewExt2(api)
	expected := e.Neg(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestNegFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E2
	_, _ = a.SetRandom()
	c.Neg(&a)

	witness := e2Neg{
		A: FromE2(&a),
		C: FromE2(&c),
	}

	err := test.IsSolved(&e2Neg{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e2Conjugate struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *e2Conjugate) Define(api frontend.API) error {
	e := NewExt2(api)
	expected := e.Conjugate(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestConjugateFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E2
	_, _ = a.SetRandom()
	c.Conjugate(&a)

	witness := e2Conjugate{
		A: FromE2(&a),
		C: FromE2(&c),
	}

	err := test.IsSolved(&e2Conjugate{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e2Inverse struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *e2Inverse) Define(api frontend.API) error {
	e := NewExt2(api)
	expected := e.Inverse(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestInverseFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E2
	_, _ = a.SetRandom()
	c.Inverse(&a)

	witness := e2Inverse{
		A: FromE2(&a),
		C: FromE2(&c),
	}

	err := test.IsSolved(&e2Inverse{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
