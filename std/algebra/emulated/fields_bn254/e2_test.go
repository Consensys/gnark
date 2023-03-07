package fields_bn254

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type e2Add struct {
	A, B, C E2
}

func (circuit *e2Add) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt2(ba)
	expected := e.Add(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestAddFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bn254.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	var witness e2Add
	witness.A.assign(&a)
	witness.B.assign(&b)
	witness.C.assign(&c)

	err := test.IsSolved(&e2Add{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2Sub struct {
	A, B, C E2
}

func (circuit *e2Sub) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt2(ba)
	expected := e.Sub(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestSubFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bn254.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)

	var witness e2Sub
	witness.A.assign(&a)
	witness.B.assign(&b)
	witness.C.assign(&c)

	err := test.IsSolved(&e2Sub{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2Double struct {
	A, C E2
}

func (circuit *e2Double) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt2(ba)
	expected := e.Double(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestDoubleFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bn254.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Double(&a)

	var witness e2Double
	witness.A.assign(&a)
	witness.C.assign(&c)

	err := test.IsSolved(&e2Double{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2Halve struct {
	A, C E2
}

func (circuit *e2Halve) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt2(ba)
	expected := e.Halve(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestHalveFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bn254.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c = a
	c.Halve()

	var witness e2Halve
	witness.A.assign(&a)
	witness.C.assign(&c)

	err := test.IsSolved(&e2Halve{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2Mul struct {
	A, B, C E2
}

func (circuit *e2Mul) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt2(ba)

	expected := e.Mul(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestMulFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bn254.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	var witness e2Mul
	witness.A.assign(&a)
	witness.B.assign(&b)
	witness.C.assign(&c)

	err := test.IsSolved(&e2Mul{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2Square struct {
	A, C E2
}

func (circuit *e2Square) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt2(ba)

	expected := e.Square(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestSquareFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E2
	_, _ = a.SetRandom()
	c.Square(&a)

	var witness e2Square
	witness.A.assign(&a)
	witness.C.assign(&c)

	err := test.IsSolved(&e2Square{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2MulByElement struct {
	A E2
	B baseEl
	C E2 `gnark:",public"`
}

func (circuit *e2MulByElement) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt2(ba)
	expected := e.MulByElement(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestMulByElement(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E2
	var b fp.Element
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.MulByElement(&a, &b)

	var witness e2MulByElement
	witness.A.assign(&a)
	witness.B = emulated.ValueOf[emulated.BN254Fp](b)
	witness.C.assign(&c)

	err := test.IsSolved(&e2MulByElement{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2MulBybTwistCurveCoeff struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *e2MulBybTwistCurveCoeff) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt2(ba)
	expected := e.MulBybTwistCurveCoeff(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestMulFp2BybTwistCurveCoeff(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E2
	_, _ = a.SetRandom()
	c.MulBybTwistCurveCoeff(&a)

	var witness e2MulBybTwistCurveCoeff
	witness.A.assign(&a)
	witness.C.assign(&c)

	err := test.IsSolved(&e2MulBybTwistCurveCoeff{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2MulByNonResidue struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *e2MulByNonResidue) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt2(ba)
	expected := e.MulByNonResidue(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestMulFp2ByNonResidue(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E2
	_, _ = a.SetRandom()
	c.MulByNonResidue(&a)

	var witness e2MulByNonResidue
	witness.A.assign(&a)
	witness.C.assign(&c)

	err := test.IsSolved(&e2MulByNonResidue{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2MulByNonResidueInv struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *e2MulByNonResidueInv) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt2(ba)
	expected := e.MulByNonResidueInv(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestMulFp2ByNonResidueInv(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E2
	_, _ = a.SetRandom()
	c.MulByNonResidueInv(&a)

	var witness e2MulByNonResidueInv
	witness.A.assign(&a)
	witness.C.assign(&c)

	err := test.IsSolved(&e2MulByNonResidueInv{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2Neg struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *e2Neg) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt2(ba)
	expected := e.Neg(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestNegFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E2
	_, _ = a.SetRandom()
	c.Neg(&a)

	var witness e2Neg
	witness.A.assign(&a)
	witness.C.assign(&c)

	err := test.IsSolved(&e2Neg{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e2Conjugate struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *e2Conjugate) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt2(ba)
	expected := e.Conjugate(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestConjugateFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E2
	_, _ = a.SetRandom()
	c.Conjugate(&a)

	var witness e2Conjugate
	witness.A.assign(&a)
	witness.C.assign(&c)

	err := test.IsSolved(&e2Conjugate{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e2Inverse struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *e2Inverse) Define(api frontend.API) error {

	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt2(ba)
	expected := e.Inverse(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestInverseFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E2
	_, _ = a.SetRandom()
	c.Inverse(&a)

	var witness e2Inverse
	witness.A.assign(&a)
	witness.C.assign(&c)

	err := test.IsSolved(&e2Inverse{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
