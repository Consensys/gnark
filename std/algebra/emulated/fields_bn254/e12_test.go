package fields_bn254

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type e12Convert struct {
	A E12
}

func (circuit *e12Convert) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.e12RoundTrip(&circuit.A)
	e.AssertIsEqual(expected, &circuit.A)
	return nil
}

func TestConvertFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a bn254.E12
	_, _ = a.SetRandom()

	witness := e12Convert{
		A: FromE12(&a),
	}

	err := test.IsSolved(&e12Convert{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12Add struct {
	A, B, C E12
}

func (circuit *e12Add) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Add(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestAddFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bn254.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	witness := e12Add{
		A: FromE12(&a),
		B: FromE12(&b),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Add{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12Sub struct {
	A, B, C E12
}

func (circuit *e12Sub) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Sub(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestSubFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bn254.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)

	witness := e12Sub{
		A: FromE12(&a),
		B: FromE12(&b),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Sub{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12Mul struct {
	A, B, C E12
}

func (circuit *e12Mul) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Mul(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestMulFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bn254.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	witness := e12Mul{
		A: FromE12(&a),
		B: FromE12(&b),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Mul{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12Div struct {
	A, B, C E12
}

func (circuit *e12Div) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.DivUnchecked(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestDivFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bn254.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Div(&a, &b)

	witness := e12Div{
		A: FromE12(&a),
		B: FromE12(&b),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Div{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12Square struct {
	A, C E12
}

func (circuit *e12Square) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Square(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestSquareFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()
	c.Square(&a)

	witness := e12Square{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Square{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12Conjugate struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *e12Conjugate) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Conjugate(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestConjugateFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()
	c.Conjugate(&a)

	witness := e12Conjugate{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Conjugate{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e12Inverse struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *e12Inverse) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Inverse(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestInverseFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()
	c.Inverse(&a)

	witness := e12Inverse{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Inverse{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type Frobenius struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *Frobenius) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Frobenius(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestFrobenius(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()

	c.Frobenius(&a)

	witness := Frobenius{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&Frobenius{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type FrobeniusSquare struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *FrobeniusSquare) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.FrobeniusSquare(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestFrobeniusSquare(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()

	c.FrobeniusSquare(&a)

	witness := FrobeniusSquare{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&FrobeniusSquare{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type FrobeniusCube struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *FrobeniusCube) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.FrobeniusCube(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestFrobeniusCube(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()

	c.FrobeniusCube(&a)

	witness := FrobeniusCube{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&FrobeniusCube{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e12MulBy01379 struct {
	A    E12 `gnark:",public"`
	W    E12
	B, C E2
}

func (circuit *e12MulBy01379) Define(api frontend.API) error {
	e := NewExt12(api)
	res := e.MulBy01379(&circuit.A, &circuit.B, &circuit.C)
	e.AssertIsEqual(res, &circuit.W)
	return nil
}

func TestFp12MulBy01379(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, w bn254.E12
	_, _ = a.SetRandom()
	var one, b, c bn254.E2
	one.SetOne()
	_, _ = b.SetRandom()
	_, _ = c.SetRandom()
	w.Set(&a)
	w.MulBy034(&one, &b, &c)

	witness := e12MulBy01379{
		A: FromE12(&a),
		B: FromE2(&b),
		C: FromE2(&c),
		W: FromE12(&w),
	}

	err := test.IsSolved(&e12MulBy01379{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}
