package fields_bn254

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type e12Add struct {
	A, B, C E12
}

func (circuit *e12Add) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)
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
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)
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
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)

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
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)

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
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)

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

type e12CycloSquare struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *e12CycloSquare) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)
	expected := e.CyclotomicSquare(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestFp12CyclotomicSquare(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()

	// put a in the cyclotomic subgroup
	var tmp bn254.E12
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)
	c.CyclotomicSquare(&a)

	witness := e12CycloSquare{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12CycloSquare{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e12CycloSquareKarabina struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *e12CycloSquareKarabina) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)
	expected := e.CyclotomicSquareCompressed(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestFp12CyclotomicSquareKarabina(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()

	// put a in the cyclotomic subgroup
	var tmp bn254.E12
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)
	c.CyclotomicSquareCompressed(&a)

	witness := e12CycloSquareKarabina{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12CycloSquareKarabina{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e12CycloSquareKarabinaAndDecompress struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *e12CycloSquareKarabinaAndDecompress) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)
	expected := e.CyclotomicSquareCompressed(&circuit.A)
	expected = e.DecompressKarabina(expected)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestFp12CyclotomicSquareKarabinaAndDecompress(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()

	// put a in the cyclotomic subgroup
	var tmp bn254.E12
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)
	c.CyclotomicSquareCompressed(&a)
	c.DecompressKarabina(&c)

	witness := e12CycloSquareKarabina{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12CycloSquareKarabinaAndDecompress{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e12Conjugate struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *e12Conjugate) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)
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
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)
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

type e12Expt struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *e12Expt) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)
	expected := e.Expt(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestFp12Expt(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()

	// put a in the cyclotomic subgroup
	var tmp bn254.E12
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)

	c.Expt(&a)

	witness := e12Expt{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Expt{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e12Frobenius struct {
	A, C E12
}

func (circuit *e12Frobenius) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)

	expected := e.Frobenius(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestFrobeniusFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()
	c.Frobenius(&a)

	witness := e12Frobenius{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Frobenius{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12FrobeniusSquare struct {
	A, C E12
}

func (circuit *e12FrobeniusSquare) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)

	expected := e.FrobeniusSquare(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestFrobeniusSquareFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()
	c.FrobeniusSquare(&a)

	witness := e12FrobeniusSquare{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12FrobeniusSquare{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12FrobeniusCube struct {
	A, C E12
}

func (circuit *e12FrobeniusCube) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)

	expected := e.FrobeniusCube(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestFrobeniusCubeFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E12
	_, _ = a.SetRandom()
	c.FrobeniusCube(&a)

	witness := e12FrobeniusCube{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12FrobeniusCube{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12MulBy034 struct {
	A    E12 `gnark:",public"`
	W    E12
	B, C E2
}

func (circuit *e12MulBy034) Define(api frontend.API) error {

	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt12(ba)
	res := e.MulBy034(&circuit.A, &circuit.B, &circuit.C)
	e.AssertIsEqual(res, &circuit.W)
	return nil
}

func TestFp12MulBy034(t *testing.T) {

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

	witness := e12MulBy034{
		A: FromE12(&a),
		B: FromE2(&b),
		C: FromE2(&c),
		W: FromE12(&w),
	}

	err := test.IsSolved(&e12MulBy034{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}
