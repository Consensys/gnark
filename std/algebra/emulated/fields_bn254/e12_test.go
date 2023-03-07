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

	var witness e12Add
	witness.A.assign(&a)
	witness.B.assign(&b)
	witness.C.assign(&c)

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

	var witness e12Sub
	witness.A.assign(&a)
	witness.B.assign(&b)
	witness.C.assign(&c)

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

	var witness e12Mul
	witness.A.assign(&a)
	witness.B.assign(&b)
	witness.C.assign(&c)

	err := test.IsSolved(&e12Mul{}, &witness, ecc.BN254.ScalarField())
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

	var witness e12Square
	witness.A.assign(&a)
	witness.C.assign(&c)

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
	u := e.Square(&circuit.A)
	v := e.CyclotomicSquare(&circuit.A)
	e.AssertIsEqual(u, v)
	e.AssertIsEqual(u, &circuit.C)
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

	var witness e12Conjugate
	witness.A.assign(&a)
	witness.C.assign(&c)

	err := test.IsSolved(&e12CycloSquare{}, &witness, ecc.BN254.ScalarField())
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

	var witness e12Conjugate
	witness.A.assign(&a)
	witness.C.assign(&c)

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

	var witness e12Inverse
	witness.A.assign(&a)
	witness.C.assign(&c)

	err := test.IsSolved(&e12Inverse{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
