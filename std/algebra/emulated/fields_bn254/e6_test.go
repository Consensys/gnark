package fields_bn254

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type e6Add struct {
	A, B, C E6
}

func (circuit *e6Add) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt6(ba)
	expected := e.Add(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestAddFp6(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bn254.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	var witness e6Add
	witness.A.assign(&a)
	witness.B.assign(&b)
	witness.C.assign(&c)

	err := test.IsSolved(&e6Add{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6Sub struct {
	A, B, C E6
}

func (circuit *e6Sub) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt6(ba)
	expected := e.Sub(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestSubFp6(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bn254.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)

	var witness e6Sub
	witness.A.assign(&a)
	witness.B.assign(&b)
	witness.C.assign(&c)

	err := test.IsSolved(&e6Sub{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6Mul struct {
	A, B, C E6
}

func (circuit *e6Mul) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt6(ba)

	expected := e.Mul(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestMulFp6(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bn254.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	var witness e6Mul
	witness.A.assign(&a)
	witness.B.assign(&b)
	witness.C.assign(&c)

	err := test.IsSolved(&e6Mul{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6Square struct {
	A, C E6
}

func (circuit *e6Square) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt6(ba)

	expected := e.Square(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestSquareFp6(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E6
	_, _ = a.SetRandom()
	c.Square(&a)

	var witness e6Square
	witness.A.assign(&a)
	witness.C.assign(&c)

	err := test.IsSolved(&e6Square{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6MulByNonResidue struct {
	A E6
	C E6 `gnark:",public"`
}

func (circuit *e6MulByNonResidue) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt6(ba)
	expected := e.MulByNonResidue(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestMulFp6ByNonResidue(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E6
	_, _ = a.SetRandom()
	c.MulByNonResidue(&a)

	var witness e6MulByNonResidue
	witness.A.assign(&a)
	witness.C.assign(&c)

	err := test.IsSolved(&e6MulByNonResidue{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6MulByE2 struct {
	A E6
	B E2
	C E6 `gnark:",public"`
}

func (circuit *e6MulByE2) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt6(ba)
	expected := e.MulByE2(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestMulFp6ByE2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E6
	var b bn254.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.MulByE2(&a, &b)

	var witness e6MulByE2
	witness.A.assign(&a)
	witness.B.assign(&b)
	witness.C.assign(&c)

	err := test.IsSolved(&e6MulByE2{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6MulBy01 struct {
	A      E6
	C0, C1 E2
	C      E6 `gnark:",public"`
}

func (circuit *e6MulBy01) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt6(ba)
	expected := e.MulBy01(&circuit.A, &circuit.C0, &circuit.C1)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestMulFp6By01(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E6
	var C0, C1 bn254.E2
	_, _ = a.SetRandom()
	_, _ = C0.SetRandom()
	_, _ = C1.SetRandom()
	c.Set(&a)
	c.MulBy01(&C0, &C1)

	var witness e6MulBy01
	witness.A.assign(&a)
	witness.C0.assign(&C0)
	witness.C1.assign(&C1)
	witness.C.assign(&c)

	err := test.IsSolved(&e6MulBy01{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6Neg struct {
	A E6
	C E6 `gnark:",public"`
}

func (circuit *e6Neg) Define(api frontend.API) error {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt6(ba)
	expected := e.Neg(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestNegFp6(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E6
	_, _ = a.SetRandom()
	c.Neg(&a)

	var witness e6Neg
	witness.A.assign(&a)
	witness.C.assign(&c)

	err := test.IsSolved(&e6Neg{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6Inverse struct {
	A E6
	C E6 `gnark:",public"`
}

func (circuit *e6Inverse) Define(api frontend.API) error {

	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := NewExt6(ba)
	expected := e.Inverse(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestInverseFp6(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bn254.E6
	_, _ = a.SetRandom()
	c.Inverse(&a)

	var witness e6Inverse
	witness.A.assign(&a)
	witness.C.assign(&c)

	err := test.IsSolved(&e6Inverse{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
