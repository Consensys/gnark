package fields_bw6761

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type e6Add struct {
	A, B, C E6
}

func (circuit *e6Add) Define(api frontend.API) error {
	var expected E6
	e := NewExt6(api)
	expected = *e.Add(&circuit.A, &circuit.B)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestAddFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b, c bw6761.E6
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
	var expected E6
	e := NewExt6(api)
	expected = *e.Sub(&circuit.A, &circuit.B)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestSubFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b, c bw6761.E6
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

type e6Double struct {
	A, B E6
}

func (circuit *e6Double) Define(api frontend.API) error {
	var expected E6
	e := NewExt6(api)
	expected = *e.Double(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.B)
	return nil
}

func TestDoubleFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Double(&a)

	witness := e6Double{
		A: FromE6(&a),
		B: FromE6(&b),
	}

	err := test.IsSolved(&e6Double{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6MulVariants struct {
	A, B, C E6
}

func (circuit *e6MulVariants) Define(api frontend.API) error {
	e := NewExt6(api)
	expected1 := *e.mulMontgomery6(&circuit.A, &circuit.B)
	expected2 := *e.mulToomCook6(&circuit.A, &circuit.B)
	e.AssertIsEqual(&expected1, &circuit.C)
	e.AssertIsEqual(&expected2, &circuit.C)
	return nil
}

func TestMulVariantsFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b, c bw6761.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	witness := e6MulVariants{
		A: FromE6(&a),
		B: FromE6(&b),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6MulVariants{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6Mul struct {
	A, B, C E6
}

func (circuit *e6Mul) Define(api frontend.API) error {
	var expected E6
	e := NewExt6(api)
	expected = *e.Mul(&circuit.A, &circuit.B)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestMulFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b, c bw6761.E6
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
	A, B E6
}

func (circuit *e6Square) Define(api frontend.API) error {
	var expected E6
	e := NewExt6(api)
	expected = *e.Square(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.B)
	return nil
}

func TestSquareFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Square(&a)

	witness := e6Square{
		A: FromE6(&a),
		B: FromE6(&b),
	}

	err := test.IsSolved(&e6Square{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6Inverse struct {
	A, B E6
}

func (circuit *e6Inverse) Define(api frontend.API) error {
	var expected E6
	e := NewExt6(api)
	expected = *e.Inverse(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.B)
	return nil
}

func TestInverseFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Inverse(&a)

	witness := e6Inverse{
		A: FromE6(&a),
		B: FromE6(&b),
	}

	err := test.IsSolved(&e6Inverse{}, &witness, ecc.BN254.ScalarField())
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
	var a, b, c bw6761.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Inverse(&b)
	c.Mul(&a, &c)

	witness := e6Div{
		A: FromE6(&a),
		B: FromE6(&b),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6Div{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6Conjugate struct {
	A, B E6
}

func (circuit *e6Conjugate) Define(api frontend.API) error {
	var expected E6
	e := NewExt6(api)
	expected = *e.Conjugate(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.B)
	return nil
}

func TestConjugateFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Conjugate(&a)

	witness := e6Conjugate{
		A: FromE6(&a),
		B: FromE6(&b),
	}

	err := test.IsSolved(&e6Conjugate{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6Expt struct {
	A, B E6
}

func (circuit *e6Expt) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.ExpX0Minus1(&circuit.A)
	expected = e.Mul(expected, &circuit.A)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestExptFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()

	// put a in the cyclotomic subgroup
	var tmp bw6761.E6
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.Frobenius(&tmp).Mul(&a, &tmp)

	b.Expt(&a)

	witness := e6Expt{
		A: FromE6(&a),
		B: FromE6(&b),
	}

	err := test.IsSolved(&e6Expt{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6MulBy023 struct {
	A    E6 `gnark:",public"`
	W    E6
	B, C baseEl
}

func (circuit *e6MulBy023) Define(api frontend.API) error {
	e := NewExt6(api)
	res := e.MulBy023(&circuit.A, &circuit.B, &circuit.C)
	e.AssertIsEqual(res, &circuit.W)
	return nil
}

func TestFp6MulBy023(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, w bw6761.E6
	_, _ = a.SetRandom()
	var one, b, c fp.Element
	one.SetOne()
	_, _ = b.SetRandom()
	_, _ = c.SetRandom()
	w.Set(&a)
	w.MulBy014(&b, &c, &one)

	witness := e6MulBy023{
		A: FromE6(&a),
		B: emulated.ValueOf[emulated.BW6761Fp](&b),
		C: emulated.ValueOf[emulated.BW6761Fp](&c),
		W: FromE6(&w),
	}

	err := test.IsSolved(&e6MulBy023{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
