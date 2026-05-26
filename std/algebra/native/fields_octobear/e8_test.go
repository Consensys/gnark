package fields_octobear

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type e8Add struct{ A, B, C E8 }

func (c *e8Add) Define(api frontend.API) error {
	var e E8
	e.Add(api, c.A, c.B)
	e.AssertIsEqual(api, c.C)
	return nil
}
func TestAddE8(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E8
	a.SetRandom()
	b.SetRandom()
	c.Add(&a, &b)
	var w e8Add
	w.A.Assign(&a)
	w.B.Assign(&b)
	w.C.Assign(&c)
	assert.CheckCircuit(&e8Add{}, test.WithValidAssignment(&w), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}

type e8Sub struct{ A, B, C E8 }

func (c *e8Sub) Define(api frontend.API) error {
	var e E8
	e.Sub(api, c.A, c.B)
	e.AssertIsEqual(api, c.C)
	return nil
}
func TestSubE8(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E8
	a.SetRandom()
	b.SetRandom()
	c.Sub(&a, &b)
	var w e8Sub
	w.A.Assign(&a)
	w.B.Assign(&b)
	w.C.Assign(&c)
	assert.CheckCircuit(&e8Sub{}, test.WithValidAssignment(&w), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}

type e8Mul struct{ A, B, C E8 }

func (c *e8Mul) Define(api frontend.API) error {
	var e E8
	e.Mul(api, c.A, c.B)
	e.AssertIsEqual(api, c.C)
	return nil
}
func TestMulE8(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E8
	a.SetRandom()
	b.SetRandom()
	c.Mul(&a, &b)
	var w e8Mul
	w.A.Assign(&a)
	w.B.Assign(&b)
	w.C.Assign(&c)
	assert.CheckCircuit(&e8Mul{}, test.WithValidAssignment(&w), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}

type e8Square struct{ A, C E8 }

func (c *e8Square) Define(api frontend.API) error {
	var e E8
	e.Square(api, c.A)
	e.AssertIsEqual(api, c.C)
	return nil
}
func TestSquareE8(t *testing.T) {
	assert := test.NewAssert(t)
	var a, c extensions.E8
	a.SetRandom()
	c.Square(&a)
	var w e8Square
	w.A.Assign(&a)
	w.C.Assign(&c)
	assert.CheckCircuit(&e8Square{}, test.WithValidAssignment(&w), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}

type e8Inv struct{ A, C E8 }

func (c *e8Inv) Define(api frontend.API) error {
	var e E8
	e.Inverse(api, c.A)
	e.AssertIsEqual(api, c.C)
	return nil
}
func TestInverseE8(t *testing.T) {
	assert := test.NewAssert(t)
	var a, c extensions.E8
	a.SetRandom()
	c.Inverse(&a)
	var w e8Inv
	w.A.Assign(&a)
	w.C.Assign(&c)
	assert.CheckCircuit(&e8Inv{}, test.WithValidAssignment(&w), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}
