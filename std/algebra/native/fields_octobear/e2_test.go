package fields_octobear

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type e2Add struct{ A, B, C E2 }

func (c *e2Add) Define(api frontend.API) error {
	var e E2
	e.Add(api, c.A, c.B)
	e.AssertIsEqual(api, c.C)
	return nil
}
func TestAddE2(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E2
	a.SetRandom()
	b.SetRandom()
	c.Add(&a, &b)
	var w e2Add
	w.A.Assign(&a)
	w.B.Assign(&b)
	w.C.Assign(&c)
	assert.CheckCircuit(&e2Add{}, test.WithValidAssignment(&w), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}

type e2Sub struct{ A, B, C E2 }

func (c *e2Sub) Define(api frontend.API) error {
	var e E2
	e.Sub(api, c.A, c.B)
	e.AssertIsEqual(api, c.C)
	return nil
}
func TestSubE2(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E2
	a.SetRandom()
	b.SetRandom()
	c.Sub(&a, &b)
	var w e2Sub
	w.A.Assign(&a)
	w.B.Assign(&b)
	w.C.Assign(&c)
	assert.CheckCircuit(&e2Sub{}, test.WithValidAssignment(&w), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}

type e2Mul struct{ A, B, C E2 }

func (c *e2Mul) Define(api frontend.API) error {
	var e E2
	e.Mul(api, c.A, c.B)
	e.AssertIsEqual(api, c.C)
	return nil
}
func TestMulE2(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E2
	a.SetRandom()
	b.SetRandom()
	c.Mul(&a, &b)
	var w e2Mul
	w.A.Assign(&a)
	w.B.Assign(&b)
	w.C.Assign(&c)
	assert.CheckCircuit(&e2Mul{}, test.WithValidAssignment(&w), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}

type e2Square struct{ A, C E2 }

func (c *e2Square) Define(api frontend.API) error {
	var e E2
	e.Square(api, c.A)
	e.AssertIsEqual(api, c.C)
	return nil
}
func TestSquareE2(t *testing.T) {
	assert := test.NewAssert(t)
	var a, c extensions.E2
	a.SetRandom()
	c.Square(&a)
	var w e2Square
	w.A.Assign(&a)
	w.C.Assign(&c)
	assert.CheckCircuit(&e2Square{}, test.WithValidAssignment(&w), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}
