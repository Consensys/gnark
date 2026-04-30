package fields_kb8

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type e4Add struct{ A, B, C E4 }

func (c *e4Add) Define(api frontend.API) error {
	var e E4
	e.Add(api, c.A, c.B)
	e.AssertIsEqual(api, c.C)
	return nil
}
func TestAddE4(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E4
	a.SetRandom()
	b.SetRandom()
	c.Add(&a, &b)
	var w e4Add
	w.A.Assign(&a)
	w.B.Assign(&b)
	w.C.Assign(&c)
	assert.CheckCircuit(&e4Add{}, test.WithValidAssignment(&w), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}

type e4Sub struct{ A, B, C E4 }

func (c *e4Sub) Define(api frontend.API) error {
	var e E4
	e.Sub(api, c.A, c.B)
	e.AssertIsEqual(api, c.C)
	return nil
}
func TestSubE4(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E4
	a.SetRandom()
	b.SetRandom()
	c.Sub(&a, &b)
	var w e4Sub
	w.A.Assign(&a)
	w.B.Assign(&b)
	w.C.Assign(&c)
	assert.CheckCircuit(&e4Sub{}, test.WithValidAssignment(&w), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}

type e4Mul struct{ A, B, C E4 }

func (c *e4Mul) Define(api frontend.API) error {
	var e E4
	e.Mul(api, c.A, c.B)
	e.AssertIsEqual(api, c.C)
	return nil
}
func TestMulE4(t *testing.T) {
	assert := test.NewAssert(t)
	var a, b, c extensions.E4
	a.SetRandom()
	b.SetRandom()
	c.Mul(&a, &b)
	var w e4Mul
	w.A.Assign(&a)
	w.B.Assign(&b)
	w.C.Assign(&c)
	assert.CheckCircuit(&e4Mul{}, test.WithValidAssignment(&w), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}
