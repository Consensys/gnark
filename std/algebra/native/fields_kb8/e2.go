package fields_kb8

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark/frontend"
)

var uSquare = koalabear.NewElement(3)

type E2 struct {
	A0, A1 frontend.Variable
}

func (e *E2) SetZero() *E2 {
	e.A0 = 0
	e.A1 = 0
	return e
}

func (e *E2) SetOne() *E2 {
	e.A0 = 1
	e.A1 = 0
	return e
}

func (e *E2) IsZero(api frontend.API) frontend.Variable {
	return api.And(api.IsZero(e.A0), api.IsZero(e.A1))
}

func (e *E2) assign(e1 []frontend.Variable) {
	e.A0 = e1[0]
	e.A1 = e1[1]
}

func (e *E2) Neg(api frontend.API, e1 E2) *E2 {
	e.A0 = api.Neg(e1.A0)
	e.A1 = api.Neg(e1.A1)
	return e
}

func (e *E2) Add(api frontend.API, e1, e2 E2) *E2 {
	e.A0 = api.Add(e1.A0, e2.A0)
	e.A1 = api.Add(e1.A1, e2.A1)
	return e
}

func (e *E2) Double(api frontend.API, e1 E2) *E2 {
	e.A0 = api.Mul(e1.A0, 2)
	e.A1 = api.Mul(e1.A1, 2)
	return e
}

func (e *E2) Sub(api frontend.API, e1, e2 E2) *E2 {
	e.A0 = api.Sub(e1.A0, e2.A0)
	e.A1 = api.Sub(e1.A1, e2.A1)
	return e
}

func (e *E2) Mul(api frontend.API, e1, e2 E2) *E2 {
	// Schoolbook multiplication: cheaper than Karatsuba in Plonk where M = A = 1 gate.
	// c0 = a0*b0 + β*a1*b1, c1 = a0*b1 + a1*b0  (β = uSquare = 3, free as constant mul)
	a0b0 := api.Mul(e1.A0, e2.A0)
	a1b1 := api.Mul(e1.A1, e2.A1)
	a0b1 := api.Mul(e1.A0, e2.A1)
	a1b0 := api.Mul(e1.A1, e2.A0)
	e.A0 = api.Add(a0b0, api.Mul(uSquare, a1b1))
	e.A1 = api.Add(a0b1, a1b0)
	return e
}

func (e *E2) Square(api frontend.API, x E2) *E2 {
	// Algorithm 22 from https://eprint.iacr.org/2010/354.pdf adapted to u^2 = 3.
	c0 := api.Add(x.A0, x.A1)
	c2 := api.Mul(x.A1, uSquare)
	c2 = api.Add(c2, x.A0)

	c0 = api.Mul(c0, c2)
	c2 = api.Mul(x.A0, x.A1)
	c2 = api.Mul(c2, 2)
	e.A1 = c2
	c2 = api.Mul(c2, 2)
	e.A0 = api.Sub(c0, c2)
	return e
}

func (e *E2) MulByFp(api frontend.API, e1 E2, c interface{}) *E2 {
	e.A0 = api.Mul(e1.A0, c)
	e.A1 = api.Mul(e1.A1, c)
	return e
}

func (e *E2) MulByNonResidue(api frontend.API, e1 E2) *E2 {
	x := e1.A0
	e.A0 = api.Mul(e1.A1, uSquare)
	e.A1 = x
	return e
}

func (e *E2) AssertIsEqual(api frontend.API, other E2) {
	api.AssertIsEqual(e.A0, other.A0)
	api.AssertIsEqual(e.A1, other.A1)
}

func (e *E2) IsEqual(api frontend.API, other E2) frontend.Variable {
	return api.And(api.IsZero(api.Sub(e.A0, other.A0)), api.IsZero(api.Sub(e.A1, other.A1)))
}

func (e *E2) Select(api frontend.API, b frontend.Variable, r1, r2 E2) *E2 {
	e.A0 = api.Select(b, r1.A0, r2.A0)
	e.A1 = api.Select(b, r1.A1, r2.A1)
	return e
}

func (e *E2) Assign(a *extensions.E2) {
	e.A0 = a.A0
	e.A1 = a.A1
}
