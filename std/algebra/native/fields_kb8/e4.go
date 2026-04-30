package fields_kb8

import (
	"github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark/frontend"
)

type E4 struct {
	B0, B1 E2
}

func (e *E4) SetZero() *E4 {
	e.B0.SetZero()
	e.B1.SetZero()
	return e
}

func (e *E4) SetOne() *E4 {
	e.B0.SetOne()
	e.B1.SetZero()
	return e
}

func (e *E4) IsZero(api frontend.API) frontend.Variable {
	return api.And(e.B0.IsZero(api), e.B1.IsZero(api))
}

func (e *E4) assign(e1 []frontend.Variable) {
	e.B0.A0 = e1[0]
	e.B0.A1 = e1[1]
	e.B1.A0 = e1[2]
	e.B1.A1 = e1[3]
}

func (e *E4) Neg(api frontend.API, e1 E4) *E4 {
	e.B0.Neg(api, e1.B0)
	e.B1.Neg(api, e1.B1)
	return e
}

func (e *E4) Add(api frontend.API, e1, e2 E4) *E4 {
	e.B0.Add(api, e1.B0, e2.B0)
	e.B1.Add(api, e1.B1, e2.B1)
	return e
}

func (e *E4) Double(api frontend.API, e1 E4) *E4 {
	e.B0.Double(api, e1.B0)
	e.B1.Double(api, e1.B1)
	return e
}

func (e *E4) Sub(api frontend.API, e1, e2 E4) *E4 {
	e.B0.Sub(api, e1.B0, e2.B0)
	e.B1.Sub(api, e1.B1, e2.B1)
	return e
}

func (e *E4) Mul(api frontend.API, e1, e2 E4) *E4 {
	var l1, l2, u, ac, bd E2
	l1.Add(api, e1.B0, e1.B1)
	l2.Add(api, e2.B0, e2.B1)
	u.Mul(api, l1, l2)
	ac.Mul(api, e1.B0, e2.B0)
	bd.Mul(api, e1.B1, e2.B1)
	e.B0.MulByNonResidue(api, bd).Add(api, e.B0, ac)
	e.B1.Add(api, ac, bd)
	e.B1.Sub(api, u, e.B1)
	return e
}

func (e *E4) Square(api frontend.API, x E4) *E4 {
	// Quadratic-extension square over E2 with v^2 = u.
	var c0, c2, tmp, tmpNR E2
	tmp.MulByNonResidue(api, x.B1)
	c0.Add(api, x.B0, x.B1)
	tmp.Add(api, tmp, x.B0)
	c0.Mul(api, c0, tmp)

	c2.Mul(api, x.B0, x.B1)
	e.B1.Double(api, c2)

	tmpNR.MulByNonResidue(api, c2)
	e.B0.Sub(api, c0, c2)
	e.B0.Sub(api, e.B0, tmpNR)
	return e
}

func (e *E4) MulByFp(api frontend.API, e1 E4, c interface{}) *E4 {
	e.B0.MulByFp(api, e1.B0, c)
	e.B1.MulByFp(api, e1.B1, c)
	return e
}

func (e *E4) MulByNonResidue(api frontend.API, e1 E4) *E4 {
	e.B0.MulByNonResidue(api, e1.B1)
	e.B1 = e1.B0
	return e
}

func (e *E4) AssertIsEqual(api frontend.API, other E4) {
	e.B0.AssertIsEqual(api, other.B0)
	e.B1.AssertIsEqual(api, other.B1)
}

func (e *E4) IsEqual(api frontend.API, other E4) frontend.Variable {
	return api.And(e.B0.IsEqual(api, other.B0), e.B1.IsEqual(api, other.B1))
}

func (e *E4) Select(api frontend.API, b frontend.Variable, r1, r2 E4) *E4 {
	e.B0.Select(api, b, r1.B0, r2.B0)
	e.B1.Select(api, b, r1.B1, r2.B1)
	return e
}

func (e *E4) Assign(a *extensions.E4) {
	e.B0.Assign(&a.B0)
	e.B1.Assign(&a.B1)
}
