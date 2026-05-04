package fields_kb8

import (
	"github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark/frontend"
)

type E8 struct {
	C0, C1 E4
}

func NewE8(v extensions.E8) E8 {
	return E8{
		C0: E4{
			B0: E2{A0: v.C0.B0.A0, A1: v.C0.B0.A1},
			B1: E2{A0: v.C0.B1.A0, A1: v.C0.B1.A1},
		},
		C1: E4{
			B0: E2{A0: v.C1.B0.A0, A1: v.C1.B0.A1},
			B1: E2{A0: v.C1.B1.A0, A1: v.C1.B1.A1},
		},
	}
}

func (e *E8) SetZero() *E8 {
	e.C0.SetZero()
	e.C1.SetZero()
	return e
}

func (e *E8) SetOne() *E8 {
	e.C0.SetOne()
	e.C1.SetZero()
	return e
}

func (e *E8) IsZero(api frontend.API) frontend.Variable {
	return api.And(e.C0.IsZero(api), e.C1.IsZero(api))
}

func (e *E8) assign(e1 []frontend.Variable) {
	e.C0.B0.A0 = e1[0]
	e.C0.B0.A1 = e1[1]
	e.C0.B1.A0 = e1[2]
	e.C0.B1.A1 = e1[3]
	e.C1.B0.A0 = e1[4]
	e.C1.B0.A1 = e1[5]
	e.C1.B1.A0 = e1[6]
	e.C1.B1.A1 = e1[7]
}

func (e *E8) Neg(api frontend.API, e1 E8) *E8 {
	e.C0.Neg(api, e1.C0)
	e.C1.Neg(api, e1.C1)
	return e
}

func (e *E8) Add(api frontend.API, e1, e2 E8) *E8 {
	e.C0.Add(api, e1.C0, e2.C0)
	e.C1.Add(api, e1.C1, e2.C1)
	return e
}

func (e *E8) Double(api frontend.API, e1 E8) *E8 {
	e.C0.Double(api, e1.C0)
	e.C1.Double(api, e1.C1)
	return e
}

func (e *E8) Sub(api frontend.API, e1, e2 E8) *E8 {
	e.C0.Sub(api, e1.C0, e2.C0)
	e.C1.Sub(api, e1.C1, e2.C1)
	return e
}

func (e *E8) Mul(api frontend.API, e1, e2 E8) *E8 {
	var l1, l2, u, ac, bd E4
	l1.Add(api, e1.C0, e1.C1)
	l2.Add(api, e2.C0, e2.C1)
	u.Mul(api, l1, l2)
	ac.Mul(api, e1.C0, e2.C0)
	bd.Mul(api, e1.C1, e2.C1)
	e.C0.MulByNonResidue(api, bd).Add(api, e.C0, ac)
	e.C1.Add(api, ac, bd)
	e.C1.Sub(api, u, e.C1)
	return e
}

func (e *E8) Square(api frontend.API, x E8) *E8 {
	// Quadratic-extension square over E4 with w^2 = v.
	var c0, c2, tmp, tmpNR E4
	tmp.MulByNonResidue(api, x.C1)
	c0.Add(api, x.C0, x.C1)
	tmp.Add(api, tmp, x.C0)
	c0.Mul(api, c0, tmp)

	c2.Mul(api, x.C0, x.C1)
	e.C1.Double(api, c2)

	tmpNR.MulByNonResidue(api, c2)
	e.C0.Sub(api, c0, c2)
	e.C0.Sub(api, e.C0, tmpNR)
	return e
}

// Cube computes e = x³ directly, cheaper than Square + Mul.
//
// With x = (A, B) in E4[w]/(w²−v):
//
//	x³.C0 = A·(A² + 3v·B²)
//	x³.C1 = B·(3·A² + v·B²)
//
// Cost: 2 E4.Square + 2 E4.Mul + adds ≈ 104 SCS gates
// vs Square(72) + Mul(176) = 176 SCS gates. Saves 72 gates.
func (e *E8) Cube(api frontend.API, x E8) *E8 {
	var a2, b2, t1, t2 E4

	a2.Square(api, x.C0) // A²
	b2.Square(api, x.C1) // B²

	// t1 = A² + 3·v·B² (v·B² = NR(B²), then scale by 3)
	t1.MulByNonResidue(api, b2)
	t1.MulByFp(api, t1, 3)
	t1.Add(api, a2, t1)

	// t2 = 3·A² + v·B²
	t2.MulByNonResidue(api, b2)
	var a2x3 E4
	a2x3.MulByFp(api, a2, 3)
	t2.Add(api, a2x3, t2)

	e.C0.Mul(api, x.C0, t1) // A·t1
	e.C1.Mul(api, x.C1, t2) // B·t2
	return e
}

func (e *E8) MulByFp(api frontend.API, e1 E8, c interface{}) *E8 {
	e.C0.MulByFp(api, e1.C0, c)
	e.C1.MulByFp(api, e1.C1, c)
	return e
}

func (e *E8) MulByNonResidue(api frontend.API, e1 E8) *E8 {
	e.C0.MulByNonResidue(api, e1.C1)
	e.C1 = e1.C0
	return e
}

func (e *E8) coeffs() []frontend.Variable {
	return []frontend.Variable{
		e.C0.B0.A0, e.C0.B0.A1, e.C0.B1.A0, e.C0.B1.A1,
		e.C1.B0.A0, e.C1.B0.A1, e.C1.B1.A0, e.C1.B1.A1,
	}
}

func (e *E8) Inverse(api frontend.API, e1 E8) *E8 {
	in := e1.coeffs()
	out, err := api.Compiler().NewHint(inverseE8Hint, 8, in...)
	if err != nil {
		panic(err)
	}
	e.assign(out)
	var check, one E8
	check.Mul(api, *e, e1)
	one.SetOne()
	check.AssertIsEqual(api, one)
	return e
}

func (e *E8) DivUnchecked(api frontend.API, e1, e2 E8) *E8 {
	in := append(e1.coeffs(), e2.coeffs()...)
	out, err := api.Compiler().NewHint(divE8Hint, 8, in...)
	if err != nil {
		panic(err)
	}
	e.assign(out)
	var check E8
	check.Mul(api, *e, e2)
	check.AssertIsEqual(api, e1)
	return e
}

func (e *E8) AssertIsEqual(api frontend.API, other E8) {
	e.C0.AssertIsEqual(api, other.C0)
	e.C1.AssertIsEqual(api, other.C1)
}

func (e *E8) IsEqual(api frontend.API, other E8) frontend.Variable {
	return api.And(e.C0.IsEqual(api, other.C0), e.C1.IsEqual(api, other.C1))
}

func (e *E8) Select(api frontend.API, b frontend.Variable, r1, r2 E8) *E8 {
	e.C0.Select(api, b, r1.C0, r2.C0)
	e.C1.Select(api, b, r1.C1, r2.C1)
	return e
}

func (e *E8) Assign(a *extensions.E8) {
	e.C0.Assign(&a.C0)
	e.C1.Assign(&a.C1)
}
