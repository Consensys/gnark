package fields_bw6761

import (
	"math/big"

	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type curveF = emulated.Field[emulated.BW6761Fp]
type baseEl = emulated.Element[emulated.BW6761Fp]

type E6 struct {
	A0, A1, A2, A3, A4, A5 baseEl
}

type Ext6 struct {
	api frontend.API
	fp  *curveF
}

func NewExt6(api frontend.API) *Ext6 {
	fp, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	return &Ext6{
		api: api,
		fp:  fp,
	}
}

func (e Ext6) Reduce(x *E6) *E6 {
	var z E6
	z.A0 = *e.fp.Reduce(&x.A0)
	z.A1 = *e.fp.Reduce(&x.A1)
	z.A2 = *e.fp.Reduce(&x.A2)
	z.A3 = *e.fp.Reduce(&x.A3)
	z.A4 = *e.fp.Reduce(&x.A4)
	z.A5 = *e.fp.Reduce(&x.A5)
	return &z
}

func (e Ext6) Zero() *E6 {
	zero := e.fp.Zero()
	return &E6{
		A0: *zero,
		A1: *zero,
		A2: *zero,
		A3: *zero,
		A4: *zero,
		A5: *zero,
	}
}

func (e Ext6) One() *E6 {
	one := e.fp.One()
	zero := e.fp.Zero()
	return &E6{
		A0: *one,
		A1: *zero,
		A2: *zero,
		A3: *zero,
		A4: *zero,
		A5: *zero,
	}
}

func (e Ext6) Neg(x *E6) *E6 {
	a0 := e.fp.Neg(&x.A0)
	a1 := e.fp.Neg(&x.A1)
	a2 := e.fp.Neg(&x.A2)
	a3 := e.fp.Neg(&x.A3)
	a4 := e.fp.Neg(&x.A4)
	a5 := e.fp.Neg(&x.A5)
	return &E6{
		A0: *a0,
		A1: *a1,
		A2: *a2,
		A3: *a3,
		A4: *a4,
		A5: *a5,
	}
}

func (e Ext6) Add(x, y *E6) *E6 {
	a0 := e.fp.Add(&x.A0, &y.A0)
	a1 := e.fp.Add(&x.A1, &y.A1)
	a2 := e.fp.Add(&x.A2, &y.A2)
	a3 := e.fp.Add(&x.A3, &y.A3)
	a4 := e.fp.Add(&x.A4, &y.A4)
	a5 := e.fp.Add(&x.A5, &y.A5)
	return &E6{
		A0: *a0,
		A1: *a1,
		A2: *a2,
		A3: *a3,
		A4: *a4,
		A5: *a5,
	}
}

func (e Ext6) Sub(x, y *E6) *E6 {
	a0 := e.fp.Sub(&x.A0, &y.A0)
	a1 := e.fp.Sub(&x.A1, &y.A1)
	a2 := e.fp.Sub(&x.A2, &y.A2)
	a3 := e.fp.Sub(&x.A3, &y.A3)
	a4 := e.fp.Sub(&x.A4, &y.A4)
	a5 := e.fp.Sub(&x.A5, &y.A5)
	return &E6{
		A0: *a0,
		A1: *a1,
		A2: *a2,
		A3: *a3,
		A4: *a4,
		A5: *a5,
	}
}

func (e Ext6) Double(x *E6) *E6 {
	two := big.NewInt(2)
	a0 := e.fp.MulConst(&x.A0, two)
	a1 := e.fp.MulConst(&x.A1, two)
	a2 := e.fp.MulConst(&x.A2, two)
	a3 := e.fp.MulConst(&x.A3, two)
	a4 := e.fp.MulConst(&x.A4, two)
	a5 := e.fp.MulConst(&x.A5, two)
	return &E6{
		A0: *a0,
		A1: *a1,
		A2: *a2,
		A3: *a3,
		A4: *a4,
		A5: *a5,
	}
}

func (e Ext6) MulByElement(x *E6, y *baseEl) *E6 {
	a0 := e.fp.Mul(&x.A0, y)
	a1 := e.fp.Mul(&x.A1, y)
	a2 := e.fp.Mul(&x.A2, y)
	a3 := e.fp.Mul(&x.A3, y)
	a4 := e.fp.Mul(&x.A4, y)
	a5 := e.fp.Mul(&x.A5, y)
	z := &E6{
		A0: *a0,
		A1: *a1,
		A2: *a2,
		A3: *a3,
		A4: *a4,
		A5: *a5,
	}
	return z
}

func (e Ext6) MulByConstElement(x *E6, y *big.Int) *E6 {
	a0 := e.fp.MulConst(&x.A0, y)
	a1 := e.fp.MulConst(&x.A1, y)
	a2 := e.fp.MulConst(&x.A2, y)
	a3 := e.fp.MulConst(&x.A3, y)
	a4 := e.fp.MulConst(&x.A4, y)
	a5 := e.fp.MulConst(&x.A5, y)
	return &E6{
		A0: *a0,
		A1: *a1,
		A2: *a2,
		A3: *a3,
		A4: *a4,
		A5: *a5,
	}
}

func (e Ext6) Conjugate(x *E6) *E6 {
	return &E6{
		A0: x.A0,
		A1: *e.fp.Neg(&x.A1),
		A2: x.A2,
		A3: *e.fp.Neg(&x.A3),
		A4: x.A4,
		A5: *e.fp.Neg(&x.A5),
	}
}

func (e Ext6) mulFpByNonResidue(fp *curveF, x *baseEl) *baseEl {

	z := fp.Neg(x)
	z = fp.MulConst(z, big.NewInt(4))
	return z
}

func (e Ext6) Mul(x, y *E6) *E6 {
	x = e.Reduce(x)
	y = e.Reduce(y)
	return e.mulToomCook6(x, y)
}

func (e Ext6) mulMontgomery6(x, y *E6) *E6 {
	// Ref.: Peter L. Montgomery. Five, six, and seven-term Karatsuba-like formulae. IEEE
	// Transactions on Computers, 54(3):362–369, 2005.
	//
	// Fixing the polynomial C to X^6 we first compute the interpolation points
	// vi = x(Xi)*y(Xi) at Xi={0, ±1, ±2, ±3, ±4, 5,∞}:
	//
	//		v0 = (a0 + a1 + a2 + a3 + a4 + a5)(b0 + b1 + b2 + b3 + b4 + b5)
	//		v2 = (a0 + a1 + a3 + a4)(b0 + b1 + b3 + b4)
	//		v3 = (a0 − a2 − a3 + a5)(b0 − b2 − b3 + b5)
	//		v4 = (a0 − a2 − a5)(b0 − b2 − b5)
	//		v5 = (a0 + a3 − a5)(b0 + b3 − b5)
	//		v6 = (a0 + a1 + a2)(b0 + b1 + b2)
	//		v7 = (a3 + a4 + a5)(b3 + b4 + b5)
	//		v8 = (a2 + a3)(b2 + b3)
	//		v9 = (a1 − a4)(b1 − b4)
	//		v10 = (a1 + a2)(b1 + b2)
	//		v11 = (a3 + a4)(b3 + b4)
	//		v12 = (a0 + a1)(b0 + b1)
	//		v13 = (a4 + a5)(b4 + b5)
	//		v14 = a0b0
	//		v15 = a1b1
	//		v16 = a4b4
	//		v17 = a5b5
	_t0 := e.fp.Add(&x.A0, &x.A1)
	t0 := e.fp.Add(_t0, &x.A2)
	t1 := e.fp.Add(&x.A3, &x.A4)
	t2 := e.fp.Add(_t0, t1)
	t3 := e.fp.Add(t2, &x.A5)
	t3 = e.fp.Add(t3, &x.A2)

	_s0 := e.fp.Add(&y.A0, &y.A1)
	s0 := e.fp.Add(_s0, &y.A2)
	s1 := e.fp.Add(&y.A3, &y.A4)
	s2 := e.fp.Add(_s0, s1)
	s3 := e.fp.Add(s2, &y.A5)
	s3 = e.fp.Add(s3, &y.A2)

	v0 := e.fp.Mul(t3, s3)
	v2 := e.fp.Mul(t2, s2)
	v6 := e.fp.Mul(t0, s0)
	t4 := e.fp.Add(t1, &x.A5)
	s4 := e.fp.Add(s1, &y.A5)
	v7 := e.fp.Mul(t4, s4)
	v12 := e.fp.Mul(_t0, _s0)
	v11 := e.fp.Mul(t1, s1)
	t0 = e.fp.Add(&x.A2, &x.A3)
	s0 = e.fp.Add(&y.A2, &y.A3)
	v8 := e.fp.Mul(t0, s0)
	_t0 = e.fp.Sub(&x.A1, &x.A4)
	_s0 = e.fp.Sub(&y.A1, &y.A4)
	v9 := e.fp.Mul(_t0, _s0)
	t1 = e.fp.Add(&x.A1, &x.A2)
	s1 = e.fp.Add(&y.A1, &y.A2)
	v10 := e.fp.Mul(t1, s1)
	t1 = e.fp.Add(&x.A4, &x.A5)
	s1 = e.fp.Add(&y.A4, &y.A5)
	v13 := e.fp.Mul(t1, s1)
	v3 := e.fp.Add(&x.A0, &x.A5)
	v3 = e.fp.Sub(v3, t0)
	s1 = e.fp.Add(&y.A0, &y.A5)
	s1 = e.fp.Sub(s1, s0)
	v3 = e.fp.Mul(v3, s1)
	t1 = e.fp.Add(&x.A2, &x.A5)
	t2 = e.fp.Sub(&x.A0, t1)
	s1 = e.fp.Add(&y.A2, &y.A5)
	s2 = e.fp.Sub(&y.A0, s1)
	v4 := e.fp.Mul(t2, s2)
	t1 = e.fp.Add(&x.A0, &x.A3)
	t1 = e.fp.Sub(t1, &x.A5)
	s1 = e.fp.Add(&y.A0, &y.A3)
	s1 = e.fp.Sub(s1, &y.A5)
	v5 := e.fp.Mul(t1, s1)
	v14 := e.fp.Mul(&x.A0, &y.A0)
	v15 := e.fp.Mul(&x.A1, &y.A1)
	v16 := e.fp.Mul(&x.A4, &y.A4)
	v17 := e.fp.Mul(&x.A5, &y.A5)

	// Then we compute the coefficients c0,c1,c3,c4 and c5 in the direct sextic
	// extension of the product x*y as follows:
	//
	// 	c0 = v14 + β(v0 − v2 + v4 + 2(v3+v5+v6-v12) + 3(v7+v15-v8-v10-v11) +
	// 	4(v16-v13) − 5(v14+v17))
	//
	//  c1 = v12 − (v14 + v15) + β(v8 + v10 + v12 − (v3 + v5 + v6 + v15) +
	//  2(v14 + v17 + v13 - v7) + 3(v11 - v16))
	//
	// 	c2 = 2v15 + v6 − (v10 + v12) + β(2v16 + v7 − (v11 + v13))
	//
	// 	c3 = v8 + v11 + v13 − (v3 + v4 + v7 + v16) + 3(v10 - v15) + 2(v12 + v14
	// 	+ v17 - v6) + β(v13 − (v16 + v17))
	//
	// 	c4 = v2 + v3 + v4 + v7 + v15 + v9 − (v8 + v13) − 3v12 + 2(v6 − (v17 +
	// 	v10 + v11 + v14)) + βv17
	//
	//  c5 = −(v3 + v4 + v5 + v9 + v15 + v16) + 2(v8 + v10 + v11 + v12 + v13 −
	//  (v6 + v7)) + 3(v14 + v17)

	c0 := e.fp.MulConst(v2, big.NewInt(4))
	s811 := e.fp.Add(v8, v11)
	s81110 := e.fp.Add(s811, v10)
	s1 = e.fp.MulConst(s81110, big.NewInt(12))
	c0 = e.fp.Add(c0, s1)
	s1 = e.fp.MulConst(v12, big.NewInt(8))
	c0 = e.fp.Add(c0, s1)
	s1 = e.fp.MulConst(v13, big.NewInt(16))
	c0 = e.fp.Add(c0, s1)
	s1 = e.fp.MulConst(v14, big.NewInt(21))
	c0 = e.fp.Add(c0, s1)
	s1 = e.fp.MulConst(v17, big.NewInt(20))
	c0 = e.fp.Add(c0, s1)
	s1 = e.fp.MulConst(v15, big.NewInt(12))
	s2 = e.fp.MulConst(v16, big.NewInt(16))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v0, big.NewInt(4))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v3, big.NewInt(8))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v4, big.NewInt(4))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v5, big.NewInt(8))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v6, big.NewInt(8))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v7, big.NewInt(12))
	s1 = e.fp.Add(s1, s2)
	c0 = e.fp.Sub(c0, s1)

	s35 := e.fp.Add(v3, v5)
	c1 := e.fp.Add(s35, v6)
	c1 = e.fp.MulConst(c1, big.NewInt(4))
	s1 = e.fp.MulConst(v7, big.NewInt(8))
	c1 = e.fp.Add(c1, s1)
	s1 = e.fp.MulConst(v16, big.NewInt(12))
	c1 = e.fp.Add(c1, s1)
	s1 = e.fp.MulConst(v15, big.NewInt(3))
	c1 = e.fp.Add(c1, s1)
	s1 = e.fp.MulConst(v12, big.NewInt(3))
	s2 = e.fp.MulConst(v14, big.NewInt(9))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v8, big.NewInt(4))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v10, big.NewInt(4))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v11, big.NewInt(12))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v13, big.NewInt(8))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v17, big.NewInt(8))
	s1 = e.fp.Add(s1, s2)
	c1 = e.fp.Sub(c1, s1)

	c2 := e.fp.MulConst(v15, big.NewInt(2))
	c2 = e.fp.Add(c2, v6)
	s1 = e.fp.MulConst(v11, big.NewInt(4))
	c2 = e.fp.Add(c2, s1)
	s1 = e.fp.MulConst(v13, big.NewInt(4))
	c2 = e.fp.Add(c2, s1)
	s1012 := e.fp.Add(v10, v12)
	s2 = e.fp.MulConst(v7, big.NewInt(4))
	s1 = e.fp.Add(s1012, s2)
	s2 = e.fp.MulConst(v16, big.NewInt(8))
	s1 = e.fp.Add(s1, s2)
	c2 = e.fp.Sub(c2, s1)

	s1 = e.fp.MulConst(v10, big.NewInt(3))
	c3 := e.fp.Add(s811, s1)
	s1 = e.fp.MulConst(v12, big.NewInt(2))
	c3 = e.fp.Add(c3, s1)
	s1 = e.fp.MulConst(v14, big.NewInt(2))
	c3 = e.fp.Add(c3, s1)
	s1 = e.fp.MulConst(v16, big.NewInt(3))
	c3 = e.fp.Add(c3, s1)
	s1 = e.fp.MulConst(v17, big.NewInt(6))
	c3 = e.fp.Add(c3, s1)
	s34 := e.fp.Add(v3, v4)
	s1 = e.fp.Add(s34, v7)
	s2 = e.fp.MulConst(v6, big.NewInt(2))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v13, big.NewInt(3))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v15, big.NewInt(3))
	s1 = e.fp.Add(s1, s2)
	c3 = e.fp.Sub(c3, s1)

	c4 := e.fp.Add(v2, v15)
	c4 = e.fp.Add(c4, v9)
	c4 = e.fp.Add(c4, v7)
	c4 = e.fp.Add(c4, s34)
	s1 = e.fp.MulConst(v6, big.NewInt(2))
	c4 = e.fp.Add(c4, s1)
	s1 = e.fp.Add(v13, v8)
	s2 = e.fp.MulConst(v10, big.NewInt(2))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v11, big.NewInt(2))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v12, big.NewInt(3))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v14, big.NewInt(2))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v17, big.NewInt(6))
	s1 = e.fp.Add(s1, s2)
	c4 = e.fp.Sub(c4, s1)

	c5 := e.fp.Add(s81110, v12)
	c5 = e.fp.Add(c5, v13)
	c5 = e.fp.MulConst(c5, big.NewInt(2))
	s1 = e.fp.MulConst(v14, big.NewInt(3))
	c5 = e.fp.Add(c5, s1)
	s1 = e.fp.MulConst(v17, big.NewInt(3))
	c5 = e.fp.Add(c5, s1)
	s1 = e.fp.Add(v15, v16)
	s1 = e.fp.Add(s1, s34)
	s1 = e.fp.Add(s1, v5)
	s1 = e.fp.Add(s1, v9)
	s2 = e.fp.MulConst(v6, big.NewInt(2))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v7, big.NewInt(2))
	s1 = e.fp.Add(s1, s2)
	c5 = e.fp.Sub(c5, s1)

	return &E6{
		A0: *c0,
		A1: *c1,
		A2: *c2,
		A3: *c3,
		A4: *c4,
		A5: *c5,
	}
}

func (e Ext6) mulToomCook6(x, y *E6) *E6 {
	// Toom-Cook 6-way multiplication:
	//
	// Ref.: https://eprint.iacr.org/2006/471.pdf
	// ⚠️  but has sign errors in c1 and coefficient errors in c3 and c4.
	//
	// We first represent a, b as the polynomials:
	// 	x(X) = a0 + a1*X + a2*X^2 + a3*X^3 + a4*X^4 + a5*X^5
	// 	y(X) = b0 + b1*X + b2*X^2 + b3*X^3 + b4*X^4 + b5*X^5
	//
	// and we compute the interpolation points
	// vi = a(Xi)*b(Xi) at Xi={0, ±1, ±2, ±3, ±4, 5, ∞}:
	//
	//     v0 = x(0)y(0)   = x0y0
	//     v1 = x(1)y(1)   = (x0 + x1 + x2 + x3 + x4 + x5)(y0 + y1 + y2 + y3 + y4 + y5)
	//     v2 = x(-1)y(-1) = (x0 - x1 + x2 - x3 + x4 - x5)(y0 - y1 + y2 - y3 + y4 - y5)
	//     v3 = x(2)y(2)   = (x0 + 2x1 + 4x2 + 8x3 + 16x4 + 32x5)(y0 + 2y1 + 4y2 + 8y3 + 16y4 + 32y5)
	//     v4 = x(-2)y(-2) = (x0 - 2x1 + 4x2 - 8x3 + 16x4 - 32x5)(y0 - 2y1 + 4y2 - 8y3 + 16y4 - 32y5)
	//     v5 = x(3)y(3)   = (x0 + 3x1 + 9x2 + 27x3 + 81x4 + 243x5)(y0 + 3y1 + 9y2 + 27y3 + 81y4 + 243y5)
	//     v6 = x(-3)y(-3) = (x0 - 3x1 + 9x2 - 27x3 + 81x4 - 243x5)(y0 - 3y1 + 9y2 - 27y3 + 81y4 - 243y5)
	//     v7 = x(4)y(4)   = (x0 + 4x1 + 16x2 + 64x3 + 256x4 + 1024x5)(y0 + 4y1 + 16y2 + 64y3 + 256y4 + 1024y5)
	//     v8 = x(-4)y(-4) = (x0 - 4x1 + 16x2 - 64x3 + 256x4 - 1024x5)(y0 - 4y1 + 16y2 - 64y3 + 256y4 - 1024y5)
	//     v9 = x(5)y(5)   = (x0 + 5x1 + 25x2 + 125x3 + 625x4 + 3125x5)(y0 + 5y1 + 25y2 + 125y3 + 625y4 + 3125y5)
	// 	   v10 = x(∞)y(∞)  = x5y5

	v0 := e.fp.Mul(&x.A0, &y.A0)

	t1 := e.fp.Add(&x.A0, &x.A2)
	t1 = e.fp.Add(t1, &x.A4)
	s1 := e.fp.Add(&y.A0, &y.A2)
	s1 = e.fp.Add(s1, &y.A4)
	t2 := e.fp.Add(&x.A1, &x.A3)
	t2 = e.fp.Add(t2, &x.A5)
	s2 := e.fp.Add(&y.A1, &y.A3)
	s2 = e.fp.Add(s2, &y.A5)

	v1 := e.fp.Add(t1, t2)
	s3 := e.fp.Add(s1, s2)
	v1 = e.fp.Mul(v1, s3)

	v2 := e.fp.Sub(t1, t2)
	s3 = e.fp.Sub(s1, s2)
	v2 = e.fp.Mul(v2, s3)

	t1 = e.fp.MulConst(&x.A2, big.NewInt(4))
	t1 = e.fp.Add(&x.A0, t1)
	t := e.fp.MulConst(&x.A4, big.NewInt(16))
	t1 = e.fp.Add(t1, t)
	t2 = e.fp.MulConst(&x.A1, big.NewInt(2))
	t = e.fp.MulConst(&x.A3, big.NewInt(8))
	t2 = e.fp.Add(t2, t)
	t = e.fp.MulConst(&x.A5, big.NewInt(32))
	t2 = e.fp.Add(t2, t)
	s1 = e.fp.MulConst(&y.A2, big.NewInt(4))
	s1 = e.fp.Add(&y.A0, s1)
	s := e.fp.MulConst(&y.A4, big.NewInt(16))
	s1 = e.fp.Add(s1, s)
	s2 = e.fp.MulConst(&y.A1, big.NewInt(2))
	s = e.fp.MulConst(&y.A3, big.NewInt(8))
	s2 = e.fp.Add(s2, s)
	s = e.fp.MulConst(&y.A5, big.NewInt(32))
	s2 = e.fp.Add(s2, s)

	v3 := e.fp.Add(t1, t2)
	s3 = e.fp.Add(s1, s2)
	v3 = e.fp.Mul(v3, s3)

	v4 := e.fp.Sub(t1, t2)
	s3 = e.fp.Sub(s1, s2)
	v4 = e.fp.Mul(v4, s3)

	t1 = e.fp.MulConst(&x.A2, big.NewInt(9))
	t1 = e.fp.Add(&x.A0, t1)
	t = e.fp.MulConst(&x.A4, big.NewInt(81))
	t1 = e.fp.Add(t1, t)
	t2 = e.fp.MulConst(&x.A1, big.NewInt(3))
	t = e.fp.MulConst(&x.A3, big.NewInt(27))
	t2 = e.fp.Add(t2, t)
	t = e.fp.MulConst(&x.A5, big.NewInt(243))
	t2 = e.fp.Add(t2, t)
	s1 = e.fp.MulConst(&y.A2, big.NewInt(9))
	s1 = e.fp.Add(&y.A0, s1)
	s = e.fp.MulConst(&y.A4, big.NewInt(81))
	s1 = e.fp.Add(s1, s)
	s2 = e.fp.MulConst(&y.A1, big.NewInt(3))
	s = e.fp.MulConst(&y.A3, big.NewInt(27))
	s2 = e.fp.Add(s2, s)
	s = e.fp.MulConst(&y.A5, big.NewInt(243))
	s2 = e.fp.Add(s2, s)

	v5 := e.fp.Add(t1, t2)
	s3 = e.fp.Add(s1, s2)
	v5 = e.fp.Mul(v5, s3)

	v6 := e.fp.Sub(t1, t2)
	s3 = e.fp.Sub(s1, s2)
	v6 = e.fp.Mul(v6, s3)

	t1 = e.fp.MulConst(&x.A2, big.NewInt(16))
	t1 = e.fp.Add(&x.A0, t1)
	t = e.fp.MulConst(&x.A4, big.NewInt(256))
	t1 = e.fp.Add(t1, t)
	t2 = e.fp.MulConst(&x.A1, big.NewInt(4))
	t = e.fp.MulConst(&x.A3, big.NewInt(64))
	t2 = e.fp.Add(t2, t)
	t = e.fp.MulConst(&x.A5, big.NewInt(1024))
	t2 = e.fp.Add(t2, t)
	s1 = e.fp.MulConst(&y.A2, big.NewInt(16))
	s1 = e.fp.Add(&y.A0, s1)
	s = e.fp.MulConst(&y.A4, big.NewInt(256))
	s1 = e.fp.Add(s1, s)
	s2 = e.fp.MulConst(&y.A1, big.NewInt(4))
	s = e.fp.MulConst(&y.A3, big.NewInt(64))
	s2 = e.fp.Add(s2, s)
	s = e.fp.MulConst(&y.A5, big.NewInt(1024))
	s2 = e.fp.Add(s2, s)

	v7 := e.fp.Add(t1, t2)
	s3 = e.fp.Add(s1, s2)
	v7 = e.fp.Mul(v7, s3)

	v8 := e.fp.Sub(t1, t2)
	s3 = e.fp.Sub(s1, s2)
	v8 = e.fp.Mul(v8, s3)

	t1 = e.fp.MulConst(&x.A2, big.NewInt(25))
	t1 = e.fp.Add(&x.A0, t1)
	t = e.fp.MulConst(&x.A4, big.NewInt(625))
	t1 = e.fp.Add(t1, t)
	t2 = e.fp.MulConst(&x.A1, big.NewInt(5))
	t = e.fp.MulConst(&x.A3, big.NewInt(125))
	t2 = e.fp.Add(t2, t)
	t = e.fp.MulConst(&x.A5, big.NewInt(3125))
	t2 = e.fp.Add(t2, t)
	s1 = e.fp.MulConst(&y.A2, big.NewInt(25))
	s1 = e.fp.Add(&y.A0, s1)
	s = e.fp.MulConst(&y.A4, big.NewInt(625))
	s1 = e.fp.Add(s1, s)
	s2 = e.fp.MulConst(&y.A1, big.NewInt(5))
	s = e.fp.MulConst(&y.A3, big.NewInt(125))
	s2 = e.fp.Add(s2, s)
	s = e.fp.MulConst(&y.A5, big.NewInt(3125))
	s2 = e.fp.Add(s2, s)
	v9 := e.fp.Add(t1, t2)
	s3 = e.fp.Add(s1, s2)
	v9 = e.fp.Mul(v9, s3)

	v10 := e.fp.Mul(&x.A5, &y.A5)

	// recording common sub-expressions
	v12 := e.fp.Add(v1, v2)
	v34 := e.fp.Add(v3, v4)
	v56 := e.fp.Add(v5, v6)
	v78 := e.fp.Add(v7, v8)

	//	Then we compute the product  362880 * x * y to avoid divisions (mul by large coeffs):
	//
	// 		c0 = 438480 v0 + 26208(v3 + v4) + 504(v7 + v8)
	// 		- (58464(v1 + v2) + 6048(v5 + v6) + 396264960 v10)
	c0 := e.fp.MulConst(v0, big.NewInt(438480))
	s1 = e.fp.MulConst(v34, big.NewInt(26208))
	c0 = e.fp.Add(c0, s1)
	s1 = e.fp.MulConst(v78, big.NewInt(504))
	c0 = e.fp.Add(c0, s1)
	s1 = e.fp.MulConst(v12, big.NewInt(58464))
	s2 = e.fp.MulConst(v56, big.NewInt(6048))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v10, big.NewInt(396264960))
	s1 = e.fp.Add(s1, s2)
	c0 = e.fp.Sub(c0, s1)
	//  	c1 = 744 v8 + 696 v9 + 49536 v4 + 39744 v5 + 380016 v1
	//  	− (87696 v0 + 226800 v2 + 133056 v3 + 8424* v6 + 7704 v7 + 1262822400 v10)
	c1 := e.fp.MulConst(v8, big.NewInt(744))
	s1 = e.fp.MulConst(v9, big.NewInt(696))
	c1 = e.fp.Add(c1, s1)
	s1 = e.fp.MulConst(v4, big.NewInt(49536))
	c1 = e.fp.Add(c1, s1)
	s1 = e.fp.MulConst(v5, big.NewInt(39744))
	c1 = e.fp.Add(c1, s1)
	s1 = e.fp.MulConst(v1, big.NewInt(380016))
	c1 = e.fp.Add(c1, s1)
	s1 = e.fp.MulConst(v0, big.NewInt(87696))
	s2 = e.fp.MulConst(v2, big.NewInt(233856))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v3, big.NewInt(133056))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v6, big.NewInt(8424))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v7, big.NewInt(7704))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v10, big.NewInt(1262822400))
	s1 = e.fp.Add(s1, s2)
	c1 = e.fp.Sub(c1, s1)
	// 		c2 = 4896(v5 + v6) + 292320(v1 + v2) + 252564480 v10
	// 		− (519120 v0 + 360(v7 + v8) + 37296(v3 + v4))
	c2 := e.fp.MulConst(v56, big.NewInt(4896))
	s1 = e.fp.MulConst(v12, big.NewInt(292320))
	c2 = e.fp.Add(c2, s1)
	s1 = e.fp.MulConst(v10, big.NewInt(252564480))
	c2 = e.fp.Add(c2, s1)
	s1 = e.fp.MulConst(v0, big.NewInt(519120))
	s2 = e.fp.MulConst(v78, big.NewInt(360))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v34, big.NewInt(37296))
	s1 = e.fp.Add(s1, s2)
	c2 = e.fp.Sub(c2, s1)
	// 		c3 = 103824 v0 + 1495065600 v10 + 10728 v6 + 9180 v7 + 53760 v2 + 154392 v3
	// 		- (55512 v4 + 47808* v5 + 940 v8 + 824* v9 + 226800* v1)
	c3 := e.fp.MulConst(v0, big.NewInt(103824))
	s1 = e.fp.MulConst(v10, big.NewInt(1495065600))
	c3 = e.fp.Add(c3, s1)
	s1 = e.fp.MulConst(v6, big.NewInt(10728))
	c3 = e.fp.Add(c3, s1)
	s1 = e.fp.MulConst(v7, big.NewInt(9180))
	c3 = e.fp.Add(c3, s1)
	s1 = e.fp.MulConst(v2, big.NewInt(53760))
	c3 = e.fp.Add(c3, s1)
	s1 = e.fp.MulConst(v3, big.NewInt(154392))
	c3 = e.fp.Add(c3, s1)
	s1 = e.fp.MulConst(v4, big.NewInt(55512))
	s2 = e.fp.MulConst(v5, big.NewInt(47808))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v8, big.NewInt(940))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v9, big.NewInt(824))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v1, big.NewInt(226800))
	s1 = e.fp.Add(s1, s2)
	c3 = e.fp.Sub(c3, s1)
	// 		c4 = 171990 v0 + 42588(v3 + v4) + 441* (v7 + v8)
	// 		− (299013120 v10 + 122976(v1 + v2) + 6048(v5 + v6))
	c4 := e.fp.MulConst(v0, big.NewInt(171990))
	s1 = e.fp.MulConst(v34, big.NewInt(42588))
	c4 = e.fp.Add(c4, s1)
	s1 = e.fp.MulConst(v78, big.NewInt(441))
	c4 = e.fp.Add(c4, s1)
	s1 = e.fp.MulConst(v10, big.NewInt(299013120))
	s2 = e.fp.MulConst(v12, big.NewInt(122976))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v56, big.NewInt(6048))
	s1 = e.fp.Add(s1, s2)
	c4 = e.fp.Sub(c4, s1)
	// 		c5 = 231 v8 + 273 v9 + 3276 v4 + 8316 v2 + 14364 v5 + 49014 v1
	// 		- (34398 v0 + 36036 v3 + 2079 v6 + 2961 v7 + 495331200 v10)
	c5 := e.fp.MulConst(v8, big.NewInt(231))
	s1 = e.fp.MulConst(v9, big.NewInt(273))
	c5 = e.fp.Add(c5, s1)
	s1 = e.fp.MulConst(v4, big.NewInt(3276))
	c5 = e.fp.Add(c5, s1)
	s1 = e.fp.MulConst(v2, big.NewInt(8316))
	c5 = e.fp.Add(c5, s1)
	s1 = e.fp.MulConst(v5, big.NewInt(14364))
	c5 = e.fp.Add(c5, s1)
	s1 = e.fp.MulConst(v1, big.NewInt(49014))
	c5 = e.fp.Add(c5, s1)
	s1 = e.fp.MulConst(v0, big.NewInt(34398))
	s2 = e.fp.MulConst(v3, big.NewInt(36036))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v6, big.NewInt(2079))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v7, big.NewInt(2961))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v10, big.NewInt(495331200))
	s1 = e.fp.Add(s1, s2)
	c5 = e.fp.Sub(c5, s1)

	res := e.divE6By362880([6]*baseEl{c0, c1, c2, c3, c4, c5})
	return &E6{
		A0: *res[0],
		A1: *res[1],
		A2: *res[2],
		A3: *res[3],
		A4: *res[4],
		A5: *res[5],
	}
}

func (e Ext6) Square(x *E6) *E6 {
	// We don't use Montgomery-6 or Toom-Cook-6 for the squaring but instead we
	// simulate a quadratic over cubic extension tower because Karatsuba over
	// Chung-Hasan SQR2 is better constraint wise.
	//
	// Algorithm 22 from https://eprint.iacr.org/2010/354.pdf
	x = e.Reduce(x)

	// c0
	x1n := e.fp.Neg(&x.A1)
	x3n := e.fp.Neg(&x.A3)
	c00 := e.fp.Add(&x.A0, x1n)
	c01 := e.fp.Add(&x.A2, x3n)
	c02 := e.fp.Sub(&x.A4, &x.A5)

	// c3
	c30 := e.fp.Add(&x.A0, e.fp.MulConst(&x.A5, big.NewInt(4)))
	c31 := e.fp.Add(&x.A2, x1n)
	c32 := e.fp.Add(&x.A4, x3n)

	t0 := e.fp.Mul(&x.A0, &x.A1)
	t1 := e.fp.Mul(&x.A2, &x.A3)
	t2 := e.fp.Mul(&x.A4, &x.A5)
	c0 := e.fp.Add(&x.A2, &x.A4)
	tmp := e.fp.Add(&x.A3, &x.A5)
	c0 = e.fp.Mul(c0, tmp)
	c0 = e.fp.Sub(e.fp.Add(t1, t2), c0)
	c0 = e.fp.MulConst(c0, big.NewInt(4))
	tmp = e.fp.Add(&x.A0, &x.A4)
	c2 := e.fp.Add(&x.A1, &x.A5)
	c2 = e.fp.Mul(c2, tmp)
	c2 = e.fp.Sub(c2, e.fp.Add(t0, t2))
	c1 := e.fp.Add(&x.A0, &x.A2)
	tmp = e.fp.Add(&x.A1, &x.A3)
	c1 = e.fp.Mul(c1, tmp)
	c1 = e.fp.Sub(c1, e.fp.Add(t0, t1))
	t2 = e.mulFpByNonResidue(e.fp, t2)
	// c2
	c20 := e.fp.Add(c0, t0)
	c21 := e.fp.Add(c1, t2)
	c22 := e.fp.Add(c2, t1)

	t0 = e.fp.Mul(c00, c30)
	t1 = e.fp.Mul(c01, c31)
	t2 = e.fp.Mul(c02, c32)
	c0 = e.fp.Add(c01, c02)
	tmp = e.fp.Add(c31, c32)
	c0 = e.fp.Mul(c0, tmp)
	c0 = e.fp.Sub(e.fp.Add(t1, t2), c0)
	c0 = e.fp.MulConst(c0, big.NewInt(4))
	tmp = e.fp.Add(c00, c02)
	c2 = e.fp.Add(c30, c32)
	c2 = e.fp.Mul(c2, tmp)
	c2 = e.fp.Sub(c2, e.fp.Add(t0, t2))
	c1 = e.fp.Add(c00, c01)
	tmp = e.fp.Add(c30, c31)
	c1 = e.fp.Mul(c1, tmp)
	c1 = e.fp.Sub(c1, e.fp.Add(t0, t1))
	t2 = e.mulFpByNonResidue(e.fp, t2)
	c00 = e.fp.Add(c0, t0)
	c01 = e.fp.Add(c1, t2)
	c02 = e.fp.Add(c2, t1)

	c00 = e.fp.Add(c00, c20)
	c01 = e.fp.Add(c01, c21)
	c02 = e.fp.Add(c02, c22)

	b10 := e.fp.MulConst(c20, big.NewInt(2))
	b11 := e.fp.MulConst(c21, big.NewInt(2))
	b12 := e.fp.MulConst(c22, big.NewInt(2))

	b00 := e.fp.Sub(c00, e.fp.MulConst(c22, big.NewInt(4)))
	b01 := e.fp.Add(c01, c20)
	b02 := e.fp.Add(c02, c21)

	return &E6{
		A0: *b00,
		A1: *b10,
		A2: *b01,
		A3: *b11,
		A4: *b02,
		A5: *b12,
	}
}

// Karabina's compressed cyclotomic square SQR12345
// https://eprint.iacr.org/2010/542.pdf
// Sec. 5.6 with minor modifications to fit our tower
func (e Ext6) CyclotomicSquareKarabina12345(x *E6) *E6 {
	x = e.Reduce(x)

	// h4 = -g4 + 3((g3+g5)(g1+c*g2)-g1g5-c*g3g2)
	g1g5 := e.fp.Mul(&x.A2, &x.A5)
	g3g2 := e.fp.Mul(&x.A1, &x.A4)
	h4 := e.mulFpByNonResidue(e.fp, &x.A4)
	h4 = e.fp.Add(h4, &x.A2)
	t := e.fp.Add(&x.A1, &x.A5)
	h4 = e.fp.Mul(h4, t)
	h4 = e.fp.Sub(h4, g1g5)
	t = e.fp.MulConst(g3g2, big.NewInt(4))
	h4 = e.fp.Add(h4, t)
	h4 = e.fp.MulConst(h4, big.NewInt(3))
	h4 = e.fp.Sub(h4, &x.A3)

	// h3 = 2(g3+3c*g1g5)
	h3 := e.mulFpByNonResidue(e.fp, g1g5)
	h3 = e.fp.MulConst(h3, big.NewInt(3))
	h3 = e.fp.Add(h3, &x.A1)
	h3 = e.fp.MulConst(h3, big.NewInt(2))

	// h2 = 3((g1+g5)(g1+c*g5)-(c+1)*g1g5)-2g2
	t = e.mulFpByNonResidue(e.fp, &x.A5)
	t = e.fp.Add(t, &x.A2)
	h2 := e.fp.Add(&x.A5, &x.A2)
	h2 = e.fp.Mul(h2, t)
	t = e.fp.MulConst(g1g5, big.NewInt(3))
	h2 = e.fp.Add(h2, t)
	h2 = e.fp.MulConst(h2, big.NewInt(3))
	t = e.fp.MulConst(&x.A4, big.NewInt(2))
	h2 = e.fp.Sub(h2, t)

	// h1 = 3((g3+g2)(g3+c*g2)-(c+1)*g3g2)-2g1
	t = e.mulFpByNonResidue(e.fp, &x.A4)
	t = e.fp.Add(t, &x.A1)
	h1 := e.fp.Add(&x.A4, &x.A1)
	h1 = e.fp.Mul(h1, t)
	t = e.fp.MulConst(g3g2, big.NewInt(3))
	h1 = e.fp.Add(h1, t)
	h1 = e.fp.MulConst(h1, big.NewInt(3))
	t = e.fp.MulConst(&x.A2, big.NewInt(2))
	h1 = e.fp.Sub(h1, t)

	// h5 = 2(g5+3g3g2)
	h5 := e.fp.MulConst(g3g2, big.NewInt(3))
	h5 = e.fp.Add(h5, &x.A5)
	h5 = e.fp.MulConst(h5, big.NewInt(2))

	return &E6{
		A0: x.A0,
		A1: *h3,
		A2: *h1,
		A3: *h4,
		A4: *h2,
		A5: *h5,
	}
}

// DecompressKarabina12345 decompresses Karabina's cyclotomic square result SQR12345
func (e Ext6) DecompressKarabina12345(x *E6) *E6 {
	x = e.Reduce(x)

	// h0 = (2g4^2 + g3g5 - 3g2g1)*c + 1
	t0 := e.fp.Mul(&x.A2, &x.A4)
	t0 = e.fp.MulConst(t0, big.NewInt(3))
	t1 := e.fp.Mul(&x.A1, &x.A5)
	h0 := e.fp.Mul(&x.A3, &x.A3)
	h0 = e.fp.MulConst(h0, big.NewInt(2))
	h0 = e.fp.Add(h0, t1)
	h0 = e.fp.Sub(t0, h0)
	h0 = e.fp.MulConst(h0, big.NewInt(4))
	h0 = e.fp.Add(h0, e.fp.One())

	//	a00 a01 a02 a10 a11 a12
	//	A0  A2  A4  A1  A3  A5
	return &E6{
		A0: *h0,
		A1: x.A1,
		A2: x.A2,
		A3: x.A3,
		A4: x.A4,
		A5: x.A5,
	}
}

func (e Ext6) Inverse(x *E6) *E6 {
	res, err := e.fp.NewHint(inverseE6Hint, 6, &x.A0, &x.A1, &x.A2, &x.A3, &x.A4, &x.A5)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	inv := E6{A0: *res[0], A1: *res[1], A2: *res[2], A3: *res[3], A4: *res[4], A5: *res[5]}
	one := e.One()

	// 1 == inv * x
	_one := e.Mul(&inv, x)
	e.AssertIsEqual(one, _one)

	return &inv

}

func (e Ext6) DivUnchecked(x, y *E6) *E6 {
	res, err := e.fp.NewHint(divE6Hint, 12, &x.A0, &x.A1, &x.A2, &x.A3, &x.A4, &x.A5, &y.A0, &y.A1, &y.A2, &y.A3, &y.A4, &y.A5)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	div := E6{A0: *res[0], A1: *res[1], A2: *res[2], A3: *res[3], A4: *res[4], A5: *res[5]}

	// x = div * y
	_x := e.Mul(&div, y)
	e.AssertIsEqual(x, _x)

	return &div

}

func (e Ext6) divE6By362880(x [6]*baseEl) [6]*baseEl {
	res, err := e.fp.NewHint(divE6By362880Hint, 6, x[0], x[1], x[2], x[3], x[4], x[5])
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	y0 := *res[0]
	y1 := *res[1]
	y2 := *res[2]
	y3 := *res[3]
	y4 := *res[4]
	y5 := *res[5]

	// xi == 362880 * yi
	x0 := e.fp.MulConst(&y0, big.NewInt(362880))
	x1 := e.fp.MulConst(&y1, big.NewInt(362880))
	x2 := e.fp.MulConst(&y2, big.NewInt(362880))
	x3 := e.fp.MulConst(&y3, big.NewInt(362880))
	x4 := e.fp.MulConst(&y4, big.NewInt(362880))
	x5 := e.fp.MulConst(&y5, big.NewInt(362880))
	e.fp.AssertIsEqual(x[0], x0)
	e.fp.AssertIsEqual(x[1], x1)
	e.fp.AssertIsEqual(x[2], x2)
	e.fp.AssertIsEqual(x[3], x3)
	e.fp.AssertIsEqual(x[4], x4)
	e.fp.AssertIsEqual(x[5], x5)

	return [6]*baseEl{&y0, &y1, &y2, &y3, &y4, &y5}
}

func (e Ext6) AssertIsEqual(a, b *E6) {
	e.fp.AssertIsEqual(&a.A0, &b.A0)
	e.fp.AssertIsEqual(&a.A1, &b.A1)
	e.fp.AssertIsEqual(&a.A2, &b.A2)
	e.fp.AssertIsEqual(&a.A3, &b.A3)
	e.fp.AssertIsEqual(&a.A4, &b.A4)
	e.fp.AssertIsEqual(&a.A5, &b.A5)

}

func (e Ext6) Copy(x *E6) *E6 {
	return &E6{
		A0: x.A0,
		A1: x.A1,
		A2: x.A2,
		A3: x.A3,
		A4: x.A4,
		A5: x.A5,
	}
}

func FromE6(a *bw6761.E6) E6 {
	// gnark-crypto uses a quadratic over cubic sextic extension of Fp.
	// The two towers are isomorphic and the coefficients are permuted as follows:
	// 		a00 a01 a02 a10 a11 a12
	// 		A0  A2  A4  A1  A3  A5
	return E6{
		A0: emulated.ValueOf[emulated.BW6761Fp](a.B0.A0),
		A1: emulated.ValueOf[emulated.BW6761Fp](a.B1.A0),
		A2: emulated.ValueOf[emulated.BW6761Fp](a.B0.A1),
		A3: emulated.ValueOf[emulated.BW6761Fp](a.B1.A1),
		A4: emulated.ValueOf[emulated.BW6761Fp](a.B0.A2),
		A5: emulated.ValueOf[emulated.BW6761Fp](a.B1.A2),
	}
}

func (e Ext6) Select(selector frontend.Variable, z1, z0 *E6) *E6 {
	a0 := e.fp.Select(selector, &z1.A0, &z0.A0)
	a1 := e.fp.Select(selector, &z1.A1, &z0.A1)
	a2 := e.fp.Select(selector, &z1.A2, &z0.A2)
	a3 := e.fp.Select(selector, &z1.A3, &z0.A3)
	a4 := e.fp.Select(selector, &z1.A4, &z0.A4)
	a5 := e.fp.Select(selector, &z1.A5, &z0.A5)

	return &E6{A0: *a0, A1: *a1, A2: *a2, A3: *a3, A4: *a4, A5: *a5}
}

// Frobenius set z in E6 to Frobenius(x), return z
func (e Ext6) Frobenius(x *E6) *E6 {
	_frobA := emulated.ValueOf[emulated.BW6761Fp]("4922464560225523242118178942575080391082002530232324381063048548642823052024664478336818169867474395270858391911405337707247735739826664939444490469542109391530482826728203582549674992333383150446779312029624171857054392282775648")
	_frobB := emulated.ValueOf[emulated.BW6761Fp]("1968985824090209297278610739700577151397666382303825728450741611566800370218827257750865013421937292370006175842381275743914023380727582819905021229583192207421122272650305267822868639090213645505120388400344940985710520836292650")
	_frobC := emulated.ValueOf[emulated.BW6761Fp]("4922464560225523242118178942575080391082002530232324381063048548642823052024664478336818169867474395270858391911405337707247735739826664939444490469542109391530482826728203582549674992333383150446779312029624171857054392282775649")
	_frobBC := emulated.ValueOf[emulated.BW6761Fp]("1968985824090209297278610739700577151397666382303825728450741611566800370218827257750865013421937292370006175842381275743914023380727582819905021229583192207421122272650305267822868639090213645505120388400344940985710520836292651")
	var z E6
	z.A0 = x.A0
	z.A2 = *e.fp.Mul(&x.A2, &_frobA)
	z.A4 = *e.fp.Mul(&x.A4, &_frobB)
	z.A1 = *e.fp.Mul(&x.A1, &_frobC)
	z.A3 = *e.fp.Neg(&x.A3)
	z.A5 = *e.fp.Mul(&x.A5, &_frobBC)

	return &z
}
