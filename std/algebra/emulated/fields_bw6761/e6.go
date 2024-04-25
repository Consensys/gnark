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

func mulFpByNonResidue(fp *curveF, x *baseEl) *baseEl {

	z := fp.Neg(x)
	z = fp.MulConst(z, big.NewInt(4))
	return z
}

func (e Ext6) Mul(x, y *E6) *E6 {
	x = e.Reduce(x)
	y = e.Reduce(y)
	v := e.interpolationX6Mul(x, y)
	return e.mulMontgomery6(v)
	// return e.mulToomCook6(v)
}

func (e Ext6) interpolationX6Mul(x, y *E6) [18]*baseEl {
	// Fixing the polynomial to X^6 we first compute the interpolation points
	// vi = x(pi)*y(pi) at {0, ±1, ±2, ±3, ±4, 5,∞}:
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
	v1 := e.fp.Zero()

	return [18]*baseEl{v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17}
}

func (e Ext6) interpolationX6Sq(x *E6) [18]*baseEl {
	// Fixing the polynomial to X^6 we first compute the interpolation points
	// vi = x(pi)*y(pi) at {0, ±1, ±2, ±3, ±4, 5,∞}:
	//
	//		v0 = (a0 + a1 + a2 + a3 + a4 + a5)^2
	//		v2 = (a0 + a1 + a3 + a4)^2
	//		v3 = (a0 − a2 − a3 + a5)^2
	//		v4 = (a0 − a2 − a5)^2
	//		v5 = (a0 + a3 − a5)^2
	//		v6 = (a0 + a1 + a2)^2
	//		v7 = (a3 + a4 + a5)^2
	//		v8 = (a2 + a3)^2
	//		v9 = (a1 − a4)^2
	//		v10 = (a1 + a2)^2
	//		v11 = (a3 + a4)^2
	//		v12 = (a0 + a1)^2
	//		v13 = (a4 + a5)^2
	//		v14 = a0^2
	//		v15 = a1^2
	//		v16 = a4^2
	//		v17 = a5^2

	_t0 := e.fp.Add(&x.A0, &x.A1)
	t0 := e.fp.Add(_t0, &x.A2)
	t1 := e.fp.Add(&x.A3, &x.A4)
	t2 := e.fp.Add(_t0, t1)
	t3 := e.fp.Add(t2, &x.A5)
	t3 = e.fp.Add(t3, &x.A2)

	v0 := e.fp.Mul(t3, t3)
	v2 := e.fp.Mul(t2, t2)
	v6 := e.fp.Mul(t0, t0)
	t4 := e.fp.Add(t1, &x.A5)
	v7 := e.fp.Mul(t4, t4)
	v12 := e.fp.Mul(_t0, _t0)
	v11 := e.fp.Mul(t1, t1)
	t0 = e.fp.Add(&x.A2, &x.A3)
	v8 := e.fp.Mul(t0, t0)
	_t0 = e.fp.Sub(&x.A1, &x.A4)
	v9 := e.fp.Mul(_t0, _t0)
	t1 = e.fp.Add(&x.A1, &x.A2)
	v10 := e.fp.Mul(t1, t1)
	t1 = e.fp.Add(&x.A4, &x.A5)
	v13 := e.fp.Mul(t1, t1)
	v3 := e.fp.Add(&x.A0, &x.A5)
	v3 = e.fp.Sub(v3, t0)
	v3 = e.fp.Mul(v3, v3)
	t1 = e.fp.Add(&x.A2, &x.A5)
	t2 = e.fp.Sub(&x.A0, t1)
	v4 := e.fp.Mul(t2, t2)
	t1 = e.fp.Add(&x.A0, &x.A3)
	t1 = e.fp.Sub(t1, &x.A5)
	v5 := e.fp.Mul(t1, t1)
	v14 := e.fp.Mul(&x.A0, &x.A0)
	v15 := e.fp.Mul(&x.A1, &x.A1)
	v16 := e.fp.Mul(&x.A4, &x.A4)
	v17 := e.fp.Mul(&x.A5, &x.A5)
	v1 := e.fp.Zero()

	return [18]*baseEl{v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17}
}

func (e Ext6) mulMontgomery6(v [18]*baseEl) *E6 {
	// Then we compute the coefficients c0,c1,c3,c4 and c5 in the direct sextic
	// extension of the product x*y as follows:
	//
	// Ref.: Peter L. Montgomery. Five, six, and seven-term Karatsuba-like formulae. IEEE
	// Transactions on Computers, 54(3):362–369, 2005.
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

	c0 := e.fp.Sub(v[0], v[2])
	c0 = e.fp.Add(c0, v[4])
	s1 := e.fp.Add(v[3], v[5])
	s1 = e.fp.Add(s1, v[6])
	s1 = e.fp.Sub(s1, v[12])
	s1 = e.fp.MulConst(s1, big.NewInt(2))
	c0 = e.fp.Add(c0, s1)
	s1 = e.fp.Add(v[7], v[15])
	s2 := e.fp.Add(v[8], v[10])
	s2 = e.fp.Add(s2, v[11])
	s1 = e.fp.Sub(s1, s2)
	s1 = e.fp.MulConst(s1, big.NewInt(3))
	c0 = e.fp.Add(c0, s1)
	s1 = e.fp.Sub(v[16], v[13])
	s1 = e.fp.MulConst(s1, big.NewInt(4))
	c0 = e.fp.Add(c0, s1)
	s1 = e.fp.Add(v[14], v[17])
	s1 = e.fp.MulConst(s1, big.NewInt(5))
	c0 = e.fp.Sub(c0, s1)
	c0 = mulFpByNonResidue(e.fp, c0)
	c0 = e.fp.Add(c0, v[14])

	c1 := e.fp.Add(v[15], v[14])
	c1 = e.fp.Sub(v[12], c1)
	s2 = e.fp.Add(v[3], v[5])
	s2 = e.fp.Add(s2, v[6])
	s2 = e.fp.Add(s2, v[15])
	s1 = e.fp.Add(v[10], v[8])
	s1 = e.fp.Add(s1, v[12])
	s1 = e.fp.Sub(s1, s2)
	s2 = e.fp.Add(v[14], v[17])
	s2 = e.fp.Add(s2, v[13])
	s2 = e.fp.Sub(s2, v[7])
	s2 = e.fp.MulConst(s2, big.NewInt(2))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.Sub(v[11], v[16])
	s2 = e.fp.MulConst(s2, big.NewInt(3))
	s1 = e.fp.Add(s1, s2)
	s1 = mulFpByNonResidue(e.fp, s1)
	c1 = e.fp.Add(c1, s1)

	c2 := e.fp.MulConst(v[15], big.NewInt(2))
	c2 = e.fp.Add(c2, v[6])
	s1 = e.fp.Add(v[10], v[12])
	c2 = e.fp.Sub(c2, s1)
	s2 = e.fp.Add(v[11], v[13])
	s1 = e.fp.MulConst(v[16], big.NewInt(2))
	s1 = e.fp.Add(s1, v[7])
	s1 = e.fp.Sub(s1, s2)
	s1 = mulFpByNonResidue(e.fp, s1)
	c2 = e.fp.Add(c2, s1)

	c3 := e.fp.Add(v[8], v[11])
	c3 = e.fp.Add(c3, v[13])
	s1 = e.fp.Add(v[3], v[4])
	s1 = e.fp.Add(s1, v[7])
	s1 = e.fp.Add(s1, v[16])
	c3 = e.fp.Sub(c3, s1)
	s1 = e.fp.Sub(v[10], v[15])
	s1 = e.fp.MulConst(s1, big.NewInt(3))
	c3 = e.fp.Add(c3, s1)
	s1 = e.fp.Add(v[12], v[14])
	s1 = e.fp.Add(s1, v[17])
	s1 = e.fp.Sub(s1, v[6])
	s1 = e.fp.MulConst(s1, big.NewInt(2))
	c3 = e.fp.Add(c3, s1)
	s2 = e.fp.Add(v[16], v[17])
	s1 = e.fp.Sub(v[13], s2)
	s1 = mulFpByNonResidue(e.fp, s1)
	c3 = e.fp.Add(c3, s1)

	c4 := e.fp.Add(v[2], v[3])
	c4 = e.fp.Add(c4, v[4])
	c4 = e.fp.Add(c4, v[7])
	c4 = e.fp.Add(c4, v[15])
	c4 = e.fp.Add(c4, v[9])
	s1 = e.fp.Add(v[8], v[13])
	c4 = e.fp.Sub(c4, s1)
	s1 = e.fp.MulConst(v[12], big.NewInt(3))
	c4 = e.fp.Sub(c4, s1)
	s1 = e.fp.Add(v[10], v[17])
	s1 = e.fp.Add(s1, v[11])
	s1 = e.fp.Add(s1, v[14])
	s1 = e.fp.Sub(v[6], s1)
	s1 = e.fp.MulConst(s1, big.NewInt(2))
	c4 = e.fp.Add(c4, s1)
	s1 = mulFpByNonResidue(e.fp, v[17])
	c4 = e.fp.Add(c4, s1)

	c5 := e.fp.Add(v[8], v[10])
	c5 = e.fp.Add(c5, v[11])
	c5 = e.fp.Add(c5, v[12])
	c5 = e.fp.Add(c5, v[13])
	s1 = e.fp.Add(v[6], v[7])
	c5 = e.fp.Sub(c5, s1)
	c5 = e.fp.MulConst(c5, big.NewInt(2))
	s1 = e.fp.Add(v[14], v[17])
	s1 = e.fp.MulConst(s1, big.NewInt(3))
	c5 = e.fp.Add(c5, s1)
	s1 = e.fp.Add(v[3], v[4])
	s1 = e.fp.Add(s1, v[5])
	s1 = e.fp.Add(s1, v[9])
	s1 = e.fp.Add(s1, v[15])
	s1 = e.fp.Add(s1, v[16])
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

func (e Ext6) Square(x *E6) *E6 {
	x = e.Reduce(x)
	v := e.interpolationX6Sq(x)
	return e.mulMontgomery6(v)
	// return e.mulToomCook6(v)
}

/*
func (e Ext6) MulToomCook6x(x, y *E6) *E6 {
	//	Then we compute the product  362880*x*y to avoid divisions:
	//
	//		c0 = 362880v0 + β(−18900v0 + 14616v2 − 6552(v3 + v4) + 1512(v5 +
	//		v6) − 126(v7 + v8) + 99066240v10)
	//
	//		c1 = −(72576v0 + 241920v2 + 120960v3 - 51840v4 - 34560v5 + 8640v6 +
	//		6480v7 - 720v8 - 576v9 + 1045094400v10 + β(-3780v0 + 2016v2 -
	//		3024v3 - 576v4 + 1296v5 + 54v6 - 306v7 + 6v8 + 30v9 - 54432000v10))
	//
	//		c2 = −516600v0 + 290304v2 − 36288(v3 + v4) + 4608(v5 + v6) − 324(v7
	//		+ v8) + 209018880v10 + β(630v0 − 504v2 + 252(v3 + v4) − 72(v5 + v6)
	//		+ 9(v7 + v8) − 10886400v10)
	//
	//		c3 = 103320v0 + 54096v2 + 154056v3 − 55656v4 − 47664v5 + 10764v6 +
	//		9144v7 − 944v8 − 820v9 + 1487808000v10 + β(−126v0 + 84(v2 − v3) −
	//		36(v4 + v5) + 9(v6 − v7) − (v8 + v9) − 1814400v10)
	//
	//		c4 = 171990v0 − 122976v2 + 42588(v3 + v4) − 6048(v5 + v6) + 63(v7 +
	//		v8) − 297561600v10 + β(362880v10)
	//
	//		c5 = −34398v0 + 8316v2 + 14364v5 − 36036v3 + 3276v4 − 2079v6 −
	//		2961v7 + 231v8 + 273v9 − 495331200v10.

	t1 = e.fp.Add(v3, v4) // v3 + v4
	t2 = e.fp.Add(v5, v6) // v5 + v6
	t3 = e.fp.Add(v7, v8) // v7 + v8
	t4 = e.fp.Add(v4, v5) // v4 + v5
	// _t0 = e.fp.Add(v8, v9) // v8 + v9

	c0 := e.fp.MulConst(t2, big.NewInt(1512))
	s1 = e.fp.MulConst(t1, big.NewInt(6552))
	c0 = e.fp.Sub(c0, s1)
	s1 = e.fp.MulConst(v2, big.NewInt(14616))
	c0 = e.fp.Add(c0, s1)
	s1 = e.fp.MulConst(v0, big.NewInt(18900))
	c0 = e.fp.Sub(c0, s1)
	s1 = e.fp.MulConst(v10, big.NewInt(99066240))
	c0 = e.fp.Add(c0, s1)
	s1 = e.fp.MulConst(t3, big.NewInt(126))
	c0 = e.fp.Sub(c0, s1)
	c0 = mulFpByNonResidue(e.fp, c0)
	s1 = e.fp.MulConst(v0, big.NewInt(362880))
	c0 = e.fp.Add(c0, s1)

	c1 := e.fp.MulConst(v0, big.NewInt(72576))
	s1 = e.fp.MulConst(v2, big.NewInt(241920))
	c1 = e.fp.Add(c1, s1)
	s1 = e.fp.MulConst(v3, big.NewInt(120960))
	c1 = e.fp.Add(c1, s1)
	s1 = e.fp.MulConst(v4, big.NewInt(51840))
	c1 = e.fp.Sub(c1, s1)
	s1 = e.fp.MulConst(v5, big.NewInt(34560))
	c1 = e.fp.Sub(c1, s1)
	s1 = e.fp.MulConst(v6, big.NewInt(8640))
	c1 = e.fp.Add(c1, s1)
	s1 = e.fp.MulConst(v7, big.NewInt(6480))
	c1 = e.fp.Add(c1, s1)
	s1 = e.fp.MulConst(v8, big.NewInt(720))
	c1 = e.fp.Sub(c1, s1)
	s1 = e.fp.MulConst(v9, big.NewInt(576))
	c1 = e.fp.Sub(c1, s1)
	s1 = e.fp.MulConst(v10, big.NewInt(1045094400))
	c1 = e.fp.Add(c1, s1)
	s1 = e.fp.MulConst(v0, big.NewInt(3780))
	s2 = e.fp.MulConst(v2, big.NewInt(2016))
	s1 = e.fp.Sub(s2, s1)
	s2 = e.fp.MulConst(v3, big.NewInt(3024))
	s1 = e.fp.Sub(s1, s2)
	s2 = e.fp.MulConst(v4, big.NewInt(576))
	s1 = e.fp.Sub(s1, s2)
	s2 = e.fp.MulConst(v5, big.NewInt(1296))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v6, big.NewInt(54))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v7, big.NewInt(306))
	s1 = e.fp.Sub(s1, s2)
	s2 = e.fp.MulConst(v8, big.NewInt(6))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v9, big.NewInt(30))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v10, big.NewInt(54432000))
	s1 = e.fp.Sub(s1, s2)
	s1 = mulFpByNonResidue(e.fp, s1)
	c1 = e.fp.Add(c1, s1)
	c1 = e.fp.Neg(c1)

	c2 := e.fp.MulConst(v2, big.NewInt(290304))
	s1 = e.fp.MulConst(t1, big.NewInt(36288))
	c2 = e.fp.Sub(c2, s1)
	s1 = e.fp.MulConst(v0, big.NewInt(516600))
	c2 = e.fp.Sub(c2, s1)
	s1 = e.fp.MulConst(t2, big.NewInt(4608))
	c2 = e.fp.Add(c2, s1)
	s1 = e.fp.MulConst(t3, big.NewInt(324))
	c2 = e.fp.Sub(c2, s1)
	s1 = e.fp.MulConst(v10, big.NewInt(209018880))
	c2 = e.fp.Add(c2, s1)
	s2 = e.fp.MulConst(v0, big.NewInt(630))
	s1 = e.fp.MulConst(v2, big.NewInt(504))
	s1 = e.fp.Sub(s2, s1)
	s2 = e.fp.MulConst(t1, big.NewInt(252))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(t2, big.NewInt(72))
	s1 = e.fp.Sub(s1, s2)
	s2 = e.fp.MulConst(t3, big.NewInt(9))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v10, big.NewInt(10886400))
	s1 = e.fp.Sub(s1, s2)
	s1 = mulFpByNonResidue(e.fp, s1)
	c2 = e.fp.Add(c2, s1)

	c3 := e.fp.MulConst(v0, big.NewInt(103320))
	s1 = e.fp.MulConst(v2, big.NewInt(54096))
	c3 = e.fp.Add(c3, s1)
	s1 = e.fp.MulConst(v3, big.NewInt(154056))
	c3 = e.fp.Add(c3, s1)
	s1 = e.fp.MulConst(v4, big.NewInt(55656))
	c3 = e.fp.Sub(c3, s1)
	s1 = e.fp.MulConst(v5, big.NewInt(47664))
	c3 = e.fp.Sub(c3, s1)
	s1 = e.fp.MulConst(v6, big.NewInt(10764))
	c3 = e.fp.Add(c3, s1)
	s1 = e.fp.MulConst(v7, big.NewInt(9144))
	c3 = e.fp.Add(c3, s1)
	s1 = e.fp.MulConst(v8, big.NewInt(944))
	c3 = e.fp.Sub(c3, s1)
	s1 = e.fp.MulConst(v9, big.NewInt(820))
	c3 = e.fp.Sub(c3, s1)
	s1 = e.fp.MulConst(v10, big.NewInt(1487808000))
	c3 = e.fp.Add(c3, s1)
	s1 = e.fp.MulConst(v0, big.NewInt(126))
	s2 = e.fp.Sub(v2, v3)
	s2 = e.fp.MulConst(s2, big.NewInt(84))
	s1 = e.fp.Sub(s2, s1)
	s2 = e.fp.Add(v4, v5)
	s2 = e.fp.MulConst(s2, big.NewInt(36))
	s1 = e.fp.Sub(s1, s2)
	s2 = e.fp.Sub(v6, v7)
	s2 = e.fp.MulConst(s2, big.NewInt(9))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v10, big.NewInt(1814400))
	s2 = e.fp.Add(s2, v8)
	s2 = e.fp.Add(s2, v9)
	s1 = e.fp.Sub(s1, s2)
	s1 = mulFpByNonResidue(e.fp, s1)
	c3 = e.fp.Add(c3, s1)

	c4 := e.fp.MulConst(v0, big.NewInt(171990))
	s1 = e.fp.MulConst(v2, big.NewInt(122976))
	c4 = e.fp.Sub(c4, s1)
	s1 = e.fp.MulConst(t1, big.NewInt(42588))
	c4 = e.fp.Add(c4, s1)
	s1 = e.fp.MulConst(t2, big.NewInt(6048))
	c4 = e.fp.Sub(c4, s1)
	s1 = e.fp.MulConst(t3, big.NewInt(63))
	c4 = e.fp.Add(c4, s1)
	s1 = e.fp.MulConst(v10, big.NewInt(297561600))
	c4 = e.fp.Sub(c4, s1)
	s1 = e.fp.MulConst(v10, big.NewInt(362880))
	s1 = mulFpByNonResidue(e.fp, s1)
	c4 = e.fp.Add(c4, s1)

	c5 := e.fp.MulConst(v2, big.NewInt(8316))
	s1 = e.fp.MulConst(v0, big.NewInt(34398))
	c5 = e.fp.Sub(c5, s1)
	s1 = e.fp.MulConst(v5, big.NewInt(14364))
	c5 = e.fp.Add(c5, s1)
	s1 = e.fp.MulConst(v3, big.NewInt(36036))
	c5 = e.fp.Sub(c5, s1)
	s1 = e.fp.MulConst(v4, big.NewInt(3276))
	c5 = e.fp.Add(c5, s1)
	s1 = e.fp.MulConst(v6, big.NewInt(2079))
	c5 = e.fp.Sub(c5, s1)
	s1 = e.fp.MulConst(v7, big.NewInt(2961))
	c5 = e.fp.Sub(c5, s1)
	s1 = e.fp.MulConst(v8, big.NewInt(231))
	c5 = e.fp.Add(c5, s1)
	s1 = e.fp.MulConst(v9, big.NewInt(273))
	c5 = e.fp.Add(c5, s1)
	s1 = e.fp.MulConst(v10, big.NewInt(495331200))
	c5 = e.fp.Sub(c5, s1)

	inv362880 := emulated.ValueOf[emulated.BW6761Fp]("4671422665851984694040348663017660157508519176517181272289218522372474038323623073011971993796055931265397672069676435635279488178552288409646583546248183456271259848848724056226545014884280653287710097584502403952205015690976464")

	return &E6{
		A0: *e.fp.Mul(&inv362880, c0),
		A1: *e.fp.Mul(&inv362880, c1),
		A2: *e.fp.Mul(&inv362880, c2),
		A3: *e.fp.Mul(&inv362880, c3),
		A4: *e.fp.Mul(&inv362880, c4),
		A5: *e.fp.Mul(&inv362880, c5),
	}
}
*/

// Karabina's compressed cyclotomic square SQR12345
// https://eprint.iacr.org/2010/542.pdf
// Sec. 5.6 with minor modifications to fit our tower
func (e Ext6) CyclotomicSquareKarabina12345(x *E6) *E6 {
	x = e.Reduce(x)

	// h4 = -g4 + 3((g3+g5)(g1+c*g2)-g1g5-c*g3g2)
	g1g5 := e.fp.Mul(&x.A2, &x.A5)
	g3g2 := e.fp.Mul(&x.A1, &x.A4)
	h4 := mulFpByNonResidue(e.fp, &x.A4)
	h4 = e.fp.Add(h4, &x.A2)
	t := e.fp.Add(&x.A1, &x.A5)
	h4 = e.fp.Mul(h4, t)
	h4 = e.fp.Sub(h4, g1g5)
	t = e.fp.MulConst(g3g2, big.NewInt(4))
	h4 = e.fp.Add(h4, t)
	h4 = e.fp.MulConst(h4, big.NewInt(3))
	h4 = e.fp.Sub(h4, &x.A3)

	// h3 = 2(g3+3c*g1g5)
	h3 := mulFpByNonResidue(e.fp, g1g5)
	h3 = e.fp.MulConst(h3, big.NewInt(3))
	h3 = e.fp.Add(h3, &x.A1)
	h3 = e.fp.MulConst(h3, big.NewInt(2))

	// h2 = 3((g1+g5)(g1+c*g5)-(c+1)*g1g5)-2g2
	t = mulFpByNonResidue(e.fp, &x.A5)
	t = e.fp.Add(t, &x.A2)
	h2 := e.fp.Add(&x.A5, &x.A2)
	h2 = e.fp.Mul(h2, t)
	t = e.fp.MulConst(g1g5, big.NewInt(3))
	h2 = e.fp.Add(h2, t)
	h2 = e.fp.MulConst(h2, big.NewInt(3))
	t = e.fp.MulConst(&x.A4, big.NewInt(2))
	h2 = e.fp.Sub(h2, t)

	// h1 = 3((g3+g2)(g3+c*g2)-(c+1)*g3g2)-2g1
	t = mulFpByNonResidue(e.fp, &x.A4)
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

// Granger-Scott's cyclotomic square
// https://eprint.iacr.org/2009/565.pdf, 3.2
func (e Ext6) CyclotomicSquare(x *E6) *E6 {
	// x=(x0,x1,x2,x3,x4,x5,x6,x7) in E3⁶
	// cyclosquare(x)=(3*x4²*u + 3*x0² - 2*x0,
	//					3*x2²*u + 3*x3² - 2*x1,
	//					3*x5²*u + 3*x1² - 2*x2,
	//					6*x1*x5*u + 2*x3,
	//					6*x0*x4 + 2*x4,
	//					6*x2*x3 + 2*x5)

	x = e.Reduce(x)

	var t [9]*baseEl

	t[0] = e.fp.Mul(&x.A3, &x.A3)
	t[1] = e.fp.Mul(&x.A0, &x.A0)
	t[6] = e.fp.Add(&x.A3, &x.A0)
	t[6] = e.fp.Mul(t[6], t[6])
	t[6] = e.fp.Sub(t[6], t[0])
	t[6] = e.fp.Sub(t[6], t[1]) // 2*x4*x0
	t[2] = e.fp.Mul(&x.A4, &x.A4)
	t[3] = e.fp.Mul(&x.A1, &x.A1)
	t[7] = e.fp.Add(&x.A4, &x.A1)
	t[7] = e.fp.Mul(t[7], t[7])
	t[7] = e.fp.Sub(t[7], t[2])
	t[7] = e.fp.Sub(t[7], t[3]) // 2*x2*x3
	t[4] = e.fp.Mul(&x.A5, &x.A5)
	t[5] = e.fp.Mul(&x.A2, &x.A2)
	t[8] = e.fp.Add(&x.A5, &x.A2)
	t[8] = e.fp.Mul(t[8], t[8])
	t[8] = e.fp.Sub(t[8], t[4])
	t[8] = e.fp.Sub(t[5], t[8])
	t[8] = e.fp.MulConst(t[8], big.NewInt(4)) // 2*x5*x1*u

	t[0] = mulFpByNonResidue(e.fp, t[0])
	t[0] = e.fp.Add(t[0], t[1]) // x4²*u + x0²
	t[2] = mulFpByNonResidue(e.fp, t[2])
	t[2] = e.fp.Add(t[2], t[3]) // x2²*u + x3²
	t[4] = mulFpByNonResidue(e.fp, t[4])
	t[4] = e.fp.Add(t[4], t[5]) // x5²*u + x1²

	var z E6
	z.A0 = *e.fp.Sub(t[0], &x.A0)
	z.A0 = *e.fp.MulConst(&z.A0, big.NewInt(2))
	z.A0 = *e.fp.Add(&z.A0, t[0])
	z.A2 = *e.fp.Sub(t[2], &x.A2)
	z.A2 = *e.fp.MulConst(&z.A2, big.NewInt(2))
	z.A2 = *e.fp.Add(&z.A2, t[2])
	z.A4 = *e.fp.Sub(t[4], &x.A4)
	z.A4 = *e.fp.MulConst(&z.A4, big.NewInt(2))
	z.A4 = *e.fp.Add(&z.A4, t[4])

	z.A1 = *e.fp.Add(t[8], &x.A1)
	z.A1 = *e.fp.MulConst(&z.A1, big.NewInt(2))
	z.A1 = *e.fp.Add(&z.A1, t[8])
	z.A3 = *e.fp.Add(t[6], &x.A3)
	z.A3 = *e.fp.MulConst(&z.A3, big.NewInt(2))
	z.A3 = *e.fp.Add(&z.A3, t[6])
	z.A5 = *e.fp.Add(t[7], &x.A5)
	z.A5 = *e.fp.Add(&z.A5, &z.A5)
	z.A5 = *e.fp.Add(&z.A5, t[7])

	return &z
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
	_frobAC := emulated.ValueOf[emulated.BW6761Fp]("-1")
	_frobBC := emulated.ValueOf[emulated.BW6761Fp]("1968985824090209297278610739700577151397666382303825728450741611566800370218827257750865013421937292370006175842381275743914023380727582819905021229583192207421122272650305267822868639090213645505120388400344940985710520836292651")
	var z E6
	z.A0 = x.A0
	z.A2 = *e.fp.Mul(&x.A2, &_frobA)
	z.A4 = *e.fp.Mul(&x.A4, &_frobB)
	z.A1 = *e.fp.Mul(&x.A1, &_frobC)
	z.A3 = *e.fp.Mul(&x.A3, &_frobAC)
	z.A5 = *e.fp.Mul(&x.A5, &_frobBC)

	return &z
}
