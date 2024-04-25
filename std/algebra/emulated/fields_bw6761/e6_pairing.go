package fields_bw6761

import (
	"math/big"
	// "github.com/consensys/gnark/std/math/emulated"
)

func (e Ext6) nSquareKarabina12345(z *E6, n int) *E6 {
	for i := 0; i < n; i++ {
		z = e.CyclotomicSquareKarabina12345(z)
	}
	z = e.DecompressKarabina12345(z)
	return z
}

// ExpX0Minus1 set z to z^{x₀-1} in E6 and return z
// x₀-1 = 9586122913090633728
func (e Ext6) ExpX0Minus1(z *E6) *E6 {
	z = e.Reduce(z)
	result := e.Copy(z)
	result = e.nSquareKarabina12345(result, 5)
	result = e.Mul(result, z)
	z33 := e.Copy(result)
	result = e.nSquareKarabina12345(result, 7)
	result = e.Mul(result, z33)
	result = e.nSquareKarabina12345(result, 4)
	result = e.Mul(result, z)
	result = e.CyclotomicSquare(result)
	result = e.Mul(result, z)
	result = e.nSquareKarabina12345(result, 46)

	return result
}

// ExpX0Minus1Square set z to z^{(x₀-1)²} in E6 and return z
// (x₀-1)² = 91893752504881257682351033800651177984
func (e Ext6) ExpX0Minus1Square(z *E6) *E6 {
	z = e.Reduce(z)
	result := e.Copy(z)
	result = e.nSquareKarabina12345(result, 3)
	t0 := e.CyclotomicSquare(result)
	t2 := e.Mul(z, t0)
	result = e.Mul(result, t2)
	t0 = e.Mul(z, result)
	t1 := e.CyclotomicSquare(t0)
	t1 = e.Mul(t2, t1)
	t3 := e.nSquareKarabina12345(t1, 7)
	t2 = e.Mul(t2, t3)
	t2 = e.nSquareKarabina12345(t2, 11)
	t1 = e.Mul(t1, t2)
	t0 = e.Mul(t0, t1)
	t0 = e.nSquareKarabina12345(t0, 7)
	result = e.Mul(result, t0)
	result = e.nSquareKarabina12345(result, 3)
	result = e.Mul(z, result)
	result = e.nSquareKarabina12345(result, 92)

	return result

}

// ExpX0Plus1 set z to z^(x₀+1) in E6 and return z
// x₀+1 = 9586122913090633730
func (e Ext6) ExpX0Plus1(z *E6) *E6 {
	z = e.Reduce(z)
	result := e.Copy(z)
	t := e.CyclotomicSquare(result)
	result = e.nSquareKarabina12345(t, 4)
	result = e.Mul(result, z)
	z33 := e.Copy(result)
	result = e.nSquareKarabina12345(result, 7)
	result = e.Mul(result, z33)
	result = e.nSquareKarabina12345(result, 4)
	result = e.Mul(result, z)
	result = e.CyclotomicSquare(result)
	result = e.Mul(result, z)
	result = e.nSquareKarabina12345(result, 46)
	result = e.Mul(result, t)

	return result
}

// ExpX0Minus1Div3 set z to z^(x₀-1)/3 in E6 and return z
// (x₀-1)/3 = 3195374304363544576
func (e Ext6) ExptMinus1Div3(z *E6) *E6 {
	z = e.Reduce(z)
	result := e.Copy(z)
	result = e.CyclotomicSquare(result)
	result = e.CyclotomicSquare(result)
	result = e.Mul(result, z)
	result = e.CyclotomicSquare(result)
	result = e.Mul(result, z)
	t0 := e.nSquareKarabina12345(result, 7)
	result = e.Mul(result, t0)
	result = e.nSquareKarabina12345(result, 5)
	result = e.Mul(result, z)
	result = e.nSquareKarabina12345(result, 46)

	return result
}

// ExpC1 set z to z^C1 in E6 and return z
// ht, hy = 13, 9
// C1 = (ht+hy)/2 = 11
func (e Ext6) ExpC1(z *E6) *E6 {
	z = e.Reduce(z)
	result := e.Copy(z)
	result = e.CyclotomicSquare(result)
	result = e.CyclotomicSquare(result)
	result = e.Mul(result, z)
	result = e.CyclotomicSquare(result)
	result = e.Mul(result, z)

	return result
}

// ExpC2 set z to z^C2 in E6 and return z
// ht, hy = 13, 9
// C2 = (ht**2+3*hy**2)/4 = 103
func (e Ext6) ExpC2(z *E6) *E6 {
	z = e.Reduce(z)
	result := e.CyclotomicSquare(z)
	result = e.Mul(result, z)
	t0 := e.nSquareKarabina12345(result, 4)
	result = e.Mul(result, t0)
	result = e.CyclotomicSquare(result)
	result = e.Mul(result, z)

	return result
}

// MulBy023 multiplies z by an E6 sparse element of the form
//
//	E6{A0: c0, A1: 0, A2: c1, A3: 1,  A4: 0,  A5: 0}
func (e *Ext6) MulBy023(x *E6, c0, c1 *baseEl) *E6 {
	x = e.Reduce(x)
	//		v0 = (a0 + a1 + a2 + a3 + a4 + a5)(c0 + c1 + 1)
	//		v2 = (a0 + a1 + a3 + a4)(c0 + 1)
	//		v3 = (a0 − a2 − a3 + a5)(c0 − c1 − 1)
	//		v4 = (a0 − a2 − a5)(c0 − c1)
	//		v5 = (a0 + a3 − a5)(c0 + 1)
	//		v6 = (a0 + a1 + a2)(c0 + c1)
	//		v7 = (a3 + a4 + a5)
	//		v8 = (a2 + a3)(c1 + 1)
	//		v10 = (a1 + a2)c1
	//		v11 = (a3 + a4)
	//		v12 = (a0 + a1)c0
	//		v14 = a0c0

	_t0 := e.fp.Add(&x.A0, &x.A1)
	t0 := e.fp.Add(_t0, &x.A2)
	t1 := e.fp.Add(&x.A3, &x.A4)
	t2 := e.fp.Add(_t0, t1)
	t3 := e.fp.Add(t2, &x.A5)
	t3 = e.fp.Add(t3, &x.A2)

	s0 := e.fp.Add(c0, c1)
	one := e.fp.One()
	s2 := e.fp.Add(c0, one)
	s3 := e.fp.Add(s2, c1)

	v0 := e.fp.Mul(t3, s3)
	v2 := e.fp.Mul(t2, s2)
	v6 := e.fp.Mul(t0, s0)
	t4 := e.fp.Add(t1, &x.A5)
	v7 := t4
	v12 := e.fp.Mul(_t0, c0)
	v11 := t1
	t0 = e.fp.Add(&x.A2, &x.A3)
	s0 = e.fp.Add(c1, one)
	v8 := e.fp.Mul(t0, s0)
	t1 = e.fp.Add(&x.A1, &x.A2)
	v10 := e.fp.Mul(t1, c1)
	v3 := e.fp.Add(&x.A0, &x.A5)
	v3 = e.fp.Sub(v3, t0)
	s1 := e.fp.Sub(c0, s0)
	v3 = e.fp.Mul(v3, s1)
	t1 = e.fp.Add(&x.A2, &x.A5)
	t2 = e.fp.Sub(&x.A0, t1)
	s2 = e.fp.Sub(c0, c1)
	v4 := e.fp.Mul(t2, s2)
	t1 = e.fp.Add(&x.A0, &x.A3)
	t1 = e.fp.Sub(t1, &x.A5)
	s1 = e.fp.Add(c0, one)
	v5 := e.fp.Mul(t1, s1)
	v14 := e.fp.Mul(&x.A0, c0)

	z0 := e.fp.Sub(v0, v2)
	z0 = e.fp.Add(z0, v4)
	s1 = e.fp.Add(v3, v5)
	s1 = e.fp.Add(s1, v6)
	s1 = e.fp.Sub(s1, v12)
	s1 = e.fp.MulConst(s1, big.NewInt(2))
	z0 = e.fp.Add(z0, s1)
	s2 = e.fp.Add(v8, v10)
	s2 = e.fp.Add(s2, v11)
	s1 = e.fp.Sub(v7, s2)
	s1 = e.fp.MulConst(s1, big.NewInt(3))
	z0 = e.fp.Add(z0, s1)
	s1 = e.fp.MulConst(v14, big.NewInt(5))
	z0 = e.fp.Sub(z0, s1)
	z0 = mulFpByNonResidue(e.fp, z0)
	z0 = e.fp.Add(z0, v14)

	z1 := e.fp.Sub(v12, v14)
	s2 = e.fp.Add(v3, v5)
	s2 = e.fp.Add(s2, v6)
	s1 = e.fp.Add(v10, v8)
	s1 = e.fp.Add(s1, v12)
	s1 = e.fp.Sub(s1, s2)
	s2 = e.fp.Sub(v14, v7)
	s2 = e.fp.MulConst(s2, big.NewInt(2))
	s1 = e.fp.Add(s1, s2)
	s2 = e.fp.MulConst(v11, big.NewInt(3))
	s1 = e.fp.Add(s1, s2)
	s1 = mulFpByNonResidue(e.fp, s1)
	z1 = e.fp.Add(z1, s1)

	z2 := v6
	s1 = e.fp.Add(v10, v12)
	z2 = e.fp.Sub(z2, s1)
	s1 = e.fp.Sub(v7, v11)
	s1 = mulFpByNonResidue(e.fp, s1)
	z2 = e.fp.Add(z2, s1)

	z3 := e.fp.Add(v8, v11)
	s1 = e.fp.Add(v3, v4)
	s1 = e.fp.Add(s1, v7)
	z3 = e.fp.Sub(z3, s1)
	s1 = e.fp.MulConst(v10, big.NewInt(3))
	z3 = e.fp.Add(z3, s1)
	s1 = e.fp.Add(v12, v14)
	s1 = e.fp.Sub(s1, v6)
	s1 = e.fp.MulConst(s1, big.NewInt(2))
	z3 = e.fp.Add(z3, s1)

	z4 := e.fp.Add(v2, v3)
	z4 = e.fp.Add(z4, v4)
	z4 = e.fp.Add(z4, v7)
	z4 = e.fp.Sub(z4, v8)
	s1 = e.fp.MulConst(v12, big.NewInt(3))
	z4 = e.fp.Sub(z4, s1)
	s1 = e.fp.Add(v10, v11)
	s1 = e.fp.Add(s1, v14)
	s1 = e.fp.Sub(v6, s1)
	s1 = e.fp.MulConst(s1, big.NewInt(2))
	z4 = e.fp.Add(z4, s1)

	z5 := e.fp.Add(v8, v10)
	z5 = e.fp.Add(z5, v11)
	z5 = e.fp.Add(z5, v12)
	s1 = e.fp.Add(v6, v7)
	z5 = e.fp.Sub(z5, s1)
	z5 = e.fp.MulConst(z5, big.NewInt(2))
	s1 = e.fp.MulConst(v14, big.NewInt(3))
	z5 = e.fp.Add(z5, s1)
	s1 = e.fp.Add(v3, v4)
	s1 = e.fp.Add(s1, v5)
	z5 = e.fp.Sub(z5, s1)

	return &E6{
		A0: *z0,
		A1: *z1,
		A2: *z2,
		A3: *z3,
		A4: *z4,
		A5: *z5,
	}
}

/*
//	Mul023By023 multiplies two E6 sparse element of the form:
//
//	E6{A0: c0, A1: 0, A2: c1, A3: 1,  A4: 0,  A5: 0}
//
// and
//
//	E6{A0: c0, A1: 0, A2: c1, A3: 1,  A4: 0,  A5: 0}
func (e Ext6) Mul023By023(d0, d1, c0, c1 *baseEl) [5]*baseEl {
	x0 := e.fp.Mul(c0, d0)
	x1 := e.fp.Mul(c1, d1)
	x04 := e.fp.Add(c0, d0)
	tmp := e.fp.Add(c0, c1)
	x01 := e.fp.Add(d0, d1)
	x01 = e.fp.Mul(x01, tmp)
	tmp = e.fp.Add(x0, x1)
	x01 = e.fp.Sub(x01, tmp)
	x14 := e.fp.Add(c1, d1)

	four := emulated.ValueOf[emulated.BW6761Fp](big.NewInt(4))
	zC0B0 := e.fp.Sub(x0, &four)

	return [5]*baseEl{zC0B0, x01, x1, x04, x14}
}

// MulBy01245 multiplies z by an E6 sparse element of the form
//
//	E6{
//		B0: E3{A0: c0, A1: c1, A2: c2},
//		B1: E3{A0: 0, A1: c4, A2: c5},
//	}
func (e *Ext6) MulBy01245(z *E6, x [5]*baseEl) *E6 {
	c0 := &E3{A0: *x[0], A1: *x[1], A2: *x[2]}
	a := e.Ext3.Add(&z.B0, &z.B1)
	b := &E3{
		A0: c0.A0,
		A1: *e.fp.Add(&c0.A1, x[3]),
		A2: *e.fp.Add(&c0.A2, x[4]),
	}
	a = e.Ext3.Mul(a, b)
	b = e.Ext3.Mul(&z.B0, c0)
	c := e.Ext3.MulBy12(&z.B1, x[3], x[4])
	z1 := e.Ext3.Sub(a, b)
	z1 = e.Ext3.Sub(z1, c)
	z0 := e.Ext3.MulByNonResidue(c)
	z0 = e.Ext3.Add(z0, b)
	return &E6{
		B0: *z0,
		B1: *z1,
	}
}

// Mul01245By014 multiplies two E6 sparse element of the form
//
//	E6{
//		C0: E3{B0: x0, B1: x1, B2: x2},
//		C1: E3{B0: 0,  B1: x4, B2: x5},
//	}
//
//	and
//
//	E6{
//		C0: E3{B0: d0, B1: d1, B2: 0},
//		C1: E3{B0: 0,  B1: 1,  B2: 0},
//	}
func (e *Ext6) Mul01245By014(x [5]*baseEl, d0, d1 *baseEl) *E6 {
	zero := e.fp.Zero()
	c0 := &E3{A0: *x[0], A1: *x[1], A2: *x[2]}
	b := &E3{
		A0: *x[0],
		A1: *e.fp.Add(x[1], x[3]),
		A2: *e.fp.Add(x[2], x[4]),
	}
	a := e.Ext3.MulBy01(b, d0, e.fp.Add(d1, e.fp.One()))
	b = e.Ext3.MulBy01(c0, d0, d1)
	c := &E3{
		A0: *e.fp.MulConst(x[4], big.NewInt(4)),
		A1: *e.fp.Neg(zero),
		A2: *e.fp.Neg(x[3]),
	}
	z1 := e.Ext3.Sub(a, b)
	z1 = e.Ext3.Add(z1, c)
	z0 := &E3{
		A0: *e.fp.MulConst(&c.A2, big.NewInt(4)),
		A1: *e.fp.Neg(&c.A0),
		A2: *e.fp.Neg(&c.A1),
	}

	z0 = e.Ext3.Add(z0, b)
	return &E6{
		B0: *z0,
		B1: *z1,
	}
}
*/
