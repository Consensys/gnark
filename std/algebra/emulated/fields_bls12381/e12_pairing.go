package fields_bls12381

func (e Ext12) nSquare(z *E12, n int) *E12 {
	for i := 0; i < n; i++ {
		z = e.Square(z)
	}
	return z
}

func (e Ext12) nSquareGS(z *E12, n int) *E12 {
	for i := 0; i < n; i++ {
		z = e.CyclotomicSquareGS(z)
	}
	return z
}

// ExptNeg sets z to x^t in E12 and return z
// where t = -u = 15132376222941642752
func (e Ext12) ExptNeg(x *E12) *E12 {
	// Expt computation is derived from the addition chain:
	//
	//	_10      = 2*1
	//	_11      = 1 + _10
	//	_1100    = _11 << 2
	//	_1101    = 1 + _1100
	//	_1101000 = _1101 << 3
	//	_1101001 = 1 + _1101000
	//	return     ((_1101001 << 9 + 1) << 32 + 1) << 15
	//
	// Operations: 62 squares 5 multiplies
	//
	// Generated by github.com/mmcloughlin/addchain v0.4.0.

	z := e.Square(x)
	z = e.Mul(x, z)
	z = e.nSquare(z, 2)
	z = e.Mul(x, z)
	z = e.nSquare(z, 3)
	z = e.Mul(x, z)
	z = e.nSquare(z, 9)
	z = e.Mul(x, z)
	z = e.nSquare(z, 32)
	z = e.Mul(x, z)
	z = e.nSquare(z, 15)
	z = e.Square(z)

	return z
}

// ExptGS sets z to x^t in E12 and return z
// where t = u = -15132376222941642752
func (e Ext12) ExptGS(x *E12) *E12 {
	// ExptGS computation is derived from the addition chain:
	//
	//	_10      = 2*1
	//	_11      = 1 + _10
	//	_1100    = _11 << 2
	//	_1101    = 1 + _1100
	//	_1101000 = _1101 << 3
	//	_1101001 = 1 + _1101000
	//	return     ((_1101001 << 9 + 1) << 32 + 1) << 15
	//
	// Operations: 62 squares 5 multiplies
	//
	// Generated by github.com/mmcloughlin/addchain v0.4.0.
	z := e.ExptHalfGS(x)
	z = e.CyclotomicSquareGS(z)
	return z
}

func (e Ext12) ExptHalfGS(x *E12) *E12 {
	z := e.CyclotomicSquareGS(x)
	z = e.Mul(x, z)
	z = e.nSquareGS(z, 2)
	z = e.Mul(x, z)
	z = e.nSquareGS(z, 3)
	z = e.Mul(x, z)
	z = e.nSquareGS(z, 9)
	z = e.Mul(x, z)
	z = e.nSquareGS(z, 32)
	z = e.Mul(x, z)
	z = e.nSquareGS(z, 15)
	z = e.Conjugate(z)

	return z
}

// MulBy02368 multiplies a by an E12 sparse element b of the form
//
//	b.A0  =  c00 - c01
//	b.A1  =  0
//	b.A2  =  c10 - c11
//	b.A3  =  1
//	b.A4  =  0
//	b.A5  =  0
//	b.A6  =  c01
//	b.A7  =  0
//	b.A8  =  c11
//	b.A9  =  0
//	b.A10 =  0
//	b.A11 =  0
func (e *Ext12) MulBy02368(a *E12, c0, c1 *E2) *E12 {
	b0 := e.fp.Sub(&c0.A0, &c0.A1)
	b2 := e.fp.Sub(&c1.A0, &c1.A1)
	b6 := &c0.A1
	b8 := &c1.A1
	mone := e.fp.NewElement(-1)

	// d0  =  a0 b0  - 2 * (a4 b8 + a6 b6 + a10 b2 + a9) - 4 * a10 b8
	d0 := e.fp.Eval([][]*baseEl{{&a.A0, b0}, {mone, &a.A4, b8}, {mone, &a.A6, b6}, {mone, &a.A9}, {mone, &a.A10, b2}, {mone, &a.A10, b8}}, []int{1, 2, 2, 2, 2, 4})

	// d1 = a1 b0  - 2 * (a5 b8 + a7 b6 + a11 b2 + a10) - 4 * a11 b8
	d1 := e.fp.Eval([][]*baseEl{{&a.A1, b0}, {mone, &a.A5, b8}, {mone, &a.A7, b6}, {mone, &a.A10}, {mone, &a.A11, b2}, {mone, &a.A11, b8}}, []int{1, 2, 2, 2, 2, 4})

	// d2 = a0 b2 + a2 b0  - 2 * (a6 b8 + a8 b6 + a11)
	d2 := e.fp.Eval([][]*baseEl{{&a.A0, b2}, {&a.A2, b0}, {mone, &a.A6, b8}, {mone, &a.A8, b6}, {mone, &a.A11}}, []int{1, 1, 2, 2, 2})

	// d3 = a0 + a1 b2 + a3 b0  - 2 * (a7 b8 + a9 b6)
	d3 := e.fp.Eval([][]*baseEl{{&a.A0}, {&a.A1, b2}, {&a.A3, b0}, {mone, &a.A7, b8}, {mone, &a.A9, b6}}, []int{1, 1, 1, 2, 2})

	// d4 = a1 + a2 b2 + a4 b0  - 2 * (a8 b8 + a10 b6)
	d4 := e.fp.Eval([][]*baseEl{{&a.A1}, {&a.A2, b2}, {&a.A4, b0}, {mone, &a.A8, b8}, {mone, &a.A10, b6}}, []int{1, 1, 1, 2, 2})

	// d5 = a2 + a3 b2 + a5 b0  - 2 * (a9 b8 + a11 b6)
	d5 := e.fp.Eval([][]*baseEl{{&a.A2}, {&a.A3, b2}, {&a.A5, b0}, {mone, &a.A9, b8}, {mone, &a.A11, b6}}, []int{1, 1, 1, 2, 2})

	// d6 = a0 b6 + a3 + a4 b2 + a6 b0  + 2 * (a4 b8 + a6 b6 + a9 + a10 b2 + a10 b8)
	d6 := e.fp.Eval([][]*baseEl{{&a.A0, b6}, {&a.A3}, {&a.A4, b2}, {&a.A6, b0}, {&a.A4, b8}, {&a.A6, b6}, {&a.A9}, {&a.A10, b2}, {&a.A10, b8}}, []int{1, 1, 1, 1, 2, 2, 2, 2, 2})

	// d7 = a1 b6 + a4 + a5 b2 + a7 b0  + 2 * (a5 b8 + a7 b6 + a10 + a11 b2 + a11 b8)
	d7 := e.fp.Eval([][]*baseEl{{&a.A1, b6}, {&a.A4}, {&a.A5, b2}, {&a.A7, b0}, {&a.A5, b8}, {&a.A7, b6}, {&a.A10}, {&a.A11, b2}, {&a.A11, b8}}, []int{1, 1, 1, 1, 2, 2, 2, 2, 2})

	// d8 = a0 b8 + a2 b6 + a5 + a6 b2 + a8 b0  + 2 * (a6 b8 + a8 b6 + a11)
	d8 := e.fp.Eval([][]*baseEl{{&a.A0, b8}, {&a.A2, b6}, {&a.A5}, {&a.A6, b2}, {&a.A8, b0}, {&a.A6, b8}, {&a.A8, b6}, {&a.A11}}, []int{1, 1, 1, 1, 1, 2, 2, 2})

	// d9 = a1 b8 + a3 b6 + a6 + a7 b2 + a9 b0  + 2 * (a7 b8 + a9 b6)
	d9 := e.fp.Eval([][]*baseEl{{&a.A1, b8}, {&a.A3, b6}, {&a.A6}, {&a.A7, b2}, {&a.A9, b0}, {&a.A7, b8}, {&a.A9, b6}}, []int{1, 1, 1, 1, 1, 2, 2})

	// d10 = a2 b8 + a4 b6 + a7 + a8 b2 + a10 b0 + 2 * (a8 b8 + a10 b6)
	d10 := e.fp.Eval([][]*baseEl{{&a.A2, b8}, {&a.A4, b6}, {&a.A7}, {&a.A8, b2}, {&a.A10, b0}, {&a.A8, b8}, {&a.A10, b6}}, []int{1, 1, 1, 1, 1, 2, 2})

	// d11 = a3 b8 + a5 b6 + a8 + a9 b2 + a11 b0 + 2 * (a9 b8 + a11 b6)
	d11 := e.fp.Eval([][]*baseEl{{&a.A3, b8}, {&a.A5, b6}, {&a.A8}, {&a.A9, b2}, {&a.A11, b0}, {&a.A9, b8}, {&a.A11, b6}}, []int{1, 1, 1, 1, 1, 2, 2})

	return &E12{
		A0:  *d0,
		A1:  *d1,
		A2:  *d2,
		A3:  *d3,
		A4:  *d4,
		A5:  *d5,
		A6:  *d6,
		A7:  *d7,
		A8:  *d8,
		A9:  *d9,
		A10: *d10,
		A11: *d11,
	}
}
