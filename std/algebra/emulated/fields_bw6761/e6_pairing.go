package fields_bw6761

func (e Ext6) nSquareCompressed(z *E6, n int) *E6 {
	for i := 0; i < n; i++ {
		z = e.CyclotomicSquareCompressed(z)
	}
	return z
}

// Expt set x to x^t in E6 and return x
func (e Ext6) Expt(x *E6) *E6 {
	x = e.Reduce(x)

	// const tAbsVal uint64 = 9586122913090633729
	// tAbsVal in binary: 1000010100001000110000000000000000000000000000000000000000000001
	// drop the low 46 bits (all 0 except the least significant bit): 100001010000100011 = 136227
	// Shortest addition chains can be found at https://wwwhomes.uni-bielefeld.de/achim/addition_chain.html

	// a shortest addition chain for 136227
	result := e.Copy(x)
	result = e.nSquareCompressed(result, 5)
	result = e.DecompressKarabina(result)
	result = e.Mul(result, x)
	x33 := e.Copy(result)
	result = e.nSquareCompressed(result, 7)
	result = e.DecompressKarabina(result)
	result = e.Mul(result, x33)
	result = e.nSquareCompressed(result, 4)
	result = e.DecompressKarabina(result)
	result = e.Mul(result, x)
	result = e.CyclotomicSquare(result)
	result = e.Mul(result, x)

	// the remaining 46 bits
	result = e.nSquareCompressed(result, 46)
	result = e.DecompressKarabina(result)
	result = e.Mul(result, x)

	return result
}

// ExptMinus1 set x to x^(t-1) in E6 and return x
func (e Ext6) ExptMinus1(x *E6) *E6 {
	result := e.Expt(x)
	result = e.Mul(result, e.Conjugate(x))
	return result
}

// ExptPlus1 set x to x^(t+1) in E6 and return x
func (e Ext6) ExptPlus1(x *E6) *E6 {
	result := e.Expt(x)
	result = e.Mul(result, x)
	return result
}

// ExptMinus1Div3 set x to x^(t-1)/3 in E6 and return x
func (e Ext6) ExptMinus1Div3(x *E6) *E6 {
	x = e.Reduce(x)
	result := e.Copy(x)
	result = e.CyclotomicSquare(result)
	result = e.Mul(result, x)
	t0 := e.Mul(result, x)
	t0 = e.CyclotomicSquare(t0)
	result = e.Mul(result, t0)
	t0 = e.CyclotomicSquare(result)
	t0 = e.nSquareCompressed(t0, 6)
	t0 = e.DecompressKarabina(t0)
	result = e.Mul(result, t0)
	result = e.nSquareCompressed(result, 5)
	result = e.DecompressKarabina(result)
	result = e.Mul(result, x)
	result = e.nSquareCompressed(result, 46)
	result = e.DecompressKarabina(result)

	return result
}

// Expc1 set x to x^c2 in E6 and return x
// ht, hy = 13, 9
// c1 = (ht+hy)/2 = 11
func (e Ext6) Expc1(x *E6) *E6 {
	x = e.Reduce(x)
	result := e.CyclotomicSquare(x)
	result = e.Mul(result, x)
	t0 := e.Mul(x, result)
	t0 = e.CyclotomicSquare(t0)
	result = e.Mul(result, t0)

	return result
}

// Expc2 set x to x^c1 in E6 and return x
// ht, hy = 13, 9
// c1 = (ht**2+3*hy**2)/4 = 103
func (e Ext6) Expc2(x *E6) *E6 {
	x = e.Reduce(x)

	result := e.CyclotomicSquare(x)
	result = e.Mul(result, x)
	t0 := e.CyclotomicSquare(result)
	t0 = e.nSquareCompressed(t0, 3)
	t0 = e.DecompressKarabina(t0)
	result = e.Mul(result, t0)
	result = e.CyclotomicSquare(result)
	result = e.Mul(result, x)

	return result
}

// Square034 squares an E6 sparse element of the form
//
//	E6{
//		B0: E3{A0: 1,  A1: 0,  A2: 0},
//		B1: E3{A0: c3, A1: c4, A2: 0},
//	}
func (e *Ext6) Square034(x *E6) *E6 {
	c0 := E3{
		A0: *e.fp.Sub(&x.B0.A0, &x.B1.A0),
		A1: *e.fp.Neg(&x.B1.A1),
		A2: *e.fp.Zero(),
	}

	c3 := E3{
		A0: x.B0.A0,
		A1: *e.fp.Neg(&x.B1.A0),
		A2: *e.fp.Neg(&x.B1.A1),
	}

	c2 := E3{
		A0: x.B1.A0,
		A1: x.B1.A1,
		A2: *e.fp.Zero(),
	}
	c3 = *e.MulBy01(&c3, &c0.A0, &c0.A1)
	c3 = *e.Ext3.Add(&c3, &c2)

	var z E6
	z.B1.A0 = *e.fp.Add(&c2.A0, &c2.A0)
	z.B1.A1 = *e.fp.Add(&c2.A1, &c2.A1)

	z.B0.A0 = c3.A0
	z.B0.A1 = *e.fp.Add(&c3.A1, &c2.A0)
	z.B0.A2 = *e.fp.Add(&c3.A2, &c2.A1)

	return &z
}

// MulBy034 multiplies z by an E6 sparse element of the form
//
//	E6{
//		B0: E3{A0: 1,  A1: 0,  A2: 0},
//		B1: E3{A0: c3, A1: c4, A2: 0},
//	}
func (e *Ext6) MulBy034(z *E6, c3, c4 *baseEl) *E6 {

	a := z.B0
	b := z.B1
	b = *e.MulBy01(&b, c3, c4)
	c3 = e.fp.Add(e.fp.One(), c3)
	d := e.Ext3.Add(&z.B0, &z.B1)
	d = e.MulBy01(d, c3, c4)

	zC1 := e.Ext3.Add(&a, &b)
	zC1 = e.Ext3.Neg(zC1)
	zC1 = e.Ext3.Add(zC1, d)
	zC0 := e.Ext3.MulByNonResidue(&b)
	zC0 = e.Ext3.Add(zC0, &a)

	return &E6{
		B0: *zC0,
		B1: *zC1,
	}
}

//	multiplies two E6 sparse element of the form:
//
//	E6{
//		C0: E6{B0: 1, B1: 0, B2: 0},
//		C1: E6{B0: c3, B1: c4, B2: 0},
//	}
//
// and
//
//	E6{
//		C0: E6{B0: 1, B1: 0, B2: 0},
//		C1: E6{B0: d3, B1: d4, B2: 0},
//	}
func (e *Ext6) Mul034By034(d3, d4, c3, c4 *baseEl) *[5]baseEl {
	x3 := e.fp.Mul(c3, d3)
	x4 := e.fp.Mul(c4, d4)
	x04 := e.fp.Add(c4, d4)
	x03 := e.fp.Add(c3, d3)
	tmp := e.fp.Add(c3, c4)
	x34 := e.fp.Add(d3, d4)
	x34 = e.fp.Mul(x34, tmp)
	x34 = e.fp.Sub(x34, x3)
	x34 = e.fp.Sub(x34, x4)

	zC0B0 := mulFpByNonResidue(e.fp, x4)
	zC0B0 = e.fp.Add(zC0B0, e.fp.One())
	zC0B1 := x3
	zC0B2 := x34
	zC1B0 := x03
	zC1B1 := x04

	return &[5]baseEl{*zC0B0, *zC0B1, *zC0B2, *zC1B0, *zC1B1}
}

// MulBy01234 multiplies z by an E6 sparse element of the form
//
//	E6{
//		C0: E3{A0: c0, A1: c1, A2: c2},
//		C1: E3{A0: c3, A1: c4, A2: 0},
//	}
func (e *Ext6) MulBy01234(z *E6, x *[5]baseEl) *E6 {
	c0 := &E3{A0: x[0], A1: x[1], A2: x[2]}
	c1 := &E3{A0: x[3], A1: x[4], A2: *e.fp.Zero()}
	a := e.Ext3.Add(&z.B0, &z.B1)
	b := e.Ext3.Add(c0, c1)
	a = e.Ext3.Mul(a, b)
	b = e.Ext3.Mul(&z.B0, c0)
	c := e.Ext3.MulBy01(&z.B1, &x[3], &x[4])
	z1 := e.Ext3.Sub(a, b)
	z1 = e.Ext3.Sub(z1, c)
	z0 := e.Ext3.MulByNonResidue(c)
	z0 = e.Ext3.Add(z0, b)
	return &E6{
		B0: *z0,
		B1: *z1,
	}
}

//	multiplies two E6 sparse element of the form:
//
//	E6{
//		C0: E2{A0: x0, A1: x1, A2: x2},
//		C1: E2{A0: x3, A1: x4, A2: 0},
//	}
//
// and
//
//	E6{
//		C0: E3{A0: 1,  A1: 0,  A2: 0},
//		C1: E3{A0: z3, A1: z4, A2: 0},
//	}
func (e *Ext6) Mul01234By034(x *[5]baseEl, z3, z4 *baseEl) *E6 {
	c0 := &E3{A0: x[0], A1: x[1], A2: x[2]}
	c1 := &E3{A0: x[3], A1: x[4], A2: *e.fp.Zero()}
	a := e.Ext3.Add(e.Ext3.One(), &E3{A0: *z3, A1: *z4, A2: *e.fp.Zero()})
	b := e.Ext3.Add(c0, c1)
	a = e.Ext3.Mul(a, b)
	c := e.Ext3.Mul01By01(z3, z4, &x[3], &x[4])
	z1 := e.Ext3.Sub(a, c0)
	z1 = e.Ext3.Sub(z1, c)
	z0 := e.Ext3.MulByNonResidue(c)
	z0 = e.Ext3.Add(z0, c0)
	return &E6{
		B0: *z0,
		B1: *z1,
	}
}
