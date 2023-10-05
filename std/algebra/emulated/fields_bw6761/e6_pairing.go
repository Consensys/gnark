package fields_bw6761

import "math/big"

func (e Ext6) nSquareCompressed(z *E6, n int) *E6 {
	for i := 0; i < n; i++ {
		z = e.CyclotomicSquareCompressed(z)
	}
	return z
}

// Expt set z to x^t in *E6 and return z
func (e Ext6) Expt(x *E6) *E6 {
	x = e.Reduce(x)

	// const tAbsVal uint64 = 9586122913090633729
	// tAbsVal in binary: 1000010100001000110000000000000000000000000000000000000000000001
	// drop the low 46 bits (all 0 except the least significant bit): 100001010000100011 = 136227
	// Shortest addition chains can be found at https://wwwhomes.uni-bielefeld.de/achim/addition_chain.html

	// a shortest addition chain for 136227
	result := e.Set(x)
	result = e.nSquareCompressed(result, 5)
	result = e.DecompressKarabina(result)
	result = e.Mul(result, x)
	x33 := e.Set(result)
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

	return e.Set(result)
}

// Expc2 set z to x^c2 in *E6 and return z
// ht, hy = 13, 9
// c1 = ht+hy = 22 (10110)
func (e Ext6) Expc2(x *E6) *E6 {

	result := e.CyclotomicSquare(x)
	result = e.CyclotomicSquare(result)
	result = e.Mul(result, x)
	result = e.CyclotomicSquare(result)
	result = e.Mul(result, x)
	result = e.CyclotomicSquare(result)

	return e.Set(result)
}

// Expc1 set z to x^c1 in *E6 and return z
// ht, hy = 13, 9
// c1 = ht**2+3*hy**2 = 412 (110011100)
func (e Ext6) Expc1(x *E6) *E6 {
	x = e.Reduce(x)

	result := e.CyclotomicSquare(x)
	result = e.Mul(result, x)
	result = e.CyclotomicSquare(result)
	result = e.CyclotomicSquare(result)
	result = e.CyclotomicSquare(result)
	result = e.Mul(result, x)
	result = e.CyclotomicSquare(result)
	result = e.Mul(result, x)
	result = e.CyclotomicSquare(result)
	result = e.Mul(result, x)
	result = e.CyclotomicSquare(result)
	result = e.CyclotomicSquare(result)

	return e.Set(result)
}

// MulBy014 multiplies z by an E6 sparse element of the form
//
//	E6{
//		C0: E3{A0: c0, A1: c1, A2: 0},
//		C1: E3{A0:  0, A1:  1, A2: 0},
//	}
func (e *Ext6) MulBy014(z *E6, c0, c1 *baseEl) *E6 {

	z = e.Reduce(z)

	a := z.B0
	a = *e.MulBy01(&a, c0, c1)

	var b E3
	// Mul by E3{0, 1, 0}
	b.A0 = *MulByNonResidue(e.fp, &z.B1.A2)
	b.A2 = z.B1.A1
	b.A1 = z.B1.A0

	one := e.fp.One()
	d := e.fp.Add(c1, one)

	zC1 := e.Ext3.Add(&z.B1, &z.B0)
	zC1 = e.Ext3.MulBy01(zC1, c0, d)
	zC1 = e.Ext3.Sub(zC1, &a)
	zC1 = e.Ext3.Sub(zC1, &b)
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
//		C0: E6{B0: c0, B1: c1, B2: 0},
//		C1: E6{B0: 0, B1: 1, B2: 0},
//	}
//
// and
//
//	E6{
//		C0: E6{B0: d0, B1: d1, B2: 0},
//		C1: E6{B0: 0, B1: 1, B2: 0},
//	}
func (e Ext6) Mul014By014(d0, d1, c0, c1 *baseEl) *[5]baseEl {
	one := e.fp.One()
	x0 := e.fp.Mul(c0, d0)
	x1 := e.fp.Mul(c1, d1)
	tmp := e.fp.Add(c0, one)
	x04 := e.fp.Add(d0, one)
	x04 = e.fp.Mul(x04, tmp)
	x04 = e.fp.Sub(x04, x0)
	x04 = e.fp.Sub(x04, one)
	tmp = e.fp.Add(c0, c1)
	x01 := e.fp.Add(d0, d1)
	x01 = e.fp.Mul(x01, tmp)
	x01 = e.fp.Sub(x01, x0)
	x01 = e.fp.Sub(x01, x1)
	tmp = e.fp.Add(c1, one)
	x14 := e.fp.Add(d1, one)
	x14 = e.fp.Mul(x14, tmp)
	x14 = e.fp.Sub(x14, x1)
	x14 = e.fp.Sub(x14, one)

	// NonResidue()
	zC0B0 := e.fp.MulConst(e.fp.One(), big.NewInt(4))
	zC0B0 = e.fp.Neg(zC0B0)

	zC0B0 = e.fp.Add(zC0B0, x0)

	return &[5]baseEl{*zC0B0, *x01, *x1, *x04, *x14}
}

// MulBy01245 multiplies z by an E6 sparse element of the form
//
//	E6{
//		C0: E6{B0: c0, B1: c1, B2: c2},
//		C1: E6{B0: 0, B1: c4, B2: c5},
//	}
func (e *Ext6) MulBy01245(z *E6, x *[5]baseEl) *E6 {
	c0 := &E3{A0: x[0], A1: x[1], A2: x[2]}
	c1 := &E3{A0: *e.fp.Zero(), A1: x[3], A2: x[4]}
	a := e.Ext3.Add(&z.B0, &z.B1)
	b := e.Ext3.Add(c0, c1)
	a = e.Ext3.Mul(a, b)
	b = e.Ext3.Mul(&z.B0, c0)
	c := e.Ext3.MulBy12(&z.B1, &x[3], &x[4])
	z1 := e.Ext3.Sub(a, b)
	z1 = e.Ext3.Sub(z1, c)
	z0 := e.Ext3.MulByNonResidue(c)
	z0 = e.Ext3.Add(z0, b)
	return &E6{
		B0: *z0,
		B1: *z1,
	}
}
