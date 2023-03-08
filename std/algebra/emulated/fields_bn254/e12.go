package fields_bn254

import "github.com/consensys/gnark-crypto/ecc/bn254"

type E12 struct {
	C0, C1 E6
}

type Ext12 struct {
	*Ext6
}

func NewExt12(baseField *curveF) *Ext12 {
	return &Ext12{Ext6: NewExt6(baseField)}
}

func (e Ext12) Add(x, y *E12) *E12 {
	z0 := e.Ext6.Add(&x.C0, &y.C0) // z.C0.Add(&x.A0, &y.A0)
	z1 := e.Ext6.Add(&x.C1, &y.C1) // z.C1.Add(&x.A1, &y.A1)
	return &E12{
		C0: *z0,
		C1: *z1,
	}
}

func (e Ext12) Sub(x, y *E12) *E12 {
	z0 := e.Ext6.Sub(&x.C0, &y.C0) // z.C0.Sub(&x.A0, &y.A0)
	z1 := e.Ext6.Sub(&x.C1, &y.C1) // z.C1.Sub(&x.A1, &y.A1)
	return &E12{
		C0: *z0,
		C1: *z1,
	}
}

func (e Ext12) Conjugate(x *E12) *E12 {
	z1 := e.Ext6.Neg(&x.C1) // z.C1.Neg(&z.C1)
	return &E12{            // return z
		C0: x.C0,
		C1: *z1,
	}
}

func (e Ext12) Inverse(x *E12) *E12 {
	// var t0, t1, tmp E6
	t0 := e.Ext6.Square(&x.C0)        // t0.Square(&x.C0)
	t1 := e.Ext6.Square(&x.C1)        // t1.Square(&x.C1)
	tmp := e.Ext6.MulByNonResidue(t1) // tmp.MulByNonResidue(&t1)
	t0 = e.Ext6.Sub(t0, tmp)          // t0.Sub(&t0, &tmp)
	t1 = e.Ext6.Inverse(t0)           // t1.Inverse(&t0)
	z0 := e.Ext6.Mul(&x.C0, t1)       // z.C0.Mul(&x.C0, &t1)
	z1 := e.Ext6.Mul(&x.C1, t1)       // z.C1.Mul(&x.C1, &t1).
	z1 = e.Ext6.Neg(z1)               //      Neg(&z.C1)
	return &E12{                      // return z
		C0: *z0,
		C1: *z1,
	}
}

func (e Ext12) Mul(x, y *E12) *E12 {
	// var a, b, c E6
	a := e.Ext6.Add(&x.C0, &x.C1)   // a.Add(&x.C0, &x.C1)
	b := e.Ext6.Add(&y.C0, &y.C1)   // b.Add(&y.C0, &y.C1)
	a = e.Ext6.Mul(a, b)            // a.Mul(&a, &b)
	b = e.Ext6.Mul(&x.C0, &y.C0)    // b.Mul(&x.C0, &y.C0)
	c := e.Ext6.Mul(&x.C1, &y.C1)   // c.Mul(&x.C1, &y.C1)
	z1 := e.Ext6.Sub(a, b)          // z.C1.Sub(&a, &b).
	z1 = e.Ext6.Sub(z1, c)          //      Sub(&z.C1, &c)
	z0 := e.Ext6.MulByNonResidue(c) // z.C0.MulByNonResidue(&c).
	z0 = e.Ext6.Add(z0, b)          //      Add(&z.C0, &b)
	return &E12{                    // return z
		C0: *z0,
		C1: *z1,
	}
}

func (e Ext12) CyclotomicSquare(x *E12) *E12 {
	// var t [9]E2
	t0 := e.Ext2.Square(&x.C1.B1)        // t[0].Square(&x.C1.B1)
	t1 := e.Ext2.Square(&x.C0.B0)        // t[1].Square(&x.C0.B0)
	t6 := e.Ext2.Add(&x.C1.B1, &x.C0.B0) // t[6].Add(&x.C1.B1, &x.C0.B0).
	t6 = e.Ext2.Square(t6)               // 	Square(&t[6]).
	t6 = e.Ext2.Sub(t6, t0)              // 	Sub(&t[6], &t[0]).
	t6 = e.Ext2.Sub(t6, t1)              // 	Sub(&t[6], &t[1])
	t2 := e.Ext2.Square(&x.C0.B2)        // t[2].Square(&x.C0.B2)
	t3 := e.Ext2.Square(&x.C1.B0)        // t[3].Square(&x.C1.B0)
	t7 := e.Ext2.Add(&x.C0.B2, &x.C1.B0) // t[7].Add(&x.C0.B2, &x.C1.B0).
	t7 = e.Ext2.Square(t7)               // 	Square(&t[7]).
	t7 = e.Ext2.Sub(t7, t2)              // 	Sub(&t[7], &t[2]).
	t7 = e.Ext2.Sub(t7, t3)              // 	Sub(&t[7], &t[3])
	t4 := e.Ext2.Square(&x.C1.B2)        // t[4].Square(&x.C1.B2)
	t5 := e.Ext2.Square(&x.C0.B1)        // t[5].Square(&x.C0.B1)
	t8 := e.Ext2.Add(&x.C1.B2, &x.C0.B1) // t[8].Add(&x.C1.B2, &x.C0.B1).
	t8 = e.Ext2.Square(t8)               // 	Square(&t[8]).
	t8 = e.Ext2.Sub(t8, t4)              // 	Sub(&t[8], &t[4]).
	t8 = e.Ext2.Sub(t8, t5)              // 	Sub(&t[8], &t[5]).
	t8 = e.Ext2.MulByNonResidue(t8)      // 	MulByNonResidue(&t[8])
	t0 = e.Ext2.MulByNonResidue(t0)      // t[0].MulByNonResidue(&t[0]).
	t0 = e.Ext2.Add(t0, t1)              // 	Add(&t[0], &t[1])
	t2 = e.Ext2.MulByNonResidue(t2)      // t[2].MulByNonResidue(&t[2]).
	t2 = e.Ext2.Add(t2, t3)              // 	Add(&t[2], &t[3])
	t4 = e.Ext2.MulByNonResidue(t4)      // t[4].MulByNonResidue(&t[4]).
	t4 = e.Ext2.Add(t4, t5)              // 	Add(&t[4], &t[5])
	z00 := e.Ext2.Sub(t0, &x.C0.B0)      // z.C0.B0.Sub(&t[0], &x.C0.B0).
	z00 = e.Ext2.Double(z00)             // 	Double(&z.C0.B0).
	z00 = e.Ext2.Add(z00, t0)            // 	Add(&z.C0.B0, &t[0])
	z01 := e.Ext2.Sub(t2, &x.C0.B1)      // z.C0.B1.Sub(&t[2], &x.C0.B1).
	z01 = e.Ext2.Double(z01)             // 	Double(&z.C0.B1).
	z01 = e.Ext2.Add(z01, t2)            // 	Add(&z.C0.B1, &t[2])
	z02 := e.Ext2.Sub(t4, &x.C0.B2)      // z.C0.B2.Sub(&t[4], &x.C0.B2).
	z02 = e.Ext2.Double(z02)             // 	Double(&z.C0.B2).
	z02 = e.Ext2.Add(z02, t4)            // 	Add(&z.C0.B2, &t[4])
	z10 := e.Ext2.Add(t8, &x.C1.B0)      // z.C1.B0.Add(&t[8], &x.C1.B0).
	z10 = e.Ext2.Double(z10)             // 	Double(&z.C1.B0).
	z10 = e.Ext2.Add(z10, t8)            // 	Add(&z.C1.B0, &t[8])
	z11 := e.Ext2.Add(t6, &x.C1.B1)      // z.C1.B1.Add(&t[6], &x.C1.B1).
	z11 = e.Ext2.Double(z11)             // 	Double(&z.C1.B1).
	z11 = e.Ext2.Add(z11, t6)            // 	Add(&z.C1.B1, &t[6])
	z12 := e.Ext2.Add(t7, &x.C1.B2)      // z.C1.B2.Add(&t[7], &x.C1.B2).
	z12 = e.Ext2.Double(z12)             // 	Double(&z.C1.B2).
	z12 = e.Ext2.Add(z12, t7)            // 	Add(&z.C1.B2, &t[7])
	return &E12{                         // return z
		C0: E6{
			B0: *z00,
			B1: *z01,
			B2: *z02,
		},
		C1: E6{
			B0: *z10,
			B1: *z11,
			B2: *z12,
		},
	}
}

func (e Ext12) NCycloSquare(z *E12, n int) *E12 {
	for i := 0; i < n; i++ {
		z = e.CyclotomicSquare(z)
	}
	return z
}

func (e Ext12) Frobenius(x *E12) *E12 {
	// var t [6]E2
	t0 := e.Ext2.Conjugate(&x.C0.B0)       // t[0].Conjugate(&x.C0.B0)
	t1 := e.Ext2.Conjugate(&x.C0.B1)       // t[1].Conjugate(&x.C0.B1)
	t2 := e.Ext2.Conjugate(&x.C0.B2)       // t[2].Conjugate(&x.C0.B2)
	t3 := e.Ext2.Conjugate(&x.C1.B0)       // t[3].Conjugate(&x.C1.B0)
	t4 := e.Ext2.Conjugate(&x.C1.B1)       // t[4].Conjugate(&x.C1.B1)
	t5 := e.Ext2.Conjugate(&x.C1.B2)       // t[5].Conjugate(&x.C1.B2)
	t1 = e.Ext2.MulByNonResidue1Power2(t1) // t[1].MulByNonResidue1Power2(&t[1])
	t2 = e.Ext2.MulByNonResidue1Power4(t2) // t[2].MulByNonResidue1Power4(&t[2])
	t3 = e.Ext2.MulByNonResidue1Power1(t3) // t[3].MulByNonResidue1Power1(&t[3])
	t4 = e.Ext2.MulByNonResidue1Power3(t4) // t[4].MulByNonResidue1Power3(&t[4])
	t5 = e.Ext2.MulByNonResidue1Power5(t5) // t[5].MulByNonResidue1Power5(&t[5])
	return &E12{                           // return z
		C0: E6{
			B0: *t0, // z.C0.B0 = t[0]
			B1: *t1, // z.C0.B1 = t[1]
			B2: *t2, // z.C0.B2 = t[2]
		},
		C1: E6{
			B0: *t3, // z.C1.B0 = t[3]
			B1: *t4, // z.C1.B1 = t[4]
			B2: *t5, // z.C1.B2 = t[5]
		},
	}
}

func (e Ext12) FrobeniusSquare(x *E12) *E12 {
	z00 := &x.C0.B0                                // z.C0.B0 = x.C0.B0
	z01 := e.Ext2.MulByNonResidue2Power2(&x.C0.B1) // z.C0.B1.MulByNonResidue2Power2(&x.C0.B1)
	z02 := e.Ext2.MulByNonResidue2Power4(&x.C0.B2) // z.C0.B2.MulByNonResidue2Power4(&x.C0.B2)
	z10 := e.Ext2.MulByNonResidue2Power1(&x.C1.B0) // z.C1.B0.MulByNonResidue2Power1(&x.C1.B0)
	z11 := e.Ext2.MulByNonResidue2Power3(&x.C1.B1) // z.C1.B1.MulByNonResidue2Power3(&x.C1.B1)
	z12 := e.Ext2.MulByNonResidue2Power5(&x.C1.B2) // z.C1.B2.MulByNonResidue2Power5(&x.C1.B2)
	return &E12{                                   // return z
		C0: E6{B0: *z00, B1: *z01, B2: *z02},
		C1: E6{B0: *z10, B1: *z11, B2: *z12},
	}
}

func (e Ext12) FrobeniusCube(x *E12) *E12 {
	// var t [6]E2
	t0 := e.Ext2.Conjugate(&x.C0.B0)       // t[0].Conjugate(&x.C0.B0)
	t1 := e.Ext2.Conjugate(&x.C0.B1)       // t[1].Conjugate(&x.C0.B1)
	t2 := e.Ext2.Conjugate(&x.C0.B2)       // t[2].Conjugate(&x.C0.B2)
	t3 := e.Ext2.Conjugate(&x.C1.B0)       // t[3].Conjugate(&x.C1.B0)
	t4 := e.Ext2.Conjugate(&x.C1.B1)       // t[4].Conjugate(&x.C1.B1)
	t5 := e.Ext2.Conjugate(&x.C1.B2)       // t[5].Conjugate(&x.C1.B2)
	t1 = e.Ext2.MulByNonResidue3Power2(t1) // t[1].MulByNonResidue3Power2(&t[1])
	t2 = e.Ext2.MulByNonResidue3Power4(t2) // t[2].MulByNonResidue3Power4(&t[2])
	t3 = e.Ext2.MulByNonResidue3Power1(t3) // t[3].MulByNonResidue3Power1(&t[3])
	t4 = e.Ext2.MulByNonResidue3Power3(t4) // t[4].MulByNonResidue3Power3(&t[4])
	t5 = e.Ext2.MulByNonResidue3Power5(t5) // t[5].MulByNonResidue3Power5(&t[5])
	return &E12{                           // return z
		C0: E6{
			B0: *t0, // z.C0.B0 = t[0]
			B1: *t1, // z.C0.B1 = t[1]
			B2: *t2, // z.C0.B2 = t[2]
		},
		C1: E6{
			B0: *t3, // z.C1.B0 = t[3]
			B1: *t4, // z.C1.B1 = t[4]
			B2: *t5, // z.C1.B2 = t[5]
		},
	}
}

func (e Ext12) One() *E12 {
	z000 := e.fp.One()
	zero := e.fp.Zero()
	return &E12{
		C0: E6{
			B0: E2{A0: *z000, A1: *zero},
			B1: E2{A0: *zero, A1: *zero},
			B2: E2{A0: *zero, A1: *zero},
		},
		C1: E6{
			B0: E2{A0: *zero, A1: *zero},
			B1: E2{A0: *zero, A1: *zero},
			B2: E2{A0: *zero, A1: *zero},
		},
	}
}

func (e Ext12) Square(x *E12) *E12 {
	// var c0, c2, c3 E6
	c0 := e.Ext6.Sub(&x.C0, &x.C1)      // c0.Sub(&x.C0, &x.C1)
	c3 := e.Ext6.MulByNonResidue(&x.C1) // c3.MulByNonResidue(&x.C1).
	c3 = e.Ext6.Neg(c3)                 //    Neg(&c3).
	c3 = e.Ext6.Add(&x.C0, c3)          //    Add(&x.C0, &c3)
	c2 := e.Ext6.Mul(&x.C0, &x.C1)      // c2.Mul(&x.C0, &x.C1)
	c0 = e.Ext6.Mul(c0, c3)             // c0.Mul(&c0, &c3).
	c0 = e.Ext6.Add(c0, c2)             //    Add(&c0, &c2)
	z1 := e.Ext6.double(c2)             // z.C1.Double(&c2)
	c2 = e.Ext6.MulByNonResidue(c2)     // c2.MulByNonResidue(&c2)
	z0 := e.Ext6.Add(c0, c2)            // z.C0.Add(&c0, &c2)
	return &E12{                        // return z
		C0: *z0,
		C1: *z1,
	}
}

func (e Ext12) AssertIsEqual(x, y *E12) {
	e.Ext6.AssertIsEqual(&x.C0, &y.C0)
	e.Ext6.AssertIsEqual(&x.C1, &y.C1)
}

func FromE12(y *bn254.E12) E12 {
	return E12{
		C0: FromE6(&y.C0),
		C1: FromE6(&y.C1),
	}

}
