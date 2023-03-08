package fields_bn254

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

type E6 struct {
	B0, B1, B2 E2
}

type Ext6 struct {
	*Ext2
}

func NewExt6(baseField *curveF) *Ext6 {
	return &Ext6{Ext2: NewExt2(baseField)}
}

func (e Ext6) Add(x, y *E6) *E6 {
	z0 := e.Ext2.Add(&x.B0, &y.B0) // z.B0.Add(&x.B0, &y.B0)
	z1 := e.Ext2.Add(&x.B1, &y.B1) // z.B1.Add(&x.B1, &y.B1)
	z2 := e.Ext2.Add(&x.B2, &y.B2) // z.B2.Add(&x.B2, &y.B2)
	return &E6{                    // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e Ext6) Neg(x *E6) *E6 {
	z0 := e.Ext2.Neg(&x.B0) // z.B0.Neg(&x.B0)
	z1 := e.Ext2.Neg(&x.B1) // z.B1.Neg(&x.B1)
	z2 := e.Ext2.Neg(&x.B2) // z.B2.Neg(&x.B2)
	return &E6{             // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e Ext6) Sub(x, y *E6) *E6 {
	z0 := e.Ext2.Sub(&x.B0, &y.B0) // z.B0.Sub(&x.B0, &y.B0)
	z1 := e.Ext2.Sub(&x.B1, &y.B1) // z.B1.Sub(&x.B1, &y.B1)
	z2 := e.Ext2.Sub(&x.B2, &y.B2) // z.B2.Sub(&x.B2, &y.B2)
	return &E6{                    // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e Ext6) Mul(x, y *E6) *E6 {
	// var t0, t1, t2, c0, c1, c2, tmp E2
	t0 := e.Ext2.Mul(&x.B0, &y.B0)   // t0.Mul(&x.B0, &y.B0)
	t1 := e.Ext2.Mul(&x.B1, &y.B1)   // t1.Mul(&x.B1, &y.B1)
	t2 := e.Ext2.Mul(&x.B2, &y.B2)   // t2.Mul(&x.B2, &y.B2)
	c0 := e.Ext2.Add(&x.B1, &x.B2)   // c0.Add(&x.B1, &x.B2)
	tmp := e.Ext2.Add(&y.B1, &y.B2)  // tmp.Add(&y.B1, &y.B2)
	c0 = e.Ext2.Mul(c0, tmp)         // c0.Mul(&c0, &tmp).
	c0 = e.Ext2.Sub(c0, t1)          // 	Sub(&c0, &t1).
	c0 = e.Ext2.Sub(c0, t2)          // 	Sub(&c0, &t2).
	c0 = e.Ext2.MulByNonResidue(c0)  // 	MulByNonResidue(&c0).
	c0 = e.Ext2.Add(c0, t0)          // 	Add(&c0, &t0)
	c1 := e.Ext2.Add(&x.B0, &x.B1)   // c1.Add(&x.B0, &x.B1)
	tmp = e.Ext2.Add(&y.B0, &y.B1)   // tmp.Add(&y.B0, &y.B1)
	c1 = e.Ext2.Mul(c1, tmp)         // c1.Mul(&c1, &tmp).
	c1 = e.Ext2.Sub(c1, t0)          // 	Sub(&c1, &t0).
	c1 = e.Ext2.Sub(c1, t1)          // 	Sub(&c1, &t1)
	tmp = e.Ext2.MulByNonResidue(t2) // tmp.MulByNonResidue(&t2)
	c1 = e.Ext2.Add(c1, tmp)         // c1.Add(&c1, &tmp)
	tmp = e.Ext2.Add(&x.B0, &x.B2)   // tmp.Add(&x.B0, &x.B2)
	c2 := e.Ext2.Add(&y.B0, &y.B2)   // c2.Add(&y.B0, &y.B2).
	c2 = e.Ext2.Mul(c2, tmp)         // 	Mul(&c2, &tmp).
	c2 = e.Ext2.Sub(c2, t0)          // 	Sub(&c2, &t0).
	c2 = e.Ext2.Sub(c2, t2)          // 	Sub(&c2, &t2).
	c2 = e.Ext2.Add(c2, t1)          // 	Add(&c2, &t1)
	return &E6{
		B0: *c0, // z.B0.Set(&c0)
		B1: *c1, // z.B1.Set(&c1)
		B2: *c2, // z.B2.Set(&c2)
	} // return z
}

func (e Ext6) double(x *E6) *E6 {
	z0 := e.Ext2.Double(&x.B0) // z.B0.Double(&x.B0)
	z1 := e.Ext2.Double(&x.B1) // z.B1.Double(&x.B1)
	z2 := e.Ext2.Double(&x.B2) // z.B2.Double(&x.B2)
	return &E6{                // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e Ext6) Square(x *E6) *E6 {
	// var c4, c5, c1, c2, c3, c0 E2
	c4 := e.Ext2.Mul(&x.B0, &x.B1)   // c4.Mul(&x.B0, &x.B1).
	c4 = e.Ext2.Double(c4)           // 	Double(&c4)
	c5 := e.Ext2.Square(&x.B2)       // c5.Square(&x.B2)
	c1 := e.Ext2.MulByNonResidue(c5) // c1.MulByNonResidue(&c5).
	c1 = e.Ext2.Add(c1, c4)          // 	Add(&c1, &c4)
	c2 := e.Ext2.Sub(c4, c5)         // c2.Sub(&c4, &c5)
	c3 := e.Ext2.Square(&x.B0)       // c3.Square(&x.B0)
	c4 = e.Ext2.Sub(&x.B0, &x.B1)    // c4.Sub(&x.B0, &x.B1).
	c4 = e.Ext2.Add(c4, &x.B2)       // 	Add(&c4, &x.B2)
	c5 = e.Ext2.Mul(&x.B1, &x.B2)    // c5.Mul(&x.B1, &x.B2).
	c5 = e.Ext2.Double(c5)           // 	Double(&c5)
	c4 = e.Ext2.Square(c4)           // c4.Square(&c4)
	c0 := e.Ext2.MulByNonResidue(c5) // c0.MulByNonResidue(&c5).
	c0 = e.Ext2.Add(c0, c3)          // 	Add(&c0, &c3)
	z2 := e.Ext2.Add(c2, c4)         // z.B2.Add(&c2, &c4).
	z2 = e.Ext2.Add(z2, c5)          // 	Add(&z.B2, &c5).
	z2 = e.Ext2.Sub(z2, c3)          // 	Sub(&z.B2, &c3)
	z0 := c0                         // z.B0.Set(&c0)
	z1 := c1                         // z.B1.Set(&c1)
	return &E6{                      // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e Ext6) Inverse(x *E6) *E6 {
	// var t0, t1, t2, t3, t4, t5, t6, c0, c1, c2, d1, d2 E2
	t0 := e.Ext2.Square(&x.B0)       // t0.Square(&x.B0)
	t1 := e.Ext2.Square(&x.B1)       // t1.Square(&x.B1)
	t2 := e.Ext2.Square(&x.B2)       // t2.Square(&x.B2)
	t3 := e.Ext2.Mul(&x.B0, &x.B1)   // t3.Mul(&x.B0, &x.B1)
	t4 := e.Ext2.Mul(&x.B0, &x.B2)   // t4.Mul(&x.B0, &x.B2)
	t5 := e.Ext2.Mul(&x.B1, &x.B2)   // t5.Mul(&x.B1, &x.B2)
	c0 := e.Ext2.MulByNonResidue(t5) // c0.MulByNonResidue(&t5).
	c0 = e.Ext2.Neg(c0)              //    Neg(&c0).
	c0 = e.Ext2.Add(c0, t0)          //    Add(&c0, &t0)
	c1 := e.Ext2.MulByNonResidue(t2) // c1.MulByNonResidue(&t2).
	c1 = e.Ext2.Sub(c1, t3)          //    Sub(&c1, &t3)
	c2 := e.Ext2.Sub(t1, t4)         // c2.Sub(&t1, &t4)
	t6 := e.Ext2.Mul(&x.B0, c0)      // t6.Mul(&x.B0, &c0)
	d1 := e.Ext2.Mul(&x.B2, c1)      // d1.Mul(&x.B2, &c1)
	d2 := e.Ext2.Mul(&x.B1, c2)      // d2.Mul(&x.B1, &c2)
	d1 = e.Ext2.Add(d1, d2)          // d1.Add(&d1, &d2).
	d1 = e.Ext2.MulByNonResidue(d1)  //    MulByNonResidue(&d1)
	t6 = e.Ext2.Add(t6, d1)          // t6.Add(&t6, &d1)
	t6 = e.Ext2.Inverse(t6)          // t6.Inverse(&t6)
	z0 := e.Ext2.Mul(c0, t6)         // z.B0.Mul(&c0, &t6)
	z1 := e.Ext2.Mul(c1, t6)         // z.B1.Mul(&c1, &t6)
	z2 := e.Ext2.Mul(c2, t6)         // z.B2.Mul(&c2, &t6)
	return &E6{                      // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}
func (e Ext6) MulByE2(x *E6, y *E2) *E6 {
	// var yCopy E2
	// yCopy.Set(y)
	z0 := e.Ext2.Mul(&x.B0, y) // z.B0.Mul(&x.B0, &yCopy)
	z1 := e.Ext2.Mul(&x.B1, y) // z.B1.Mul(&x.B1, &yCopy)
	z2 := e.Ext2.Mul(&x.B2, y) // z.B2.Mul(&x.B2, &yCopy)
	return &E6{                // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e Ext6) MulBy01(z *E6, c0, c1 *E2) *E6 {
	// var a, b, tmp, t0, t1, t2 E2
	a := e.Ext2.Mul(&z.B0, c0)      // a.Mul(&z.B0, c0)
	b := e.Ext2.Mul(&z.B1, c1)      // b.Mul(&z.B1, c1)
	tmp := e.Ext2.Add(&z.B1, &z.B2) // tmp.Add(&z.B1, &z.B2)
	t0 := e.Ext2.Mul(c1, tmp)       // t0.Mul(c1, &tmp)
	t0 = e.Ext2.Sub(t0, b)          // t0.Sub(&t0, &b)
	t0 = e.Ext2.MulByNonResidue(t0) // t0.MulByNonResidue(&t0)
	t0 = e.Ext2.Add(t0, a)          // t0.Add(&t0, &a)
	tmp = e.Ext2.Add(&z.B0, &z.B2)  // tmp.Add(&z.B0, &z.B2)
	t2 := e.Ext2.Mul(c0, tmp)       // t2.Mul(c0, &tmp)
	t2 = e.Ext2.Sub(t2, a)          // t2.Sub(&t2, &a)
	t2 = e.Ext2.Add(t2, b)          // t2.Add(&t2, &b)
	t1 := e.Ext2.Add(c0, c1)        // t1.Add(c0, c1)
	tmp = e.Ext2.Add(&z.B0, &z.B1)  // tmp.Add(&z.B0, &z.B1)
	t1 = e.Ext2.Mul(t1, tmp)        // t1.Mul(&t1, &tmp)
	t1 = e.Ext2.Sub(t1, a)          // t1.Sub(&t1, &a)
	t1 = e.Ext2.Sub(t1, b)          // t1.Sub(&t1, &b)
	return &E6{
		B0: *t0, // z.B0.Set(&t0)
		B1: *t1, // z.B1.Set(&t1)
		B2: *t2, // z.B2.Set(&t2)
	} // return z
}

func (e Ext6) MulByNonResidue(x *E6) *E6 {
	z2, z1, z0 := &x.B1, &x.B0, &x.B2 // z.B2, z.B1, z.B0 = x.B1, x.B0, x.B2
	z0 = e.Ext2.MulByNonResidue(z0)   // z.B0.MulByNonResidue(&z.B0)
	return &E6{                       // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e Ext6) AssertIsEqual(x, y *E6) {
	e.Ext2.AssertIsEqual(&x.B0, &y.B0)
	e.Ext2.AssertIsEqual(&x.B1, &y.B1)
	e.Ext2.AssertIsEqual(&x.B2, &y.B2)
}

func FromE6(y *bn254.E6) E6 {
	return E6{
		B0: FromE2(&y.B0),
		B1: FromE2(&y.B1),
		B2: FromE2(&y.B2),
	}

}
