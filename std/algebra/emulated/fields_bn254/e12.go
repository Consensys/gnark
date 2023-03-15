package fields_bn254

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

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
	z0 := e.Ext6.Add(&x.C0, &y.C0)
	z1 := e.Ext6.Add(&x.C1, &y.C1)
	return &E12{
		C0: *z0,
		C1: *z1,
	}
}

func (e Ext12) Sub(x, y *E12) *E12 {
	z0 := e.Ext6.Sub(&x.C0, &y.C0)
	z1 := e.Ext6.Sub(&x.C1, &y.C1)
	return &E12{
		C0: *z0,
		C1: *z1,
	}
}

func (e Ext12) Conjugate(x *E12) *E12 {
	z1 := e.Ext6.Neg(&x.C1)
	return &E12{
		C0: x.C0,
		C1: *z1,
	}
}

func (e Ext12) Mul(x, y *E12) *E12 {
	a := e.Ext6.Add(&x.C0, &x.C1)
	b := e.Ext6.Add(&y.C0, &y.C1)
	a = e.Ext6.Mul(a, b)
	b = e.Ext6.Mul(&x.C0, &y.C0)
	c := e.Ext6.Mul(&x.C1, &y.C1)
	z1 := e.Ext6.Sub(a, b)
	z1 = e.Ext6.Sub(z1, c)
	z0 := e.Ext6.MulByNonResidue(c)
	z0 = e.Ext6.Add(z0, b)
	return &E12{
		C0: *z0,
		C1: *z1,
	}
}

func (e Ext12) CyclotomicSquare(x *E12) *E12 {
	t0 := e.Ext2.Square(&x.C1.B1)
	t1 := e.Ext2.Square(&x.C0.B0)
	t6 := e.Ext2.Add(&x.C1.B1, &x.C0.B0)
	t6 = e.Ext2.Square(t6)
	t6 = e.Ext2.Sub(t6, t0)
	t6 = e.Ext2.Sub(t6, t1)
	t2 := e.Ext2.Square(&x.C0.B2)
	t3 := e.Ext2.Square(&x.C1.B0)
	t7 := e.Ext2.Add(&x.C0.B2, &x.C1.B0)
	t7 = e.Ext2.Square(t7)
	t7 = e.Ext2.Sub(t7, t2)
	t7 = e.Ext2.Sub(t7, t3)
	t4 := e.Ext2.Square(&x.C1.B2)
	t5 := e.Ext2.Square(&x.C0.B1)
	t8 := e.Ext2.Add(&x.C1.B2, &x.C0.B1)
	t8 = e.Ext2.Square(t8)
	t8 = e.Ext2.Sub(t8, t4)
	t8 = e.Ext2.Sub(t8, t5)
	t8 = e.Ext2.MulByNonResidue(t8)
	t0 = e.Ext2.MulByNonResidue(t0)
	t0 = e.Ext2.Add(t0, t1)
	t2 = e.Ext2.MulByNonResidue(t2)
	t2 = e.Ext2.Add(t2, t3)
	t4 = e.Ext2.MulByNonResidue(t4)
	t4 = e.Ext2.Add(t4, t5)
	z00 := e.Ext2.Sub(t0, &x.C0.B0)
	z00 = e.Ext2.Double(z00)
	z00 = e.Ext2.Add(z00, t0)
	z01 := e.Ext2.Sub(t2, &x.C0.B1)
	z01 = e.Ext2.Double(z01)
	z01 = e.Ext2.Add(z01, t2)
	z02 := e.Ext2.Sub(t4, &x.C0.B2)
	z02 = e.Ext2.Double(z02)
	z02 = e.Ext2.Add(z02, t4)
	z10 := e.Ext2.Add(t8, &x.C1.B0)
	z10 = e.Ext2.Double(z10)
	z10 = e.Ext2.Add(z10, t8)
	z11 := e.Ext2.Add(t6, &x.C1.B1)
	z11 = e.Ext2.Double(z11)
	z11 = e.Ext2.Add(z11, t6)
	z12 := e.Ext2.Add(t7, &x.C1.B2)
	z12 = e.Ext2.Double(z12)
	z12 = e.Ext2.Add(z12, t7)
	return &E12{
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

// Karabina's compressed cyclotomic square
// https://eprint.iacr.org/2010/542.pdf
// Th. 3.2 with minor modifications to fit our tower
func (e Ext12) CyclotomicSquareCompressed(x *E12) *E12 {

	// t0 = g1²
	t0 := e.Ext2.Square(&x.C0.B1)
	// t1 = g5²
	t1 := e.Ext2.Square(&x.C1.B2)
	// t5 = g1 + g5
	t5 := e.Ext2.Add(&x.C0.B1, &x.C1.B2)
	// t2 = (g1 + g5)²
	t2 := e.Ext2.Square(t5)

	// t3 = g1² + g5²
	t3 := e.Ext2.Add(t0, t1)
	// t5 = 2 * g1 * g5
	t5 = e.Ext2.Sub(t2, t3)

	// t6 = g3 + g2
	t6 := e.Ext2.Add(&x.C1.B0, &x.C0.B2)
	// t3 = (g3 + g2)²
	t3 = e.Ext2.Square(t6)
	// t2 = g3²
	t2 = e.Ext2.Square(&x.C1.B0)

	// t6 = 2 * nr * g1 * g5
	t6 = e.Ext2.MulByNonResidue(t5)
	// t5 = 4 * nr * g1 * g5 + 2 * g3
	t5 = e.Ext2.Add(t6, &x.C1.B0)
	t5 = e.Ext2.Double(t5)
	// z3 = 6 * nr * g1 * g5 + 2 * g3
	C1B0 := e.Ext2.Add(t5, t6)

	// t4 = nr * g5²
	t4 := e.Ext2.MulByNonResidue(t1)
	// t5 = nr * g5² + g1²
	t5 = e.Ext2.Add(t0, t4)
	// t6 = nr * g5² + g1² - g2
	t6 = e.Ext2.Sub(t5, &x.C0.B2)

	// t1 = g2²
	t1 = e.Ext2.Square(&x.C0.B2)

	// t6 = 2 * nr * g5² + 2 * g1² - 2*g2
	t6 = e.Ext2.Double(t6)
	// z2 = 3 * nr * g5² + 3 * g1² - 2*g2
	C0B2 := e.Ext2.Add(t6, t5)

	// t4 = nr * g2²
	t4 = e.Ext2.MulByNonResidue(t1)
	// t5 = g3² + nr * g2²
	t5 = e.Ext2.Add(t2, t4)
	// t6 = g3² + nr * g2² - g1
	t6 = e.Ext2.Sub(t5, &x.C0.B1)
	// t6 = 2 * g3² + 2 * nr * g2² - 2 * g1
	t6 = e.Ext2.Double(t6)
	// z1 = 3 * g3² + 3 * nr * g2² - 2 * g1
	C0B1 := e.Ext2.Add(t6, t5)

	// t0 = g2² + g3²
	t0 = e.Ext2.Add(t2, t1)
	// t5 = 2 * g3 * g2
	t5 = e.Ext2.Sub(t3, t0)
	// t6 = 2 * g3 * g2 + g5
	t6 = e.Ext2.Add(t5, &x.C1.B2)
	// t6 = 4 * g3 * g2 + 2 * g5
	t6 = e.Ext2.Double(t6)
	// z5 = 6 * g3 * g2 + 2 * g5
	C1B2 := e.Ext2.Add(t5, t6)

	zero := e.Ext2.Zero()

	return &E12{
		C0: E6{
			B0: *zero,
			B1: *C0B1,
			B2: *C0B2,
		},
		C1: E6{
			B0: *C1B0,
			B1: *zero,
			B2: *C1B2,
		},
	}
}

func (e Ext12) NCycloSquareCompressed(z *E12, n int) *E12 {
	for i := 0; i < n; i++ {
		z = e.CyclotomicSquareCompressed(z)
	}
	return z
}

// DecompressKarabina Karabina's cyclotomic square result
func (e Ext12) DecompressKarabina(x *E12) *E12 {

	one := e.Ext2.One()

	// TODO: hadle the g3==0 case with MUX

	// t0 = g1²
	t0 := e.Ext2.Square(&x.C0.B1)
	// t1 = 3 * g1² - 2 * g2
	t1 := e.Ext2.Sub(t0, &x.C0.B2)
	t1 = e.Ext2.Double(t1)
	t1 = e.Ext2.Add(t1, t0)
	// t0 = E * g5² + t1
	t2 := e.Ext2.Square(&x.C1.B2)
	t0 = e.Ext2.MulByNonResidue(t2)
	t0 = e.Ext2.Add(t0, t1)
	// t1 = 4 * g3
	t1 = e.Ext2.Double(&x.C1.B0)
	t1 = e.Ext2.Double(t1)

	// z4 = g4
	C1B1 := e.Ext2.DivUnchecked(t0, t1)

	// t1 = g2 * g1
	t1 = e.Ext2.Mul(&x.C0.B2, &x.C0.B1)
	// t2 = 2 * g4² - 3 * g2 * g1
	t2 = e.Ext2.Square(C1B1)
	t2 = e.Ext2.Sub(t2, t1)
	t2 = e.Ext2.Double(t2)
	t2 = e.Ext2.Sub(t2, t1)
	// t1 = g3 * g5 (g3 can be 0)
	t1 = e.Ext2.Mul(&x.C1.B0, &x.C1.B2)
	// c₀ = E * (2 * g4² + g3 * g5 - 3 * g2 * g1) + 1
	t2 = e.Ext2.Add(t2, t1)
	C0B0 := e.Ext2.MulByNonResidue(t2)
	C0B0 = e.Ext2.Add(C0B0, one)

	return &E12{
		C0: E6{
			B0: *C0B0,
			B1: x.C0.B1,
			B2: x.C0.B2,
		},
		C1: E6{
			B0: x.C1.B0,
			B1: *C1B1,
			B2: x.C1.B2,
		},
	}
}

func (e Ext12) Frobenius(x *E12) *E12 {
	t0 := e.Ext2.Conjugate(&x.C0.B0)
	t1 := e.Ext2.Conjugate(&x.C0.B1)
	t2 := e.Ext2.Conjugate(&x.C0.B2)
	t3 := e.Ext2.Conjugate(&x.C1.B0)
	t4 := e.Ext2.Conjugate(&x.C1.B1)
	t5 := e.Ext2.Conjugate(&x.C1.B2)
	t1 = e.Ext2.MulByNonResidue1Power2(t1)
	t2 = e.Ext2.MulByNonResidue1Power4(t2)
	t3 = e.Ext2.MulByNonResidue1Power1(t3)
	t4 = e.Ext2.MulByNonResidue1Power3(t4)
	t5 = e.Ext2.MulByNonResidue1Power5(t5)
	return &E12{
		C0: E6{
			B0: *t0,
			B1: *t1,
			B2: *t2,
		},
		C1: E6{
			B0: *t3,
			B1: *t4,
			B2: *t5,
		},
	}
}

func (e Ext12) FrobeniusSquare(x *E12) *E12 {
	z00 := &x.C0.B0
	z01 := e.Ext2.MulByNonResidue2Power2(&x.C0.B1)
	z02 := e.Ext2.MulByNonResidue2Power4(&x.C0.B2)
	z10 := e.Ext2.MulByNonResidue2Power1(&x.C1.B0)
	z11 := e.Ext2.MulByNonResidue2Power3(&x.C1.B1)
	z12 := e.Ext2.MulByNonResidue2Power5(&x.C1.B2)
	return &E12{
		C0: E6{B0: *z00, B1: *z01, B2: *z02},
		C1: E6{B0: *z10, B1: *z11, B2: *z12},
	}
}

func (e Ext12) FrobeniusCube(x *E12) *E12 {
	t0 := e.Ext2.Conjugate(&x.C0.B0)
	t1 := e.Ext2.Conjugate(&x.C0.B1)
	t2 := e.Ext2.Conjugate(&x.C0.B2)
	t3 := e.Ext2.Conjugate(&x.C1.B0)
	t4 := e.Ext2.Conjugate(&x.C1.B1)
	t5 := e.Ext2.Conjugate(&x.C1.B2)
	t1 = e.Ext2.MulByNonResidue3Power2(t1)
	t2 = e.Ext2.MulByNonResidue3Power4(t2)
	t3 = e.Ext2.MulByNonResidue3Power1(t3)
	t4 = e.Ext2.MulByNonResidue3Power3(t4)
	t5 = e.Ext2.MulByNonResidue3Power5(t5)
	return &E12{
		C0: E6{
			B0: *t0,
			B1: *t1,
			B2: *t2,
		},
		C1: E6{
			B0: *t3,
			B1: *t4,
			B2: *t5,
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
	c0 := e.Ext6.Sub(&x.C0, &x.C1)
	c3 := e.Ext6.MulByNonResidue(&x.C1)
	c3 = e.Ext6.Neg(c3)
	c3 = e.Ext6.Add(&x.C0, c3)
	c2 := e.Ext6.Mul(&x.C0, &x.C1)
	c0 = e.Ext6.Mul(c0, c3)
	c0 = e.Ext6.Add(c0, c2)
	z1 := e.Ext6.double(c2)
	c2 = e.Ext6.MulByNonResidue(c2)
	z0 := e.Ext6.Add(c0, c2)
	return &E12{
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

func (e Ext12) Inverse(x *E12) *E12 {
	res, err := e.fp.NewHint(inverseE12Hint, 12, &x.C0.B0.A0, &x.C0.B0.A1, &x.C0.B1.A0, &x.C0.B1.A1, &x.C0.B2.A0, &x.C0.B2.A1, &x.C1.B0.A0, &x.C1.B0.A1, &x.C1.B1.A0, &x.C1.B1.A1, &x.C1.B2.A0, &x.C1.B2.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	inv := E12{
		C0: E6{
			B0: E2{A0: *res[0], A1: *res[1]},
			B1: E2{A0: *res[2], A1: *res[3]},
			B2: E2{A0: *res[4], A1: *res[5]},
		},
		C1: E6{
			B0: E2{A0: *res[6], A1: *res[7]},
			B1: E2{A0: *res[8], A1: *res[9]},
			B2: E2{A0: *res[10], A1: *res[11]},
		},
	}

	one := e.One()

	// 1 == inv * x
	_one := e.Mul(&inv, x)
	e.AssertIsEqual(one, _one)

	return &inv

}

// DivUnchecked e2 elmts
func (e Ext12) DivUnchecked(x, y *E12) *E12 {
	res, err := e.fp.NewHint(divE12Hint, 12, &x.C0.B0.A0, &x.C0.B0.A1, &x.C0.B1.A0, &x.C0.B1.A1, &x.C0.B2.A0, &x.C0.B2.A1, &x.C1.B0.A0, &x.C1.B0.A1, &x.C1.B1.A0, &x.C1.B1.A1, &x.C1.B2.A0, &x.C1.B2.A1, &y.C0.B0.A0, &y.C0.B0.A1, &y.C0.B1.A0, &y.C0.B1.A1, &y.C0.B2.A0, &y.C0.B2.A1, &y.C1.B0.A0, &y.C1.B0.A1, &y.C1.B1.A0, &y.C1.B1.A1, &y.C1.B2.A0, &y.C1.B2.A1)

	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	div := E12{
		C0: E6{
			B0: E2{A0: *res[0], A1: *res[1]},
			B1: E2{A0: *res[2], A1: *res[3]},
			B2: E2{A0: *res[4], A1: *res[5]},
		},
		C1: E6{
			B0: E2{A0: *res[6], A1: *res[7]},
			B1: E2{A0: *res[8], A1: *res[9]},
			B2: E2{A0: *res[10], A1: *res[11]},
		},
	}

	// x == div * y
	_x := e.Mul(&div, y)
	e.AssertIsEqual(x, _x)

	return &div
}
