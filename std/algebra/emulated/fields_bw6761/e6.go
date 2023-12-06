package fields_bw6761

import (
	"math/big"

	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type E6 struct {
	B0, B1 E3
}

type Ext6 struct {
	*Ext3
}

func (e Ext6) Reduce(x *E6) *E6 {
	var z E6
	z.B0 = *e.Ext3.Reduce(&x.B0)
	z.B1 = *e.Ext3.Reduce(&x.B1)
	return &z
}

func NewExt6(api frontend.API) *Ext6 {
	return &Ext6{Ext3: NewExt3(api)}
}

func (e Ext6) Zero() *E6 {
	b0 := e.Ext3.Zero()
	b1 := e.Ext3.Zero()
	return &E6{
		B0: *b0,
		B1: *b1,
	}
}

func (e Ext6) One() *E6 {
	return &E6{
		B0: *e.Ext3.One(),
		B1: *e.Ext3.Zero(),
	}
}

func (e Ext6) Add(x, y *E6) *E6 {
	return &E6{
		B0: *e.Ext3.Add(&x.B0, &y.B0),
		B1: *e.Ext3.Add(&x.B1, &y.B1),
	}
}

func (e Ext6) Sub(x, y *E6) *E6 {
	return &E6{
		B0: *e.Ext3.Sub(&x.B0, &y.B0),
		B1: *e.Ext3.Sub(&x.B1, &y.B1),
	}
}

func (e Ext6) Double(x *E6) *E6 {
	return &E6{
		B0: *e.Ext3.Double(&x.B0),
		B1: *e.Ext3.Double(&x.B1),
	}
}

func (e Ext6) Mul(x, y *E6) *E6 {
	x = e.Reduce(x)
	y = e.Reduce(y)

	a := e.Ext3.Add(&x.B0, &x.B1)
	b := e.Ext3.Add(&y.B0, &y.B1)
	a = e.Ext3.Mul(a, b)
	b = e.Ext3.Mul(&x.B0, &y.B0)
	c := e.Ext3.Mul(&x.B1, &y.B1)
	b1 := e.Ext3.Sub(a, b)
	b1 = e.Ext3.Sub(b1, c)
	b0 := e.Ext3.MulByNonResidue(c)
	b0 = e.Ext3.Add(b0, b)

	return &E6{
		B0: *b0,
		B1: *b1,
	}
}

func (e Ext6) Square(x *E6) *E6 {

	x = e.Reduce(x)
	//Algorithm 22 from https://eprint.iacr.org/2010/354.pdf
	c0 := e.Ext3.Sub(&x.B0, &x.B1)
	c3 := e.Ext3.MulByNonResidue(&x.B1)
	c3 = e.Ext3.Neg(c3)
	c3 = e.Ext3.Add(&x.B0, c3)
	c2 := e.Ext3.Mul(&x.B0, &x.B1)
	c0 = e.Ext3.Mul(c0, c3)
	c0 = e.Ext3.Add(c0, c2)
	b1 := e.Ext3.Double(c2)
	c2 = e.Ext3.MulByNonResidue(c2)
	b0 := e.Ext3.Add(c0, c2)

	return &E6{
		B0: *b0,
		B1: *b1,
	}
}

// Karabina's compressed cyclotomic square SQR12345
// https://eprint.iacr.org/2010/542.pdf
// Sec. 5.6 with minor modifications to fit our tower
func (e Ext6) CyclotomicSquareKarabina12345(x *E6) *E6 {
	x = e.Reduce(x)

	// h4 = -g4 + 3((g3+g5)(g1+c*g2)-g1g5-c*g3g2)
	g1g5 := e.fp.Mul(&x.B0.A1, &x.B1.A2)
	g3g2 := e.fp.Mul(&x.B1.A0, &x.B0.A2)
	h4 := mulFpByNonResidue(e.fp, &x.B0.A2)
	h4 = e.fp.Add(h4, &x.B0.A1)
	t := e.fp.Add(&x.B1.A0, &x.B1.A2)
	h4 = e.fp.Mul(h4, t)
	h4 = e.fp.Sub(h4, g1g5)
	t = e.fp.MulConst(g3g2, big.NewInt(4))
	h4 = e.fp.Add(h4, t)
	h4 = e.fp.MulConst(h4, big.NewInt(3))
	h4 = e.fp.Sub(h4, &x.B1.A1)

	// h3 = 2(g3+3c*g1g5)
	h3 := mulFpByNonResidue(e.fp, g1g5)
	h3 = e.fp.MulConst(h3, big.NewInt(3))
	h3 = e.fp.Add(h3, &x.B1.A0)
	h3 = e.fp.MulConst(h3, big.NewInt(2))

	// h2 = 3((g1+g5)(g1+c*g5)-(c+1)*g1g5)-2g2
	t = mulFpByNonResidue(e.fp, &x.B1.A2)
	t = e.fp.Add(t, &x.B0.A1)
	h2 := e.fp.Add(&x.B1.A2, &x.B0.A1)
	h2 = e.fp.Mul(h2, t)
	t = e.fp.MulConst(g1g5, big.NewInt(3))
	h2 = e.fp.Add(h2, t)
	h2 = e.fp.MulConst(h2, big.NewInt(3))
	t = e.fp.MulConst(&x.B0.A2, big.NewInt(2))
	h2 = e.fp.Sub(h2, t)

	// h1 = 3((g3+g2)(g3+c*g2)-(c+1)*g3g2)-2g1
	t = mulFpByNonResidue(e.fp, &x.B0.A2)
	t = e.fp.Add(t, &x.B1.A0)
	h1 := e.fp.Add(&x.B0.A2, &x.B1.A0)
	h1 = e.fp.Mul(h1, t)
	t = e.fp.MulConst(g3g2, big.NewInt(3))
	h1 = e.fp.Add(h1, t)
	h1 = e.fp.MulConst(h1, big.NewInt(3))
	t = e.fp.MulConst(&x.B0.A1, big.NewInt(2))
	h1 = e.fp.Sub(h1, t)

	// h5 = 2(g5+3g3g2)
	h5 := e.fp.MulConst(g3g2, big.NewInt(3))
	h5 = e.fp.Add(h5, &x.B1.A2)
	h5 = e.fp.MulConst(h5, big.NewInt(2))

	return &E6{
		B0: E3{
			A0: x.B0.A0,
			A1: *h1,
			A2: *h2,
		},
		B1: E3{
			A0: *h3,
			A1: *h4,
			A2: *h5,
		},
	}
}

// DecompressKarabina12345 decompresses Karabina's cyclotomic square result SQR12345
func (e Ext6) DecompressKarabina12345(x *E6) *E6 {
	x = e.Reduce(x)

	// h0 = (2g4^2 + g3g5 - 3g2g1)*c + 1
	t0 := e.fp.Mul(&x.B0.A1, &x.B0.A2)
	t0 = e.fp.MulConst(t0, big.NewInt(3))
	t1 := e.fp.Mul(&x.B1.A0, &x.B1.A2)
	h0 := e.fp.Mul(&x.B1.A1, &x.B1.A1)
	h0 = e.fp.MulConst(h0, big.NewInt(2))
	h0 = e.fp.Add(h0, t1)
	h0 = e.fp.Sub(t0, h0)
	h0 = e.fp.MulConst(h0, big.NewInt(4))
	h0 = e.fp.Add(h0, e.fp.One())

	return &E6{
		B0: E3{
			A0: *h0,
			A1: x.B0.A1,
			A2: x.B0.A2,
		},
		B1: x.B1,
	}
}

// Karabina's compressed cyclotomic square SQR2345
// https://eprint.iacr.org/2010/542.pdf
// Th. 3.2 with minor modifications to fit our tower
func (e Ext6) CyclotomicSquareKarabina2345(x *E6) *E6 {
	x = e.Reduce(x)
	z := e.Copy(x)

	var t [7]*baseEl

	// t0 = g1²
	t[0] = e.fp.Mul(&x.B0.A1, &x.B0.A1)
	// t1 = g5²
	t[1] = e.fp.Mul(&x.B1.A2, &x.B1.A2)
	// t5 = g1 + g5
	t[5] = e.fp.Add(&x.B0.A1, &x.B1.A2)
	// t2 = (g1 + g5)²
	t[2] = e.fp.Mul(t[5], t[5])

	// t3 = g1² + g5²
	t[3] = e.fp.Add(t[0], t[1])
	// t5 = 2 * g1 * g5
	t[5] = e.fp.Sub(t[3], t[2])

	// t6 = g3 + g2
	t[6] = e.fp.Add(&x.B1.A0, &x.B0.A2)
	// t3 = (g3 + g2)²
	t[3] = e.fp.Mul(t[6], t[6])
	// t2 = g3²
	t[2] = e.fp.Mul(&x.B1.A0, &x.B1.A0)

	// t6 = 2 * nr * g1 * g5
	t[6] = e.fp.MulConst(t[5], big.NewInt(4))
	// t5 = 4 * nr * g1 * g5 + 2 * g3
	t[5] = e.fp.Add(t[6], &x.B1.A0)
	t[5] = e.fp.MulConst(t[5], big.NewInt(2))
	// z3 = 6 * nr * g1 * g5 + 2 * g3
	z.B1.A0 = *e.fp.Add(t[5], t[6])

	// t4 = nr * g5²
	t[4] = mulFpByNonResidue(e.fp, t[1])
	// t5 = nr * g5² + g1²
	t[5] = e.fp.Add(t[0], t[4])
	// t6 = nr * g5² + g1² - g2
	t[6] = e.fp.Sub(t[5], &x.B0.A2)

	// t1 = g2²
	t[1] = e.fp.Mul(&x.B0.A2, &x.B0.A2)

	// t6 = 2 * nr * g5² + 2 * g1² - 2*g2
	t[6] = e.fp.MulConst(t[6], big.NewInt(2))
	// z2 = 3 * nr * g5² + 3 * g1² - 2*g2
	z.B0.A2 = *e.fp.Add(t[6], t[5])

	// t4 = nr * g2²
	t[4] = mulFpByNonResidue(e.fp, t[1])
	// t5 = g3² + nr * g2²
	t[5] = e.fp.Add(t[2], t[4])
	// t6 = g3² + nr * g2² - g1
	t[6] = e.fp.Sub(t[5], &x.B0.A1)
	// t6 = 2 * g3² + 2 * nr * g2² - 2 * g1
	t[6] = e.fp.MulConst(t[6], big.NewInt(2))
	// z1 = 3 * g3² + 3 * nr * g2² - 2 * g1
	z.B0.A1 = *e.fp.Add(t[6], t[5])

	// t0 = g2² + g3²
	t[0] = e.fp.Add(t[2], t[1])
	// t5 = 2 * g3 * g2
	t[5] = e.fp.Sub(t[3], t[0])
	// t6 = 2 * g3 * g2 + g5
	t[6] = e.fp.Add(t[5], &x.B1.A2)
	// t6 = 4 * g3 * g2 + 2 * g5
	t[6] = e.fp.MulConst(t[6], big.NewInt(2))
	// z5 = 6 * g3 * g2 + 2 * g5
	z.B1.A2 = *e.fp.Add(t[5], t[6])

	return z
}

// DecompressKarabina2345 decompresses Karabina's cyclotomic square result SQR2345
// if g3 != 0
//
//	g4 = (E * g5^2 + 3 * g1^2 - 2 * g2)/4g3
//
// if g3 == 0
//
//	g4 = 2g1g5/g2
//
// if g3=g2=0 then g4=g5=g1=0 and g0=1 (x=1)
// Theorem 3.1 is well-defined for all x in Gϕₙ\{1}
func (e Ext6) DecompressKarabina2345(x *E6) *E6 {

	x = e.Reduce(x)

	var z E6

	var t [3]*baseEl
	var _t [2]*baseEl
	one := e.fp.One()

	// if g3 == 0
	// t0 = 2 * g1 * g5
	// t1 = g2
	selector1 := e.fp.IsZero(&x.B1.A0)
	_t[0] = e.fp.Mul(&x.B0.A1, &x.B0.A1)
	_t[0] = e.fp.MulConst(_t[0], big.NewInt(2))
	_t[1] = &x.B0.A2

	// if g2 == g3 == 0
	selector2 := e.fp.IsZero(_t[1])

	// if g3 != 0
	// t0 = E * g5^2 + 3 * g1^2 - 2 * g2
	// t1 = 4 * g3
	t[0] = e.fp.Mul(&x.B0.A1, &x.B0.A1)
	t[1] = e.fp.Sub(t[0], &x.B0.A2)
	t[1] = e.fp.MulConst(t[1], big.NewInt(2))
	t[1] = e.fp.Add(t[1], t[0])
	t[2] = e.fp.Mul(&x.B1.A2, &x.B1.A2)
	t[0] = mulFpByNonResidue(e.fp, t[2])
	t[0] = e.fp.Add(t[0], t[1])
	t[1] = e.fp.Add(&x.B1.A0, &x.B1.A0)
	t[1] = e.fp.MulConst(t[1], big.NewInt(2))

	// g4 = (E * g5^2 + 3 * g1^2 - 2 * g2)/4g3 or (2 * g1 * g5)/g2
	t[0] = e.fp.Select(selector1, _t[0], t[0])
	t[1] = e.fp.Select(selector1, _t[1], t[1])
	// g4 = dummy value, continue
	t[1] = e.fp.Select(selector2, one, t[1])

	z.B1.A1 = *e.fp.Div(t[0], t[1])

	// Rest of the computation for all cases
	// t1 = g2 * g1
	t[1] = e.fp.Mul(&x.B0.A2, &x.B0.A1)
	// t2 = 2 * g4² - 3 * g2 * g1
	t[2] = e.fp.Mul(&z.B1.A1, &z.B1.A1)
	t[2] = e.fp.Sub(t[2], t[1])
	t[2] = e.fp.MulConst(t[2], big.NewInt(2))
	t[2] = e.fp.Sub(t[2], t[1])
	// t1 = g3 * g5 (g3 can be 0)
	t[1] = e.fp.Mul(&x.B1.A0, &x.B1.A2)
	// g0 = E * (2 * g4² + g3 * g5 - 3 * g2 * g1) + 1
	t[2] = e.fp.Add(t[2], t[1])

	z.B0.A0 = *mulFpByNonResidue(e.fp, t[2])
	z.B0.A0 = *e.fp.Add(&z.B0.A0, one)

	z.B0.A1 = x.B0.A1
	z.B0.A2 = x.B0.A2
	z.B1.A0 = x.B1.A0
	z.B1.A2 = x.B1.A2

	return e.Select(e.api.And(selector1, selector2), e.One(), &z)
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

	t[0] = e.fp.Mul(&x.B1.A1, &x.B1.A1)
	t[1] = e.fp.Mul(&x.B0.A0, &x.B0.A0)
	t[6] = e.fp.Add(&x.B1.A1, &x.B0.A0)
	t[6] = e.fp.Mul(t[6], t[6])
	t[6] = e.fp.Sub(t[6], t[0])
	t[6] = e.fp.Sub(t[6], t[1]) // 2*x4*x0
	t[2] = e.fp.Mul(&x.B0.A2, &x.B0.A2)
	t[3] = e.fp.Mul(&x.B1.A0, &x.B1.A0)
	t[7] = e.fp.Add(&x.B0.A2, &x.B1.A0)
	t[7] = e.fp.Mul(t[7], t[7])
	t[7] = e.fp.Sub(t[7], t[2])
	t[7] = e.fp.Sub(t[7], t[3]) // 2*x2*x3
	t[4] = e.fp.Mul(&x.B1.A2, &x.B1.A2)
	t[5] = e.fp.Mul(&x.B0.A1, &x.B0.A1)
	t[8] = e.fp.Add(&x.B1.A2, &x.B0.A1)
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
	z.B0.A0 = *e.fp.Sub(t[0], &x.B0.A0)
	z.B0.A0 = *e.fp.MulConst(&z.B0.A0, big.NewInt(2))
	z.B0.A0 = *e.fp.Add(&z.B0.A0, t[0])
	z.B0.A1 = *e.fp.Sub(t[2], &x.B0.A1)
	z.B0.A1 = *e.fp.MulConst(&z.B0.A1, big.NewInt(2))
	z.B0.A1 = *e.fp.Add(&z.B0.A1, t[2])
	z.B0.A2 = *e.fp.Sub(t[4], &x.B0.A2)
	z.B0.A2 = *e.fp.MulConst(&z.B0.A2, big.NewInt(2))
	z.B0.A2 = *e.fp.Add(&z.B0.A2, t[4])

	z.B1.A0 = *e.fp.Add(t[8], &x.B1.A0)
	z.B1.A0 = *e.fp.MulConst(&z.B1.A0, big.NewInt(2))
	z.B1.A0 = *e.fp.Add(&z.B1.A0, t[8])
	z.B1.A1 = *e.fp.Add(t[6], &x.B1.A1)
	z.B1.A1 = *e.fp.MulConst(&z.B1.A1, big.NewInt(2))
	z.B1.A1 = *e.fp.Add(&z.B1.A1, t[6])
	z.B1.A2 = *e.fp.Add(t[7], &x.B1.A2)
	z.B1.A2 = *e.fp.Add(&z.B1.A2, &z.B1.A2)
	z.B1.A2 = *e.fp.Add(&z.B1.A2, t[7])

	return &z
}

func (e Ext6) Inverse(x *E6) *E6 {
	res, err := e.fp.NewHint(inverseE6Hint, 6, &x.B0.A0, &x.B0.A1, &x.B0.A2, &x.B1.A0, &x.B1.A1, &x.B1.A2)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	inv := E6{
		B0: E3{A0: *res[0], A1: *res[1], A2: *res[2]},
		B1: E3{A0: *res[3], A1: *res[4], A2: *res[5]},
	}
	one := e.One()

	// 1 == inv * x
	_one := e.Mul(&inv, x)
	e.AssertIsEqual(one, _one)

	return &inv

}

func (e Ext6) DivUnchecked(x, y *E6) *E6 {
	res, err := e.fp.NewHint(divE6Hint, 12, &x.B0.A0, &x.B0.A1, &x.B0.A2, &x.B1.A0, &x.B1.A1, &x.B1.A2, &y.B0.A0, &y.B0.A1, &y.B0.A2, &y.B1.A0, &y.B1.A1, &y.B1.A2)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	div := E6{
		B0: E3{A0: *res[0], A1: *res[1], A2: *res[2]},
		B1: E3{A0: *res[3], A1: *res[4], A2: *res[5]},
	}

	// x = div * y
	_x := e.Mul(&div, y)
	e.AssertIsEqual(x, _x)

	return &div

}

func (e Ext6) Conjugate(x *E6) *E6 {
	return &E6{
		B0: x.B0,
		B1: *e.Ext3.Neg(&x.B1),
	}
}

func (e Ext6) AssertIsEqual(a, b *E6) {
	e.Ext3.AssertIsEqual(&a.B0, &b.B0)
	e.Ext3.AssertIsEqual(&a.B1, &b.B1)
}

func (e Ext6) Copy(x *E6) *E6 {
	b0 := e.Ext3.Copy(&x.B0)
	b1 := e.Ext3.Copy(&x.B1)
	return &E6{
		B0: *b0,
		B1: *b1,
	}
}

func FromE6(a *bw6761.E6) E6 {
	return E6{
		B0: FromE3(&a.B0),
		B1: FromE3(&a.B1),
	}
}

// Frobenius set z in E6 to Frobenius(x), return z
func (e Ext6) Frobenius(x *E6) *E6 {
	_frobA := emulated.ValueOf[emulated.BW6761Fp]("4922464560225523242118178942575080391082002530232324381063048548642823052024664478336818169867474395270858391911405337707247735739826664939444490469542109391530482826728203582549674992333383150446779312029624171857054392282775648")
	_frobB := emulated.ValueOf[emulated.BW6761Fp]("1968985824090209297278610739700577151397666382303825728450741611566800370218827257750865013421937292370006175842381275743914023380727582819905021229583192207421122272650305267822868639090213645505120388400344940985710520836292650")
	_frobC := emulated.ValueOf[emulated.BW6761Fp]("4922464560225523242118178942575080391082002530232324381063048548642823052024664478336818169867474395270858391911405337707247735739826664939444490469542109391530482826728203582549674992333383150446779312029624171857054392282775649")
	_frobAC := emulated.ValueOf[emulated.BW6761Fp]("-1")
	_frobBC := emulated.ValueOf[emulated.BW6761Fp]("1968985824090209297278610739700577151397666382303825728450741611566800370218827257750865013421937292370006175842381275743914023380727582819905021229583192207421122272650305267822868639090213645505120388400344940985710520836292651")
	var z E6
	z.B0.A0 = x.B0.A0
	z.B0.A1 = *e.fp.Mul(&x.B0.A1, &_frobA)
	z.B0.A2 = *e.fp.Mul(&x.B0.A2, &_frobB)

	z.B1.A0 = *e.fp.Mul(&x.B1.A0, &_frobC)
	z.B1.A1 = *e.fp.Mul(&x.B1.A1, &_frobAC)
	z.B1.A2 = *e.fp.Mul(&x.B1.A2, &_frobBC)

	return &z
}

func (e Ext6) Select(selector frontend.Variable, z1, z0 *E6) *E6 {
	b0 := e.Ext3.Select(selector, &z1.B0, &z0.B0)
	b1 := e.Ext3.Select(selector, &z1.B1, &z0.B1)
	return &E6{B0: *b0, B1: *b1}
}
