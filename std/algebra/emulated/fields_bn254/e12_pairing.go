package fields_bn254

import (
	"math/big"
)

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

// Exponentiation by the seed t=4965661367192848881
func (e Ext12) Expt(x *E12) *E12 {
	// ExptTorus computation is derived from the addition chain:
	//
	//	_10     = 2*1
	//	_100    = 2*_10
	//	_1000   = 2*_100
	//	_10000  = 2*_1000
	//	_10001  = 1 + _10000
	//	_10011  = _10 + _10001
	//	_10100  = 1 + _10011
	//	_11001  = _1000 + _10001
	//	_100010 = 2*_10001
	//	_100111 = _10011 + _10100
	//	_101001 = _10 + _100111
	//	i27     = (_100010 << 6 + _100 + _11001) << 7 + _11001
	//	i44     = (i27 << 8 + _101001 + _10) << 6 + _10001
	//	i70     = ((i44 << 8 + _101001) << 6 + _101001) << 10
	//	return    (_100111 + i70) << 6 + _101001 + _1000
	//
	// Operations: 62 squares 17 multiplies
	//
	// Generated by github.com/mmcloughlin/addchain v0.4.0.

	t3 := e.CyclotomicSquareGS(x)
	t5 := e.CyclotomicSquareGS(t3)
	result := e.CyclotomicSquareGS(t5)
	t0 := e.CyclotomicSquareGS(result)
	t2 := e.Mul(x, t0)
	t0 = e.Mul(t3, t2)
	t1 := e.Mul(x, t0)
	t4 := e.Mul(result, t2)
	t6 := e.CyclotomicSquareGS(t2)
	t1 = e.Mul(t0, t1)
	t0 = e.Mul(t3, t1)
	t6 = e.nSquareGS(t6, 6)
	t5 = e.Mul(t5, t6)
	t5 = e.Mul(t4, t5)
	t5 = e.nSquareGS(t5, 7)
	t4 = e.Mul(t4, t5)
	t4 = e.nSquareGS(t4, 8)
	t4 = e.Mul(t0, t4)
	t3 = e.Mul(t3, t4)
	t3 = e.nSquareGS(t3, 6)
	t2 = e.Mul(t2, t3)
	t2 = e.nSquareGS(t2, 8)
	t2 = e.Mul(t0, t2)
	t2 = e.nSquareGS(t2, 6)
	t2 = e.Mul(t0, t2)
	t2 = e.nSquareGS(t2, 10)
	t1 = e.Mul(t1, t2)
	t1 = e.nSquareGS(t1, 6)
	t0 = e.Mul(t0, t1)
	z := e.Mul(result, t0)
	return z
}

// Exponentiation by U=6u+2 where t is the seed u=4965661367192848881
func (e Ext12) ExpByU(x *E12) *E12 {
	// ExpByU computation is derived from the addition chain:
	//	_10      = 2*1
	//	_11      = 1 + _10
	//	_110     = 2*_11
	//	_111     = 1 + _110
	//	_1100    = 2*_110
	//	_1111    = _11 + _1100
	//	_1100000 = _1100 << 3
	//	_1100111 = _111 + _1100000
	//	i22      = ((_1100111 << 2 + 1) << 5 + _1111) << 3
	//	i38      = ((1 + i22) << 4 + _111) << 9 + _111
	//	i50      = 2*((i38 << 4 + _11) << 5 + _1111)
	//	i61      = ((1 + i50) << 5 + _111) << 3 + _11
	//	i75      = ((i61 << 6 + _111) << 4 + _111) << 2
	//	return     ((1 + i75) << 2 + 1) << 3
	//
	// Operations: 64 squares 18 multiplies
	//
	// Generated by github.com/mmcloughlin/addchain v0.4.0.

	z := e.Square(x)
	t0 := e.Mul(x, z)
	t1 := e.Square(t0)
	z = e.Mul(x, t1)
	t2 := e.Square(t1)
	t1 = e.Mul(t0, t2)
	t2 = e.nSquare(t2, 3)
	t2 = e.Mul(z, t2)
	t2 = e.nSquare(t2, 2)
	t2 = e.Mul(x, t2)
	t2 = e.nSquare(t2, 5)
	t2 = e.Mul(t1, t2)
	t2 = e.nSquare(t2, 3)
	t2 = e.Mul(x, t2)
	t2 = e.nSquare(t2, 4)
	t2 = e.Mul(z, t2)
	t2 = e.nSquare(t2, 9)
	t2 = e.Mul(z, t2)
	t2 = e.nSquare(t2, 4)
	t2 = e.Mul(t0, t2)
	t2 = e.nSquare(t2, 5)
	t1 = e.Mul(t1, t2)
	t1 = e.Square(t1)
	t1 = e.Mul(x, t1)
	t1 = e.nSquare(t1, 5)
	t1 = e.Mul(z, t1)
	t1 = e.nSquare(t1, 3)
	t0 = e.Mul(t0, t1)
	t0 = e.nSquare(t0, 6)
	t0 = e.Mul(z, t0)
	t0 = e.nSquare(t0, 4)
	z = e.Mul(z, t0)
	z = e.nSquare(z, 2)
	z = e.Mul(x, z)
	z = e.nSquare(z, 2)
	z = e.Mul(x, z)
	z = e.nSquare(z, 3)

	return z
}

// MulBy01379 multiplies a by an E12 sparse element b of the form
//
//	b.A0  =  1
//	b.A1  =  c3.A0 - 9 * c3.A1
//	b.A2  =  0
//	b.A3  =  c4.A0 - 9 * c4.A1
//	b.A4  =  0
//	b.A5  =  0
//	b.A6  =  0
//	b.A7  =  c3.A1
//	b.A8  =  0
//	b.A9  =  c4.A1
//	b.A10 =  0
//	b.A11 =  0
func (e *Ext12) MulBy01379(a *E12, c3, c4 *E2) *E12 {
	nine := big.NewInt(9)
	b1 := e.fp.Sub(&c3.A0, e.fp.MulConst(&c3.A1, nine))
	b3 := e.fp.Sub(&c4.A0, e.fp.MulConst(&c4.A1, nine))
	b7 := &c3.A1
	b9 := &c4.A1
	// d0  =  a0  - 82 * (a3 b9 + a5 b7 + a9 b3 + a11 b1) - 1476 * (a9 b9 + a11 b7)
	mone := e.fp.NewElement(-1)
	d0 := e.fp.Eval([][]*baseEl{{&a.A0}, {mone, &a.A3, b9}, {mone, &a.A5, b7}, {mone, &a.A9, b3}, {mone, &a.A11, b1}, {mone, &a.A9, b9}, {mone, &a.A11, b7}}, []int{1, 82, 82, 82, 82, 1476, 1476})

	// d1  =  a0 b1 + a1  - 82 * (a4 b9 + a10 b3 + a6 b7) - 1476 * a10 b9
	d1 := e.fp.Eval([][]*baseEl{{&a.A0, b1}, {&a.A1}, {mone, &a.A4, b9}, {mone, &a.A10, b3}, {mone, &a.A6, b7}, {mone, &a.A10, b9}}, []int{1, 1, 82, 82, 82, 1476})

	// d2  =  a1 b1 + a2  - 82 * (a5 b9 + a11 b3 + a7 b7) - 1476 * a11 b9
	d2 := e.fp.Eval([][]*baseEl{{&a.A1, b1}, {&a.A2}, {mone, &a.A5, b9}, {mone, &a.A11, b3}, {mone, &a.A7, b7}, {mone, &a.A11, b9}}, []int{1, 1, 82, 82, 82, 1476})

	// d3  =  a0 b3 + a2 b1 + a3 - 82 * (a6 b9 + a8 b7)
	d3 := e.fp.Eval([][]*baseEl{{&a.A0, b3}, {&a.A2, b1}, {&a.A3}, {mone, &a.A6, b9}, {mone, &a.A8, b7}}, []int{1, 1, 1, 82, 82})

	// d4  =  a1 b3 + a3 b1 + a4  - 82 * (a7 b9 + a9 b7)
	d4 := e.fp.Eval([][]*baseEl{{&a.A1, b3}, {&a.A3, b1}, {&a.A4}, {mone, &a.A7, b9}, {mone, &a.A9, b7}}, []int{1, 1, 1, 82, 82})

	// d5  =  a2 b3 + a4 b1 + a5  - 82 * (a8 b9 + a10 b7)
	d5 := e.fp.Eval([][]*baseEl{{&a.A2, b3}, {&a.A4, b1}, {&a.A5}, {mone, &a.A8, b9}, {mone, &a.A10, b7}}, []int{1, 1, 1, 82, 82})

	// d6  =  a3 b3 + a5 b1 + a6 + 18 * (a3 b9 + a9 b3 + a11 b1 + a5 b7) + 242 * (a9 b9 + a11 b7)
	d6 := e.fp.Eval([][]*baseEl{{&a.A3, b3}, {&a.A5, b1}, {&a.A6}, {&a.A3, b9}, {&a.A9, b3}, {&a.A11, b1}, {&a.A5, b7}, {&a.A11, b7}, {&a.A9, b9}}, []int{1, 1, 1, 18, 18, 18, 18, 242, 242})

	// d7  =  a0 b7 + a4 b3 + a6 b1 + a7 + 18 * (a4 b9 + a10 b3 + a6 b7) + 242 * a10 b9
	d7 := e.fp.Eval([][]*baseEl{{&a.A0, b7}, {&a.A4, b3}, {&a.A6, b1}, {&a.A7}, {&a.A4, b9}, {&a.A10, b3}, {&a.A6, b7}, {&a.A10, b9}}, []int{1, 1, 1, 1, 18, 18, 18, 242})

	// d8  =  a1 b7 + a5 b3 + a7 b1 + a8  + 18 * (a5 b9 + a11 b3 + a7 b7) + 242 * a11 b9
	d8 := e.fp.Eval([][]*baseEl{{&a.A1, b7}, {&a.A5, b3}, {&a.A7, b1}, {&a.A8}, {&a.A5, b9}, {&a.A11, b3}, {&a.A7, b7}, {&a.A11, b9}}, []int{1, 1, 1, 1, 18, 18, 18, 242})

	// d9  =  a2 b7 + a0 b9 + a6 b3 + a8 b1 + a9  + 18 * (a6 b9 + a8 b7)
	d9 := e.fp.Eval([][]*baseEl{{&a.A2, b7}, {&a.A0, b9}, {&a.A6, b3}, {&a.A8, b1}, {&a.A9}, {&a.A6, b9}, {&a.A8, b7}}, []int{1, 1, 1, 1, 1, 18, 18})

	// d10 =  a3 b7 + a1 b9 + a7 b3 + a9 b1 + a10 + 18 * (a7 b9 + a9 b7)
	d10 := e.fp.Eval([][]*baseEl{{&a.A3, b7}, {&a.A1, b9}, {&a.A7, b3}, {&a.A9, b1}, {&a.A10}, {&a.A7, b9}, {&a.A9, b7}}, []int{1, 1, 1, 1, 1, 18, 18})

	// d11 =  a4 b7 + a2 b9 + a8 b3 + a10 b1 + a11 + 18 * (a8 b9 + a10 b7)
	d11 := e.fp.Eval([][]*baseEl{{&a.A4, b7}, {&a.A2, b9}, {&a.A8, b3}, {&a.A10, b1}, {&a.A11}, {&a.A8, b9}, {&a.A10, b7}}, []int{1, 1, 1, 1, 1, 18, 18})

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

// Mul01379By01379 multiplies two E12 sparse element of the form:
//
//	A0  =  1
//	A1  =  c3.A0 - 9 * c3.A1
//	A2  =  0
//	A3  =  c4.A0 - 9 * c4.A1
//	A4  =  0
//	A5  =  0
//	A6  =  0
//	A7  =  c3.A1
//	A8  =  0
//	A9  =  c4.A1
//	A10 =  0
//	A11 =  0
func (e *Ext12) Mul01379By01379(e3, e4, c3, c4 *E2) [10]*baseEl {
	nine := big.NewInt(9)
	a1 := e.fp.Sub(&e3.A0, e.fp.MulConst(&e3.A1, nine))
	a3 := e.fp.Sub(&e4.A0, e.fp.MulConst(&e4.A1, nine))
	a7 := &e3.A1
	a9 := &e4.A1
	b1 := e.fp.Sub(&c3.A0, e.fp.MulConst(&c3.A1, nine))
	b3 := e.fp.Sub(&c4.A0, e.fp.MulConst(&c4.A1, nine))
	b7 := &c3.A1
	b9 := &c4.A1

	// d0  =  1  - 82 * (a3 b9 + a9 b3) - 1476 * a9 b9
	mone := e.fp.NewElement(-1)
	d0 := e.fp.Eval([][]*baseEl{{a3, b9}, {a9, b3}, {a9, b9}, {mone}}, []int{82, 82, 1476, 1})
	d0 = e.fp.Neg(d0)

	// d1  =  b1 + a1
	d1 := e.fp.Add(a1, b1)

	// d2  =  a1 b1 - 82 * a7 b7
	d2 := e.fp.Eval([][]*baseEl{{a1, b1}, {mone, a7, b7}}, []int{1, 82})

	// d3  =  b3 + a3
	d3 := e.fp.Add(a3, b3)

	// d4  =  a1 b3 + a3 b1 - 82 * (a7 b9 + a9 b7)
	d4 := e.fp.Eval([][]*baseEl{{a1, b3}, {a3, b1}, {mone, a7, b9}, {mone, a9, b7}}, []int{1, 1, 82, 82})

	// d6  =  a3 b3 + 18 * (a3 b9 + a9 b3) + 242 * a9 b9
	d6 := e.fp.Eval([][]*baseEl{{a3, b3}, {a3, b9}, {a9, b3}, {a9, b9}}, []int{1, 18, 18, 242})

	// d7  =  b7 + a7
	d7 := e.fp.Add(a7, b7)

	// d8  =  a1 b7 + a7 b1 + 18 * a7 b7
	d8 := e.fp.Eval([][]*baseEl{{a1, b7}, {a7, b1}, {a7, b7}}, []int{1, 1, 18})

	// d9  =  b9 + a9
	d9 := e.fp.Add(a9, b9)

	// d10 =  a3 b7 + a1 b9 + a7 b3 + a9 b1 + 18 * (a7 b9 + a9 b7)
	d10 := e.fp.Eval([][]*baseEl{{a3, b7}, {a1, b9}, {a7, b3}, {a9, b1}, {a7, b9}, {a9, b7}}, []int{1, 1, 1, 1, 18, 18})

	return [10]*baseEl{d0, d1, d2, d3, d4, d6, d7, d8, d9, d10}
}

// MulBy012346789 multiplies a by an E12 sparse element b of the form
//
//	b.A0  =  b[0]
//	b.A1  =  b[1]
//	b.A2  =  b[2]
//	b.A3  =  b[3]
//	b.A4  =  b[4]
//	b.A5  =  0
//	b.A6  =  b[5]
//	b.A7  =  b[6]
//	b.A8  =  b[7]
//	b.A9  =  b[8]
//	b.A10 =  b[9]
//	b.A11 =  0
func (e *Ext12) MulBy012346789(a *E12, b [10]*baseEl) *E12 {
	// d0  =  a0 b0  - 82 * (a2 b10 + a3 b9 + a4 b8 + a5 b7 + a6 b6 + a8 b4 + a9 b3 + a10 b2 + a11 b1) - 1476 * (a8 b10 + a9 b9 + a10 b8 + a11 b7)
	mone := e.fp.NewElement(-1)
	d0 := e.fp.Eval([][]*baseEl{{&a.A0, b[0]}, {mone, &a.A2, b[9]}, {mone, &a.A3, b[8]}, {mone, &a.A4, b[7]}, {mone, &a.A5, b[6]}, {mone, &a.A6, b[5]}, {mone, &a.A8, b[4]}, {mone, &a.A9, b[3]}, {mone, &a.A10, b[2]}, {mone, &a.A11, b[1]}, {mone, &a.A8, b[9]}, {mone, &a.A9, b[8]}, {mone, &a.A10, b[7]}, {mone, &a.A11, b[6]}}, []int{1, 82, 82, 82, 82, 82, 82, 82, 82, 82, 1476, 1476, 1476, 1476})

	// d1  =  a0 b1 + a1 b0  - 82 * (a3 b10 + a4 b9 + a5 b8 + a6 b7 + a7 b6 + a9 b4 + a10 b3 + a11 b2) - 1476 * (a9 b10 + a10 b9 + a11 b8)
	d1 := e.fp.Eval([][]*baseEl{{&a.A0, b[1]}, {&a.A1, b[0]}, {mone, &a.A3, b[9]}, {mone, &a.A4, b[8]}, {mone, &a.A5, b[7]}, {mone, &a.A6, b[6]}, {mone, &a.A7, b[5]}, {mone, &a.A9, b[4]}, {mone, &a.A10, b[3]}, {mone, &a.A11, b[2]}, {mone, &a.A9, b[9]}, {mone, &a.A10, b[8]}, {mone, &a.A11, b[7]}}, []int{1, 1, 82, 82, 82, 82, 82, 82, 82, 82, 1476, 1476, 1476})

	// d2  =  a0 b2 + a1 b1 + a2 b0  - 82 * (a4 b10 + a5 b9 + a6 b8 + a7 b7 + a8 b6 + a10 b4 + a11 b3) - 1476 * (a10 b10 + a11 b9)
	d2 := e.fp.Eval([][]*baseEl{{&a.A0, b[2]}, {&a.A1, b[1]}, {&a.A2, b[0]}, {mone, &a.A4, b[9]}, {mone, &a.A5, b[8]}, {mone, &a.A6, b[7]}, {mone, &a.A7, b[6]}, {mone, &a.A8, b[5]}, {mone, &a.A10, b[4]}, {mone, &a.A11, b[3]}, {mone, &a.A10, b[9]}, {mone, &a.A11, b[8]}}, []int{1, 1, 1, 82, 82, 82, 82, 82, 82, 82, 1476, 1476})

	// d3  =  a0 b3 + a1 b2 + a2 b1 + a3 b0  - 82 * (a5 b10 + a6 b9 + a7 b8 + a8 b7 + a9 b6 + a11 b4) - 1476 * a11 b10
	d3 := e.fp.Eval([][]*baseEl{{&a.A0, b[3]}, {&a.A1, b[2]}, {&a.A2, b[1]}, {&a.A3, b[0]}, {mone, &a.A5, b[9]}, {mone, &a.A6, b[8]}, {mone, &a.A7, b[7]}, {mone, &a.A8, b[6]}, {mone, &a.A9, b[5]}, {mone, &a.A11, b[4]}, {mone, &a.A11, b[9]}}, []int{1, 1, 1, 1, 82, 82, 82, 82, 82, 82, 1476})

	// d4  =  a0 b4 + a1 b3 + a2 b2 + a3 b1 + a4 b0  - 82 * (a6 b10 + a7 b9 + a8 b8 + a9 b7 + a10 b6)
	d4 := e.fp.Eval([][]*baseEl{{&a.A0, b[4]}, {&a.A1, b[3]}, {&a.A2, b[2]}, {&a.A3, b[1]}, {&a.A4, b[0]}, {mone, &a.A6, b[9]}, {mone, &a.A7, b[8]}, {mone, &a.A8, b[7]}, {mone, &a.A9, b[6]}, {mone, &a.A10, b[5]}}, []int{1, 1, 1, 1, 1, 82, 82, 82, 82, 82})

	// d5  =  a1 b4 + a2 b3 + a3 b2 + a4 b1 + a5 b0  - 82 * (a7 b10 + a8 b9 + a9 b8 + a10 b7 + a11 b6)
	d5 := e.fp.Eval([][]*baseEl{{&a.A1, b[4]}, {&a.A2, b[3]}, {&a.A3, b[2]}, {&a.A4, b[1]}, {&a.A5, b[0]}, {mone, &a.A7, b[9]}, {mone, &a.A8, b[8]}, {mone, &a.A9, b[7]}, {mone, &a.A10, b[6]}, {mone, &a.A11, b[5]}}, []int{1, 1, 1, 1, 1, 82, 82, 82, 82, 82})

	// d6  =  a0 b6 + a2 b4 + a3 b3 + a4 b2 + a5 b1 + a6 b0  + 18 * (a2 b10 + a3 b9 + a4 b8 + a5 b7 + a6 b6 + a8 b4 + a9 b3 + a10 b2 + a11 b1) + 242 * (a8 b10 + a9 b9 + a10 b8 + a11 b7)
	d6 := e.fp.Eval([][]*baseEl{{&a.A0, b[5]}, {&a.A2, b[4]}, {&a.A3, b[3]}, {&a.A4, b[2]}, {&a.A5, b[1]}, {&a.A6, b[0]}, {&a.A2, b[9]}, {&a.A3, b[8]}, {&a.A4, b[7]}, {&a.A5, b[6]}, {&a.A6, b[5]}, {&a.A8, b[4]}, {&a.A9, b[3]}, {&a.A10, b[2]}, {&a.A11, b[1]}, {&a.A8, b[9]}, {&a.A9, b[8]}, {&a.A10, b[7]}, {&a.A11, b[6]}}, []int{1, 1, 1, 1, 1, 1, 18, 18, 18, 18, 18, 18, 18, 18, 18, 242, 242, 242, 242})

	// d7  ==  a0 b7 + a1 b6 + a3 b4 + a4 b3 + a5 b2 + a6 b1 + a7 b0  + 18 * (a3 b10 + a4 b9 + a5 b8 + a6 b7 + a7 b6 + a9 b4 + a10 b3 + a11 b2) + 242 * (a9 b10 + a10 b9 + a11 b8)
	d7 := e.fp.Eval([][]*baseEl{{&a.A0, b[6]}, {&a.A1, b[5]}, {&a.A3, b[4]}, {&a.A4, b[3]}, {&a.A5, b[2]}, {&a.A6, b[1]}, {&a.A7, b[0]}, {&a.A3, b[9]}, {&a.A4, b[8]}, {&a.A5, b[7]}, {&a.A6, b[6]}, {&a.A7, b[5]}, {&a.A9, b[4]}, {&a.A10, b[3]}, {&a.A11, b[2]}, {&a.A9, b[9]}, {&a.A10, b[8]}, {&a.A11, b[7]}}, []int{1, 1, 1, 1, 1, 1, 1, 18, 18, 18, 18, 18, 18, 18, 18, 242, 242, 242})

	// d8  =  a0 b8 + a1 b7 + a2 b6 + a4 b4 + a5 b3 + a6 b2 + a7 b1 + a8 b0  + 18 * (a4 b10 + a5 b9 + a6 b8 + a7 b7 + a8 b6 + a10 b4 + a11 b3) + 242 * (a10 b10 + a11 b9)
	d8 := e.fp.Eval([][]*baseEl{{&a.A0, b[7]}, {&a.A1, b[6]}, {&a.A2, b[5]}, {&a.A4, b[4]}, {&a.A5, b[3]}, {&a.A6, b[2]}, {&a.A7, b[1]}, {&a.A8, b[0]}, {&a.A4, b[9]}, {&a.A5, b[8]}, {&a.A6, b[7]}, {&a.A7, b[6]}, {&a.A8, b[5]}, {&a.A10, b[4]}, {&a.A11, b[3]}, {&a.A10, b[9]}, {&a.A11, b[8]}}, []int{1, 1, 1, 1, 1, 1, 1, 1, 18, 18, 18, 18, 18, 18, 18, 242, 242})

	// d9  =  a0 b9 + a1 b8 + a2 b7 + a3 b6 + a5 b4 + a6 b3 + a7 b2 + a8 b1 + a9 b0  + 18 * (a5 b10 + a6 b9 + a7 b8 + a8 b7 + a9 b6 + a11 b4) + 242 * a11 b10
	d9 := e.fp.Eval([][]*baseEl{{&a.A0, b[8]}, {&a.A1, b[7]}, {&a.A2, b[6]}, {&a.A3, b[5]}, {&a.A5, b[4]}, {&a.A6, b[3]}, {&a.A7, b[2]}, {&a.A8, b[1]}, {&a.A9, b[0]}, {&a.A5, b[9]}, {&a.A6, b[8]}, {&a.A7, b[7]}, {&a.A8, b[6]}, {&a.A9, b[5]}, {&a.A11, b[4]}, {&a.A11, b[9]}}, []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 18, 18, 18, 18, 18, 18, 242})

	// d10 =  a0 b10 + a1 b9 + a2 b8 + a3 b7 + a4 b6 + a6 b4 + a7 b3 + a8 b2 + a9 b1 + a10 b0 + 18 * (a6 b10 + a7 b9 + a8 b8 + a9 b7 + a10 b6)
	d10 := e.fp.Eval([][]*baseEl{{&a.A0, b[9]}, {&a.A1, b[8]}, {&a.A2, b[7]}, {&a.A3, b[6]}, {&a.A4, b[5]}, {&a.A6, b[4]}, {&a.A7, b[3]}, {&a.A8, b[2]}, {&a.A9, b[1]}, {&a.A10, b[0]}, {&a.A6, b[9]}, {&a.A7, b[8]}, {&a.A8, b[7]}, {&a.A9, b[6]}, {&a.A10, b[5]}}, []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 18, 18, 18, 18, 18})

	// d11 =  a1 b10 + a2 b9 + a3 b8 + a4 b7 + a5 b6 + a7 b4 + a8 b3 + a9 b2 + a10 b1 + a11 b0 + 18 * (a7 b10 + a8 b9 + a9 b8 + a10 b7 + a11 b6)
	d11 := e.fp.Eval([][]*baseEl{{&a.A1, b[9]}, {&a.A2, b[8]}, {&a.A3, b[7]}, {&a.A4, b[6]}, {&a.A5, b[5]}, {&a.A7, b[4]}, {&a.A8, b[3]}, {&a.A9, b[2]}, {&a.A10, b[1]}, {&a.A11, b[0]}, {&a.A7, b[9]}, {&a.A8, b[8]}, {&a.A9, b[7]}, {&a.A10, b[6]}, {&a.A11, b[5]}}, []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 18, 18, 18, 18, 18})

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
