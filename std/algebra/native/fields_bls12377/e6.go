// Copyright 2020-2024 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package fields_bls12377

import (
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/frontend"
)

type E6 struct {
	A0, A1, A2, A3, A4, A5 frontend.Variable
}

func (e *E6) SetZero() *E6 {
	e.A0 = 0
	e.A1 = 0
	e.A2 = 0
	e.A3 = 0
	e.A4 = 0
	e.A5 = 0
	return e
}

func (e *E6) SetOne() *E6 {
	e.A0 = 1
	e.A1 = 0
	e.A2 = 0
	e.A3 = 0
	e.A4 = 0
	e.A5 = 0
	return e
}

func (e *E6) assign(e1 []frontend.Variable) {
	e.A0 = e1[0]
	e.A1 = e1[1]
	e.A2 = e1[2]
	e.A3 = e1[3]
	e.A4 = e1[4]
	e.A5 = e1[5]
}

func (e *E6) Double(api frontend.API, e1 E6) *E6 {
	e.A0 = api.Mul(e1.A0, 2)
	e.A1 = api.Mul(e1.A1, 2)
	e.A2 = api.Mul(e1.A2, 2)
	e.A3 = api.Mul(e1.A3, 2)
	e.A4 = api.Mul(e1.A4, 2)
	e.A5 = api.Mul(e1.A5, 2)
	return e
}

// Add creates a fp6elmt from fp elmts
func (e *E6) Add(api frontend.API, e1, e2 E6) *E6 {

	e.A0 = api.Add(e1.A0, e2.A0)
	e.A1 = api.Add(e1.A1, e2.A1)
	e.A2 = api.Add(e1.A2, e2.A2)
	e.A3 = api.Add(e1.A3, e2.A3)
	e.A4 = api.Add(e1.A4, e2.A4)
	e.A5 = api.Add(e1.A5, e2.A5)

	return e
}

// NewFp6Zero creates a new
func NewFp6Zero(api frontend.API) *E6 {
	return &E6{
		A0: 0,
		A1: 0,
		A2: 0,
		A3: 0,
		A4: 0,
		A5: 0,
	}
}

// Sub creates a fp6elmt from fp elmts
func (e *E6) Sub(api frontend.API, e1, e2 E6) *E6 {

	e.A0 = api.Sub(e1.A0, e2.A0)
	e.A1 = api.Sub(e1.A1, e2.A1)
	e.A2 = api.Sub(e1.A2, e2.A2)
	e.A3 = api.Sub(e1.A3, e2.A3)
	e.A4 = api.Sub(e1.A4, e2.A4)
	e.A5 = api.Sub(e1.A5, e2.A5)

	return e
}

// Neg negates an Fp6 elmt
func (e *E6) Neg(api frontend.API, e1 E6) *E6 {
	e.A0 = api.Sub(0, e1.A0)
	e.A1 = api.Sub(0, e1.A1)
	e.A2 = api.Sub(0, e1.A2)
	e.A3 = api.Sub(0, e1.A3)
	e.A4 = api.Sub(0, e1.A4)
	e.A5 = api.Sub(0, e1.A5)
	return e
}

// Mul multiplies two E6 elmts
func (e *E6) Mul(api frontend.API, e1, e2 E6) *E6 {
	return e.mulToomCook6(api, e1, e2)
}

func (e *E6) mulToomCook6(api frontend.API, x, y E6) *E6 {
	// Toom-Cook 6-way multiplication:
	//
	// Ref.: https://eprint.iacr.org/2006/471.pdf
	// ⚠️  but has sign errors in c1 and coefficient errors in c3 and c4.
	//
	// We first represent a, b as the polynomials:
	// 	x(X) = a0 + a1*X + a2*X^2 + a3*X^3 + a4*X^4 + a5*X^5
	// 	y(X) = b0 + b1*X + b2*X^2 + b3*X^3 + b4*X^4 + b5*X^5
	//
	// and we compute the interpolation points
	// vi = a(Xi)*b(Xi) at Xi={0, ±1, ±2, ±3, ±4, 5, ∞}:
	//
	//     v0 = x(0)y(0)   = x0y0
	//     v1 = x(1)y(1)   = (x0 + x1 + x2 + x3 + x4 + x5)(y0 + y1 + y2 + y3 + y4 + y5)
	//     v2 = x(-1)y(-1) = (x0 - x1 + x2 - x3 + x4 - x5)(y0 - y1 + y2 - y3 + y4 - y5)
	//     v3 = x(2)y(2)   = (x0 + 2x1 + 4x2 + 8x3 + 16x4 + 32x5)(y0 + 2y1 + 4y2 + 8y3 + 16y4 + 32y5)
	//     v4 = x(-2)y(-2) = (x0 - 2x1 + 4x2 - 8x3 + 16x4 - 32x5)(y0 - 2y1 + 4y2 - 8y3 + 16y4 - 32y5)
	//     v5 = x(3)y(3)   = (x0 + 3x1 + 9x2 + 27x3 + 81x4 + 243x5)(y0 + 3y1 + 9y2 + 27y3 + 81y4 + 243y5)
	//     v6 = x(-3)y(-3) = (x0 - 3x1 + 9x2 - 27x3 + 81x4 - 243x5)(y0 - 3y1 + 9y2 - 27y3 + 81y4 - 243y5)
	//     v7 = x(4)y(4)   = (x0 + 4x1 + 16x2 + 64x3 + 256x4 + 1024x5)(y0 + 4y1 + 16y2 + 64y3 + 256y4 + 1024y5)
	//     v8 = x(-4)y(-4) = (x0 - 4x1 + 16x2 - 64x3 + 256x4 - 1024x5)(y0 - 4y1 + 16y2 - 64y3 + 256y4 - 1024y5)
	//     v9 = x(5)y(5)   = (x0 + 5x1 + 25x2 + 125x3 + 625x4 + 3125x5)(y0 + 5y1 + 25y2 + 125y3 + 625y4 + 3125y5)
	// 	   v10 = x(∞)y(∞)  = x5y5

	v0 := api.Mul(x.A0, y.A0)

	t1 := api.Add(x.A0, x.A2)
	t1 = api.Add(t1, x.A4)
	s1 := api.Add(y.A0, y.A2)
	s1 = api.Add(s1, y.A4)
	t2 := api.Add(x.A1, x.A3)
	t2 = api.Add(t2, x.A5)
	s2 := api.Add(y.A1, y.A3)
	s2 = api.Add(s2, y.A5)

	v1 := api.Add(t1, t2)
	s3 := api.Add(s1, s2)
	v1 = api.Mul(v1, s3)

	v2 := api.Sub(t1, t2)
	s3 = api.Sub(s1, s2)
	v2 = api.Mul(v2, s3)

	t1 = api.Mul(x.A2, 4)
	t1 = api.Add(x.A0, t1)
	t := api.Mul(x.A4, 16)
	t1 = api.Add(t1, t)
	t2 = api.Mul(x.A1, 2)
	t = api.Mul(x.A3, 8)
	t2 = api.Add(t2, t)
	t = api.Mul(x.A5, 32)
	t2 = api.Add(t2, t)
	s1 = api.Mul(y.A2, 4)
	s1 = api.Add(y.A0, s1)
	s := api.Mul(y.A4, 16)
	s1 = api.Add(s1, s)
	s2 = api.Mul(y.A1, 2)
	s = api.Mul(y.A3, 8)
	s2 = api.Add(s2, s)
	s = api.Mul(y.A5, 32)
	s2 = api.Add(s2, s)

	v3 := api.Add(t1, t2)
	s3 = api.Add(s1, s2)
	v3 = api.Mul(v3, s3)

	v4 := api.Sub(t1, t2)
	s3 = api.Sub(s1, s2)
	v4 = api.Mul(v4, s3)

	t1 = api.Mul(x.A2, 9)
	t1 = api.Add(x.A0, t1)
	t = api.Mul(x.A4, 81)
	t1 = api.Add(t1, t)
	t2 = api.Mul(x.A1, 3)
	t = api.Mul(x.A3, 27)
	t2 = api.Add(t2, t)
	t = api.Mul(x.A5, 243)
	t2 = api.Add(t2, t)
	s1 = api.Mul(y.A2, 9)
	s1 = api.Add(y.A0, s1)
	s = api.Mul(y.A4, 81)
	s1 = api.Add(s1, s)
	s2 = api.Mul(y.A1, 3)
	s = api.Mul(y.A3, 27)
	s2 = api.Add(s2, s)
	s = api.Mul(y.A5, 243)
	s2 = api.Add(s2, s)

	v5 := api.Add(t1, t2)
	s3 = api.Add(s1, s2)
	v5 = api.Mul(v5, s3)

	v6 := api.Sub(t1, t2)
	s3 = api.Sub(s1, s2)
	v6 = api.Mul(v6, s3)

	t1 = api.Mul(x.A2, 16)
	t1 = api.Add(x.A0, t1)
	t = api.Mul(x.A4, 256)
	t1 = api.Add(t1, t)
	t2 = api.Mul(x.A1, 4)
	t = api.Mul(x.A3, 64)
	t2 = api.Add(t2, t)
	t = api.Mul(x.A5, 1024)
	t2 = api.Add(t2, t)
	s1 = api.Mul(y.A2, 16)
	s1 = api.Add(y.A0, s1)
	s = api.Mul(y.A4, 256)
	s1 = api.Add(s1, s)
	s2 = api.Mul(y.A1, 4)
	s = api.Mul(y.A3, 64)
	s2 = api.Add(s2, s)
	s = api.Mul(y.A5, 1024)
	s2 = api.Add(s2, s)

	v7 := api.Add(t1, t2)
	s3 = api.Add(s1, s2)
	v7 = api.Mul(v7, s3)

	v8 := api.Sub(t1, t2)
	s3 = api.Sub(s1, s2)
	v8 = api.Mul(v8, s3)

	t1 = api.Mul(x.A2, 25)
	t1 = api.Add(x.A0, t1)
	t = api.Mul(x.A4, 625)
	t1 = api.Add(t1, t)
	t2 = api.Mul(x.A1, 5)
	t = api.Mul(x.A3, 125)
	t2 = api.Add(t2, t)
	t = api.Mul(x.A5, 3125)
	t2 = api.Add(t2, t)
	s1 = api.Mul(y.A2, 25)
	s1 = api.Add(y.A0, s1)
	s = api.Mul(y.A4, 625)
	s1 = api.Add(s1, s)
	s2 = api.Mul(y.A1, 5)
	s = api.Mul(y.A3, 125)
	s2 = api.Add(s2, s)
	s = api.Mul(y.A5, 3125)
	s2 = api.Add(s2, s)
	v9 := api.Add(t1, t2)
	s3 = api.Add(s1, s2)
	v9 = api.Mul(v9, s3)

	v10 := api.Mul(x.A5, y.A5)

	// recording common sub-expressions
	v12 := api.Add(v1, v2)
	v34 := api.Add(v3, v4)
	v56 := api.Add(v5, v6)
	v78 := api.Add(v7, v8)

	//	Then we compute the product  362880 * x * y to with β=-5:
	//
	// 		c0 = 457380 v0 + 32760(v3 + v4) + 630(v7 + v8)
	// 		- (73080(v1 + v2) + 7560(v5 + v6) + 495331200 v10)
	c0 := api.Mul(v0, 457380)
	s1 = api.Mul(v34, 32760)
	c0 = api.Add(c0, s1)
	s1 = api.Mul(v78, 630)
	c0 = api.Add(c0, s1)
	s1 = api.Mul(v12, 73080)
	s2 = api.Mul(v56, 7560)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v10, 495331200)
	s1 = api.Add(s1, s2)
	c0 = api.Sub(c0, s1)
	//  	c1 = 750 v8 + 726 v9 + 48960 v4 + 41040 v5 + 384300 v1
	//  	− (91476 v0 + 231840 v2 + 136080 v3 + 8370 v6 + 8010 v7 + 1317254400 v10)
	c1 := api.Mul(v8, 750)
	s1 = api.Mul(v9, 726)
	c1 = api.Add(c1, s1)
	s1 = api.Mul(v4, 48960)
	c1 = api.Add(c1, s1)
	s1 = api.Mul(v5, 41040)
	c1 = api.Add(c1, s1)
	s1 = api.Mul(v1, 384300)
	c1 = api.Add(c1, s1)
	s1 = api.Mul(v0, 91476)
	s2 = api.Mul(v2, 231840)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v3, 136080)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v6, 8370)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v7, 8010)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v10, 1317254400)
	s1 = api.Add(s1, s2)
	c1 = api.Sub(c1, s1)
	// 		c2 = 4968(v5 + v6) + 292824(v1 + v2) + 263450880 v10
	// 		− (519750 v0 + 369(v7 + v8) + 37548(v3 + v4)
	c2 := api.Mul(v56, 4968)
	s1 = api.Mul(v12, 292824)
	c2 = api.Add(c2, s1)
	s1 = api.Mul(v10, 263450880)
	c2 = api.Add(c2, s1)
	s1 = api.Mul(v0, 519750)
	s2 = api.Mul(v78, 369)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v34, 37548)
	s1 = api.Add(s1, s2)
	c2 = api.Sub(c2, s1)
	// 		c3 = 103950 v0 + 1496880000 v10 + 10719 v6 + 9189 v7 + 53676 v2 + 154476 v3
	// 		- (55476 v4 + 47844* v5 + 939 v8 + 825* v9 + 226926* v1)
	c3 := api.Mul(v0, 103950)
	s1 = api.Mul(v10, 1496880000)
	c3 = api.Add(c3, s1)
	s1 = api.Mul(v6, 10719)
	c3 = api.Add(c3, s1)
	s1 = api.Mul(v7, 9189)
	c3 = api.Add(c3, s1)
	s1 = api.Mul(v2, 53676)
	c3 = api.Add(c3, s1)
	s1 = api.Mul(v3, 154476)
	c3 = api.Add(c3, s1)
	s1 = api.Mul(v4, 55476)
	s2 = api.Mul(v5, 47844)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v8, 939)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v9, 825)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v1, 226926)
	s1 = api.Add(s1, s2)
	c3 = api.Sub(c3, s1)
	// 		c4 = 171990 v0 + 42588(v3 + v4) + 441* (v7 + v8)
	// 		− (299376000 v10 + 122976(v1 + v2) + 6048(v5 + v6)
	c4 := api.Mul(v0, 171990)
	s1 = api.Mul(v34, 42588)
	c4 = api.Add(c4, s1)
	s1 = api.Mul(v78, 441)
	c4 = api.Add(c4, s1)
	s1 = api.Mul(v10, 299376000)
	s2 = api.Mul(v12, 122976)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v56, 6048)
	s1 = api.Add(s1, s2)
	c4 = api.Sub(c4, s1)
	// 		c5 = 231 v8 + 273 v9 + 3276 v4 + 8316 v2 + 14364 v5 + 49014 v1
	// 		- (34398 v0 + 36036 v3 + 2079 v6 + 2961 v7 + 495331200 v10)
	c5 := api.Mul(v8, 231)
	s1 = api.Mul(v9, 273)
	c5 = api.Add(c5, s1)
	s1 = api.Mul(v4, 3276)
	c5 = api.Add(c5, s1)
	s1 = api.Mul(v2, 8316)
	c5 = api.Add(c5, s1)
	s1 = api.Mul(v5, 14364)
	c5 = api.Add(c5, s1)
	s1 = api.Mul(v1, 49014)
	c5 = api.Add(c5, s1)
	s1 = api.Mul(v0, 34398)
	s2 = api.Mul(v3, 36036)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v6, 2079)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v7, 2961)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v10, 495331200)
	s1 = api.Add(s1, s2)
	c5 = api.Sub(c5, s1)

	inv := newInt("88136795313121664371514491190400409890802603261703408927951580208201018931512614951655032274564118329218122870754")
	e.A0 = api.Mul(c0, inv)
	e.A1 = api.Mul(c1, inv)
	e.A2 = api.Mul(c2, inv)
	e.A3 = api.Mul(c3, inv)
	e.A4 = api.Mul(c4, inv)
	e.A5 = api.Mul(c5, inv)
	return e
}

func (e *E6) Square(api frontend.API, x E6) *E6 {
	// vi = a(Xi)*b(Xi) at Xi={0, ±1, ±2, ±3, ±4, 5, ∞}:
	//     v0 = x(0)y(0)   = x0y0
	//     v1 = x(1)y(1)   = (x0 + x1 + x2 + x3 + x4 + x5)^2
	//     v2 = x(-1)y(-1) = (x0 - x1 + x2 - x3 + x4 - x5)^2
	//     v3 = x(2)y(2)   = (x0 + 2x1 + 4x2 + 8x3 + 16x4 + 32x5)^2
	//     v4 = x(-2)y(-2) = (x0 - 2x1 + 4x2 - 8x3 + 16x4 - 32x5)^2
	//     v5 = x(3)y(3)   = (x0 + 3x1 + 9x2 + 27x3 + 81x4 + 243x5)^2
	//     v6 = x(-3)y(-3) = (x0 - 3x1 + 9x2 - 27x3 + 81x4 - 243x5)^2
	//     v7 = x(4)y(4)   = (x0 + 4x1 + 16x2 + 64x3 + 256x4 + 1024x5)^2
	//     v8 = x(-4)y(-4) = (x0 - 4x1 + 16x2 - 64x3 + 256x4 - 1024x5)^2
	//     v9 = x(5)y(5)   = (x0 + 5x1 + 25x2 + 125x3 + 625x4 + 3125x5)^2
	// 	   v10 = x(∞)y(∞)  = x5y5
	v0 := api.Mul(x.A0, x.A0)
	t1 := api.Add(x.A0, x.A2)
	t1 = api.Add(t1, x.A4)
	t2 := api.Add(x.A1, x.A3)
	t2 = api.Add(t2, x.A5)

	v1 := api.Add(t1, t2)
	v1 = api.Mul(v1, v1)

	v2 := api.Sub(t1, t2)
	v2 = api.Mul(v2, v2)

	t1 = api.Mul(x.A2, 4)
	t1 = api.Add(x.A0, t1)
	t := api.Mul(x.A4, 16)
	t1 = api.Add(t1, t)
	t2 = api.Mul(x.A1, 2)
	t = api.Mul(x.A3, 8)
	t2 = api.Add(t2, t)
	t = api.Mul(x.A5, 32)
	t2 = api.Add(t2, t)

	v3 := api.Add(t1, t2)
	v3 = api.Mul(v3, v3)

	v4 := api.Sub(t1, t2)
	v4 = api.Mul(v4, v4)

	t1 = api.Mul(x.A2, 9)
	t1 = api.Add(x.A0, t1)
	t = api.Mul(x.A4, 81)
	t1 = api.Add(t1, t)
	t2 = api.Mul(x.A1, 3)
	t = api.Mul(x.A3, 27)
	t2 = api.Add(t2, t)
	t = api.Mul(x.A5, 243)
	t2 = api.Add(t2, t)

	v5 := api.Add(t1, t2)
	v5 = api.Mul(v5, v5)

	v6 := api.Sub(t1, t2)
	v6 = api.Mul(v6, v6)

	t1 = api.Mul(x.A2, 16)
	t1 = api.Add(x.A0, t1)
	t = api.Mul(x.A4, 256)
	t1 = api.Add(t1, t)
	t2 = api.Mul(x.A1, 4)
	t = api.Mul(x.A3, 64)
	t2 = api.Add(t2, t)
	t = api.Mul(x.A5, 1024)
	t2 = api.Add(t2, t)

	v7 := api.Add(t1, t2)
	v7 = api.Mul(v7, v7)

	v8 := api.Sub(t1, t2)
	v8 = api.Mul(v8, v8)

	t1 = api.Mul(x.A2, 25)
	t1 = api.Add(x.A0, t1)
	t = api.Mul(x.A4, 625)
	t1 = api.Add(t1, t)
	t2 = api.Mul(x.A1, 5)
	t = api.Mul(x.A3, 125)
	t2 = api.Add(t2, t)
	t = api.Mul(x.A5, 3125)
	t2 = api.Add(t2, t)

	v9 := api.Add(t1, t2)
	v9 = api.Mul(v9, v9)

	v10 := api.Mul(x.A5, x.A5)

	// recording common sub-expressions
	v12 := api.Add(v1, v2)
	v34 := api.Add(v3, v4)
	v56 := api.Add(v5, v6)
	v78 := api.Add(v7, v8)

	//	Then we compute the product  362880 * x * y to with β=-5:
	//
	// 		c0 = 457380 v0 + 32760(v3 + v4) + 630(v7 + v8)
	// 		- (73080(v1 + v2) + 7560(v5 + v6) + 495331200 v10)
	c0 := api.Mul(v0, 457380)
	s1 := api.Mul(v34, 32760)
	c0 = api.Add(c0, s1)
	s1 = api.Mul(v78, 630)
	c0 = api.Add(c0, s1)
	s1 = api.Mul(v12, 73080)
	s2 := api.Mul(v56, 7560)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v10, 495331200)
	s1 = api.Add(s1, s2)
	c0 = api.Sub(c0, s1)
	//  	c1 = 750 v8 + 726 v9 + 48960 v4 + 41040 v5 + 384300 v1
	//  	− (91476 v0 + 231840 v2 + 136080 v3 + 8370 v6 + 8010 v7 + 1317254400 v10)
	c1 := api.Mul(v8, 750)
	s1 = api.Mul(v9, 726)
	c1 = api.Add(c1, s1)
	s1 = api.Mul(v4, 48960)
	c1 = api.Add(c1, s1)
	s1 = api.Mul(v5, 41040)
	c1 = api.Add(c1, s1)
	s1 = api.Mul(v1, 384300)
	c1 = api.Add(c1, s1)
	s1 = api.Mul(v0, 91476)
	s2 = api.Mul(v2, 231840)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v3, 136080)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v6, 8370)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v7, 8010)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v10, 1317254400)
	s1 = api.Add(s1, s2)
	c1 = api.Sub(c1, s1)
	// 		c2 = 4968(v5 + v6) + 292824(v1 + v2) + 263450880 v10
	// 		− (519750 v0 + 369(v7 + v8) + 37548(v3 + v4)
	c2 := api.Mul(v56, 4968)
	s1 = api.Mul(v12, 292824)
	c2 = api.Add(c2, s1)
	s1 = api.Mul(v10, 263450880)
	c2 = api.Add(c2, s1)
	s1 = api.Mul(v0, 519750)
	s2 = api.Mul(v78, 369)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v34, 37548)
	s1 = api.Add(s1, s2)
	c2 = api.Sub(c2, s1)
	// 		c3 = 103950 v0 + 1496880000 v10 + 10719 v6 + 9189 v7 + 53676 v2 + 154476 v3
	// 		- (55476 v4 + 47844* v5 + 939 v8 + 825* v9 + 226926* v1)
	c3 := api.Mul(v0, 103950)
	s1 = api.Mul(v10, 1496880000)
	c3 = api.Add(c3, s1)
	s1 = api.Mul(v6, 10719)
	c3 = api.Add(c3, s1)
	s1 = api.Mul(v7, 9189)
	c3 = api.Add(c3, s1)
	s1 = api.Mul(v2, 53676)
	c3 = api.Add(c3, s1)
	s1 = api.Mul(v3, 154476)
	c3 = api.Add(c3, s1)
	s1 = api.Mul(v4, 55476)
	s2 = api.Mul(v5, 47844)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v8, 939)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v9, 825)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v1, 226926)
	s1 = api.Add(s1, s2)
	c3 = api.Sub(c3, s1)
	// 		c4 = 171990 v0 + 42588(v3 + v4) + 441* (v7 + v8)
	// 		− (299376000 v10 + 122976(v1 + v2) + 6048(v5 + v6)
	c4 := api.Mul(v0, 171990)
	s1 = api.Mul(v34, 42588)
	c4 = api.Add(c4, s1)
	s1 = api.Mul(v78, 441)
	c4 = api.Add(c4, s1)
	s1 = api.Mul(v10, 299376000)
	s2 = api.Mul(v12, 122976)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v56, 6048)
	s1 = api.Add(s1, s2)
	c4 = api.Sub(c4, s1)
	// 		c5 = 231 v8 + 273 v9 + 3276 v4 + 8316 v2 + 14364 v5 + 49014 v1
	// 		- (34398 v0 + 36036 v3 + 2079 v6 + 2961 v7 + 495331200 v10)
	c5 := api.Mul(v8, 231)
	s1 = api.Mul(v9, 273)
	c5 = api.Add(c5, s1)
	s1 = api.Mul(v4, 3276)
	c5 = api.Add(c5, s1)
	s1 = api.Mul(v2, 8316)
	c5 = api.Add(c5, s1)
	s1 = api.Mul(v5, 14364)
	c5 = api.Add(c5, s1)
	s1 = api.Mul(v1, 49014)
	c5 = api.Add(c5, s1)
	s1 = api.Mul(v0, 34398)
	s2 = api.Mul(v3, 36036)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v6, 2079)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v7, 2961)
	s1 = api.Add(s1, s2)
	s2 = api.Mul(v10, 495331200)
	s1 = api.Add(s1, s2)
	c5 = api.Sub(c5, s1)

	inv := newInt("88136795313121664371514491190400409890802603261703408927951580208201018931512614951655032274564118329218122870754")
	e.A0 = api.Mul(c0, inv)
	e.A1 = api.Mul(c1, inv)
	e.A2 = api.Mul(c2, inv)
	e.A3 = api.Mul(c3, inv)
	e.A4 = api.Mul(c4, inv)
	e.A5 = api.Mul(c5, inv)
	return e
}

// DivUnchecked e6 elmts
func (e *E6) DivUnchecked(api frontend.API, e1, e2 E6) *E6 {

	res, err := api.NewHint(divE6Hint, 6, e1.A0, e1.A1, e1.A2, e1.A3, e1.A4, e1.A5, e2.A0, e2.A1, e2.A2, e2.A3, e2.A4, e2.A5)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	var e3, one E6
	e3.assign(res[:6])
	one.SetOne()

	// e1 == e3 * e2
	e3.Mul(api, e3, e2)
	e3.AssertIsEqual(api, e1)

	e.assign(res[:6])

	return e
}

// Inverse e6 elmts
func (e *E6) Inverse(api frontend.API, e1 E6) *E6 {

	res, err := api.NewHint(inverseE6Hint, 6, e1.A0, e1.A1, e1.A2, e1.A3, e1.A4, e1.A5)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	var e3, one E6
	e3.assign(res[:6])
	one.SetOne()

	// 1 == e3 * e1
	e3.Mul(api, e3, e1)
	e3.AssertIsEqual(api, one)

	e.assign(res[:6])

	return e
}

func (e *E6) Mul0By01(api frontend.API, a0, b0, b1 E2) *E6 {

	var t0, c1 E2

	t0.Mul(api, a0, b0)
	c1.Add(api, b0, b1)
	c1.Mul(api, c1, a0).Sub(api, c1, t0)

	e.A0 = t0.A0
	e.A1 = c1.A0
	e.A2 = 0
	e.A3 = t0.A1
	e.A4 = c1.A1
	e.A5 = 0

	return e
}

// MulByNonResidue multiplies e by the imaginary elmt of Fp6 (noted a+bV+cV where V**3 in F²)
func (e *E6) MulByNonResidue(api frontend.API, e1 E6) *E6 {
	B0 := E2{}
	B0.MulByNonResidue(api, E2{A0: e1.A2, A1: e1.A5})
	e.A1 = e1.A0
	e.A4 = e1.A3
	e.A2 = e1.A1
	e.A5 = e1.A4
	e.A0 = B0.A0
	e.A3 = B0.A1
	return e
}

// MulBy01 multiplication by sparse element (c0,c1,0)
func (e *E6) MulBy01(api frontend.API, c0, c1 E2) *E6 {

	var a, b, tmp, t0, t1, t2 E2
	B0 := E2{A0: e.A0, A1: e.A3}
	B1 := E2{A0: e.A1, A1: e.A4}
	B2 := E2{A0: e.A2, A1: e.A5}
	a.Mul(api, B0, c0)
	b.Mul(api, B1, c1)

	tmp.Add(api, B1, B2)
	t0.Mul(api, c1, tmp)
	t0.Sub(api, t0, b)
	t0.MulByNonResidue(api, t0)
	t0.Add(api, t0, a)

	// for t2, schoolbook is faster than karatsuba
	// c2 = a0b2 + a1b1 + a2b0,
	// c2 = a2b0 + b ∵ b2 = 0, b = a1b1
	t2.Mul(api, B2, c0)
	t2.Add(api, t2, b)

	t1.Add(api, c0, c1)
	tmp.Add(api, B0, B1)
	t1.Mul(api, t1, tmp)
	t1.Sub(api, t1, a)
	t1.Sub(api, t1, b)

	e.A0 = t0.A0
	e.A1 = t1.A0
	e.A2 = t2.A0
	e.A3 = t0.A1
	e.A4 = t1.A1
	e.A5 = t2.A1

	return e
}

func Mul01By01(api frontend.API, c0, c1, d0, d1 E2) *E6 {
	var a, b, t1, tmp E2

	a.Mul(api, d0, c0)
	b.Mul(api, d1, c1)
	t1.Add(api, c0, c1)
	tmp.Add(api, d0, d1)
	t1.Mul(api, t1, tmp)
	t1.Sub(api, t1, a)
	t1.Sub(api, t1, b)

	return &E6{
		A0: a.A0,
		A1: t1.A0,
		A2: b.A0,
		A3: a.A1,
		A4: t1.A1,
		A5: b.A1,
	}
}

// Select sets e to r1 if b=1, r2 otherwise
func (e *E6) Select(api frontend.API, b frontend.Variable, r1, r2 E6) *E6 {

	e.A0 = api.Select(b, r1.A0, r2.A0)
	e.A1 = api.Select(b, r1.A1, r2.A1)
	e.A2 = api.Select(b, r1.A2, r2.A2)
	e.A3 = api.Select(b, r1.A3, r2.A3)
	e.A4 = api.Select(b, r1.A4, r2.A4)
	e.A5 = api.Select(b, r1.A5, r2.A5)

	return e
}

// Lookup2 implements two-bit lookup. It returns:
//   - r1 if b1=0 and b2=0,
//   - r2 if b1=0 and b2=1,
//   - r3 if b1=1 and b2=0,
//   - r3 if b1=1 and b2=1.
func (e *E6) Lookup2(api frontend.API, b1, b2 frontend.Variable, r1, r2, r3, r4 E6) *E6 {

	e.A0 = api.Lookup2(b1, b2, r1.A0, r2.A0, r3.A0, r4.A0)
	e.A1 = api.Lookup2(b1, b2, r1.A1, r2.A1, r3.A1, r4.A1)
	e.A2 = api.Lookup2(b1, b2, r1.A2, r2.A2, r3.A2, r4.A2)
	e.A3 = api.Lookup2(b1, b2, r1.A3, r2.A3, r3.A3, r4.A3)
	e.A4 = api.Lookup2(b1, b2, r1.A4, r2.A4, r3.A4, r4.A4)
	e.A5 = api.Lookup2(b1, b2, r1.A5, r2.A5, r3.A5, r4.A5)

	return e
}

// AssertIsEqual constraint self to be equal to other into the given constraint system
func (e *E6) AssertIsEqual(api frontend.API, other E6) {
	api.AssertIsEqual(e.A0, other.A0)
	api.AssertIsEqual(e.A1, other.A1)
	api.AssertIsEqual(e.A2, other.A2)
	api.AssertIsEqual(e.A3, other.A3)
	api.AssertIsEqual(e.A4, other.A4)
	api.AssertIsEqual(e.A5, other.A5)
}

// Assign a value to self (witness assignment)
func (e *E6) Assign(a *bls12377.E6) {
	// gnark-crypto uses a cubic over quadratic sextic extension of Fp.
	// The two towers are isomorphic and the coefficients are permuted as follows:
	//
	//     A0  =  a00
	//     A1  =  a10
	//     A2  =  a20
	//     A3  =  a01
	//     A4  =  a11
	//     A5  =  a21
	e.A0 = (fr.Element)(a.B0.A0)
	e.A1 = (fr.Element)(a.B1.A0)
	e.A2 = (fr.Element)(a.B2.A0)
	e.A3 = (fr.Element)(a.B0.A1)
	e.A4 = (fr.Element)(a.B1.A1)
	e.A5 = (fr.Element)(a.B2.A1)
}

func FromTower(a [6]frontend.Variable) *E6 {
	// gnark-crypto uses a cubic over quadratic sextic extension of Fp.
	// The two towers are isomorphic and the coefficients are permuted as follows:
	//
	//     A0  =  a00
	//     A1  =  a10
	//     A2  =  a20
	//     A3  =  a01
	//     A4  =  a11
	//     A5  =  a21
	var e E6
	e.A0 = a[0]
	e.A1 = a[2]
	e.A2 = a[4]
	e.A3 = a[1]
	e.A4 = a[3]
	e.A5 = a[5]
	return &e
}

func ToTower(e E6) [6]frontend.Variable {
	// gnark-crypto uses a cubic over quadratic sextic extension of Fp.
	// The two towers are isomorphic and the coefficients are permuted as follows:
	//
	//     A0  =  a00
	//     A1  =  a10
	//     A2  =  a20
	//     A3  =  a01
	//     A4  =  a11
	//     A5  =  a21
	var a [6]frontend.Variable
	a[0] = e.A0
	a[2] = e.A1
	a[4] = e.A2
	a[1] = e.A3
	a[3] = e.A4
	a[5] = e.A5
	return a
}
