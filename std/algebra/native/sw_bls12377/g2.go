// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package sw_bls12377

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/native/fields_bls12377"
)

type g2AffP struct {
	X, Y fields_bls12377.E2
}

// G2Affine point in affine coords
type G2Affine struct {
	P     g2AffP
	Lines *lineEvaluations
}

// Neg outputs -p
func (p *g2AffP) Neg(api frontend.API, p1 g2AffP) *g2AffP {
	p.Y.Neg(api, p1.Y)
	p.X = p1.X
	return p
}

// AddAssign add p1 to p and return p
func (p *g2AffP) AddAssign(api frontend.API, p1 g2AffP) *g2AffP {

	var n, d, l, xr, yr fields_bls12377.E2

	// compute lambda = (p1.y-p.y)/(p1.x-p.x)
	n.Sub(api, p1.Y, p.Y)
	d.Sub(api, p1.X, p.X)
	l.DivUnchecked(api, n, d)

	// xr =lambda**2-p1.x-p.x
	xr.Square(api, l).
		Sub(api, xr, p1.X).
		Sub(api, xr, p.X)

	// yr = lambda(p.x - xr)-p.y
	yr.Sub(api, p.X, xr).
		Mul(api, l, yr).
		Sub(api, yr, p.Y)

	p.X = xr
	p.Y = yr

	return p
}

func (p *g2AffP) AddUnified(api frontend.API, q g2AffP) *g2AffP {
	// selector1 = 1 when p is (0,0) and 0 otherwise
	selector1 := api.And(p.X.IsZero(api), p.Y.IsZero(api))
	// selector2 = 1 when q is (0,0) and 0 otherwise
	selector2 := api.And(q.X.IsZero(api), q.Y.IsZero(api))

	// λ = ((p.x+q.x)² - p.x*q.x + a)/(p.y + q.y)
	var pxqx, pxplusqx, num, denum, λ fields_bls12377.E2
	pxqx.Mul(api, p.X, q.X)
	pxplusqx.Add(api, p.X, q.X)
	num.Mul(api, pxplusqx, pxplusqx)
	num.Sub(api, num, pxqx)
	denum.Add(api, p.Y, q.Y)
	// if p.y + q.y = 0, assign dummy 1 to denum and continue
	selector3 := denum.IsZero(api)
	one := fields_bls12377.E2{A0: 1, A1: 0}
	denum.Select(api, selector3, one, denum)
	λ.DivUnchecked(api, num, denum)

	// x = λ^2 - p.x - q.x
	var xr, yr fields_bls12377.E2
	xr.Square(api, λ)
	xr.Sub(api, xr, pxplusqx)

	// y = λ(p.x - xr) - p.y
	yr.Sub(api, p.X, xr)
	yr.Mul(api, yr, λ)
	yr.Sub(api, yr, p.Y)
	result := g2AffP{
		X: xr,
		Y: yr,
	}

	// if p=(0,0) return q
	result.Select(api, selector1, q, result)
	// if q=(0,0) return p
	result.Select(api, selector2, *p, result)
	// if p.y + q.y = 0, return (0, 0)
	zero := fields_bls12377.E2{A0: 0, A1: 0}
	result.Select(api, selector3, g2AffP{X: zero, Y: zero}, result)

	p.X = result.X
	p.Y = result.Y

	return p
}

// Select sets p1 if b=1, p2 if b=0, and returns it. b must be boolean constrained
func (p *g2AffP) Select(api frontend.API, b frontend.Variable, p1, p2 g2AffP) *g2AffP {

	p.X.Select(api, b, p1.X, p2.X)
	p.Y.Select(api, b, p1.Y, p2.Y)

	return p
}

// Lookup2 performs a 2-bit lookup between p1, p2, p3, p4 based on bits b0 and b1.
// Returns:
//   - p1 if b0=0 and b1=0,
//   - p2 if b0=1 and b1=0,
//   - p3 if b0=0 and b1=1,
//   - p4 if b0=1 and b1=1.
func (p *g2AffP) Lookup2(api frontend.API, b1, b2 frontend.Variable, p1, p2, p3, p4 g2AffP) *g2AffP {

	p.X.Lookup2(api, b1, b2, p1.X, p2.X, p3.X, p4.X)
	p.Y.Lookup2(api, b1, b2, p1.Y, p2.Y, p3.Y, p4.Y)

	return p
}

// Double compute 2*p1, assign the result to p and return it
// Only for curve with j invariant 0 (a=0).
func (p *g2AffP) Double(api frontend.API, p1 g2AffP) *g2AffP {

	var n, d, l, xr, yr fields_bls12377.E2

	// lambda = 3*p1.x**2/2*p.y
	n.Square(api, p1.X).MulByFp(api, n, 3)
	d.MulByFp(api, p1.Y, 2)
	l.DivUnchecked(api, n, d)

	// xr = lambda**2-2*p1.x
	xr.Square(api, l).
		Sub(api, xr, p1.X).
		Sub(api, xr, p1.X)

	// yr = lambda*(p.x-xr)-p.y
	yr.Sub(api, p1.X, xr).
		Mul(api, l, yr).
		Sub(api, yr, p1.Y)

	p.X = xr
	p.Y = yr

	return p

}

func (p *g2AffP) doubleN(api frontend.API, Q *g2AffP, n int) *g2AffP {
	pn := Q
	for s := 0; s < n; s++ {
		pn.Double(api, *pn)
	}
	return pn
}

func (p *g2AffP) scalarMulBySeed(api frontend.API, Q *g2AffP) *g2AffP {
	var z, t0, t1 g2AffP
	z.Double(api, *Q)
	z.AddAssign(api, *Q)
	z.DoubleAndAdd(api, &z, Q)
	t0.Double(api, z)
	t0.Double(api, t0)
	z.AddAssign(api, t0)
	t1.Double(api, z)
	t1.AddAssign(api, z)
	t0.AddAssign(api, t1)
	t0.doubleN(api, &t0, 9)
	z.DoubleAndAdd(api, &t0, &z)
	z.doubleN(api, &z, 45)
	p.DoubleAndAdd(api, &z, Q)

	return p
}

// ScalarMul sets P = [s] Q and returns P.
//
// The method chooses an implementation based on scalar s. If it is constant,
// then the compiled circuit depends on s. If it is variable type, then
// the circuit is independent of the inputs.
func (p *g2AffP) ScalarMul(api frontend.API, Q g2AffP, s interface{}, opts ...algopts.AlgebraOption) *g2AffP {
	if n, ok := api.Compiler().ConstantValue(s); ok {
		return p.constScalarMul(api, Q, n, opts...)
	} else {
		return p.scalarMulGLVAndFakeGLV(api, Q, s, opts...)
	}
}

// varScalarMul sets P = [s]Q and returns P. It doesn't modify Q nor s.
// It implements an optimized version based on algorithm 1 of [Halo] (see Section 6.2 and appendix C).
//
// ⚠️  The scalar s must be nonzero and the point Q different from (0,0) unless [algopts.WithCompleteArithmetic] is set.
// (0,0) is not on the curve but we conventionally take it as the
// neutral/infinity point as per the [EVM].
//
// [Halo]: https://eprint.iacr.org/2019/1021.pdf
// [EVM]: https://ethereum.github.io/yellowpaper/paper.pdf
func (p *g2AffP) varScalarMul(api frontend.API, Q g2AffP, s frontend.Variable, opts ...algopts.AlgebraOption) *g2AffP {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(err)
	}
	var selector frontend.Variable
	one := fields_bls12377.E2{A0: 1, A1: 0}
	zero := fields_bls12377.E2{A0: 0, A1: 0}
	if cfg.CompleteArithmetic {
		// if Q=(0,0) we assign a dummy (1,1) to Q and continue
		selector = api.And(Q.X.IsZero(api), Q.Y.IsZero(api))
		Q.Select(api, selector, g2AffP{X: one, Y: one}, Q)
	}

	// We use the endomorphism à la GLV to compute [s]Q as
	// 		[s1]Q + [s2]Φ(Q)
	//
	// The context we are working is based on the `outer` curve. However, the
	// points and the operations on the points are performed on the `inner`
	// curve of the outer curve. We require some parameters from the inner
	// curve.
	cc := getInnerCurveConfig(api.Compiler().Field())

	// the hints allow to decompose the scalar s into s1 and s2 such that
	//     s1 + λ * s2 == s mod r,
	// where λ is third root of one in 𝔽_r.
	sd, err := api.Compiler().NewHint(decomposeScalarG1Simple, 2, s)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	s1, s2 := sd[0], sd[1]

	// s1 + λ * s2 == s
	api.AssertIsEqual(
		api.Add(s1, api.Mul(s2, cc.lambda)),
		s,
	)

	// For BLS12 λ bitsize is 127 equal to half of r bitsize
	nbits := cc.lambda.BitLen()
	s1bits := api.ToBinary(s1, nbits)
	s2bits := api.ToBinary(s2, nbits)

	// precompute -Q, -Φ(Q), Φ(Q)
	var tableQ, tablePhiQ [2]g2AffP
	tableQ[1] = Q
	tableQ[0].Neg(api, Q)
	cc.phi2(api, &tablePhiQ[1], &Q)
	tablePhiQ[0].Neg(api, tablePhiQ[1])

	// we suppose that the first bits of the sub-scalars are 1 and set:
	// 		Acc = Q + Φ(Q) = -Φ²(Q)
	var Acc, B g2AffP
	cc.phi1Neg(api, &Acc, &Q)

	// At each iteration we need to compute:
	// 		[2]Acc ± Q ± Φ(Q).
	// We can compute [2]Acc and look up the (precomputed) point B from:
	// 		B1 = +Q + Φ(Q)
	B1 := Acc
	// 		B2 = -Q - Φ(Q)
	B2 := g2AffP{}
	B2.Neg(api, B1)
	// 		B3 = +Q - Φ(Q)
	B3 := tableQ[1]
	B3.AddAssign(api, tablePhiQ[0])
	// 		B4 = -Q + Φ(Q)
	B4 := g2AffP{}
	B4.Neg(api, B3)
	//
	// Note that half the points are negatives of the other half,
	// hence have the same X coordinates.

	// However when doing doubleAndAdd(Acc, B) as (Acc+B)+Acc it might happen
	// that Acc==B or -B. So we add the base point G to it to avoid incomplete
	// additions in the loop by forcing Acc to be different than the stored B.
	// However we need at the end to subtract [2^nbits]G or conditionally
	// [2^nbits]Φ²(G) from the result.
	//
	// Acc = Q + Φ(Q) + G
	points := getTwistPoints()
	Acc.AddAssign(api,
		g2AffP{
			X: fields_bls12377.E2{A0: points.G2x[0], A1: points.G2x[1]},
			Y: fields_bls12377.E2{A0: points.G2y[0], A1: points.G2y[1]},
		},
	)

	for i := nbits - 1; i > 0; i-- {
		B.X.Select(api, api.Xor(s1bits[i], s2bits[i]), B3.X, B2.X)
		B.Y.Lookup2(api, s1bits[i], s2bits[i], B2.Y, B3.Y, B4.Y, B1.Y)
		// Acc = [2]Acc + B
		Acc.DoubleAndAdd(api, &Acc, &B)
	}

	// i = 0
	// subtract the Q, R, Φ(Q), Φ(R) if the first bits are 0.
	// When cfg.CompleteArithmetic is set, we use AddUnified instead of Add. This means
	// when s=0 then Acc=(0,0) because AddUnified(Q, -Q) = (0,0).
	if cfg.CompleteArithmetic {
		tableQ[0].AddUnified(api, Acc)
		Acc.Select(api, s1bits[0], Acc, tableQ[0])
		tablePhiQ[0].AddUnified(api, Acc)
		Acc.Select(api, s2bits[0], Acc, tablePhiQ[0])
		Acc.Select(api, selector, g2AffP{X: zero, Y: zero}, Acc)
	} else {
		tableQ[0].AddAssign(api, Acc)
		Acc.Select(api, s1bits[0], Acc, tableQ[0])
		tablePhiQ[0].AddAssign(api, Acc)
		Acc.Select(api, s2bits[0], Acc, tablePhiQ[0])
	}

	// subtract [2^nbits]G since we added G at the beginning
	B.X = fields_bls12377.E2{
		A0: points.G2m[nbits-1][0],
		A1: points.G2m[nbits-1][1],
	}
	B.Y = fields_bls12377.E2{
		A0: points.G2m[nbits-1][2],
		A1: points.G2m[nbits-1][3],
	}
	B.Y.Neg(api, B.Y)
	if cfg.CompleteArithmetic {
		Acc.AddUnified(api, B)
	} else {
		Acc.AddAssign(api, B)
	}

	if cfg.CompleteArithmetic {
		Acc.Select(api, selector, g2AffP{X: zero, Y: zero}, Acc)
	}

	p.X = Acc.X
	p.Y = Acc.Y

	return p
}

// constScalarMul sets P = [s] Q and returns P.
func (p *g2AffP) constScalarMul(api frontend.API, Q g2AffP, s *big.Int, opts ...algopts.AlgebraOption) *g2AffP {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(err)
	}
	if s.BitLen() == 0 {
		zero := fields_bls12377.E2{A0: 0, A1: 0}
		p.X = zero
		p.Y = zero
		return p
	}
	// see the comments in varScalarMul. However, two-bit lookup is cheaper if
	// bits are constant and here it makes sense to use the table in the main
	// loop.
	var Acc, negQ, negPhiQ, phiQ g2AffP
	cc := getInnerCurveConfig(api.Compiler().Field())
	s.Mod(s, cc.fr)
	cc.phi2(api, &phiQ, &Q)

	k := ecc.SplitScalar(s, cc.glvBasis)
	if k[0].Sign() == -1 {
		k[0].Neg(&k[0])
		Q.Neg(api, Q)
	}
	if k[1].Sign() == -1 {
		k[1].Neg(&k[1])
		phiQ.Neg(api, phiQ)
	}
	nbits := k[0].BitLen()
	if k[1].BitLen() > nbits {
		nbits = k[1].BitLen()
	}
	negQ.Neg(api, Q)
	negPhiQ.Neg(api, phiQ)
	var table [4]g2AffP
	table[0] = negQ
	table[1] = Q
	table[2] = negQ
	table[3] = Q

	if cfg.CompleteArithmetic {
		table[0].AddUnified(api, negPhiQ)
		table[1].AddUnified(api, negPhiQ)
		table[2].AddUnified(api, phiQ)
		table[3].AddUnified(api, phiQ)
	} else {
		table[0].AddAssign(api, negPhiQ)
		table[1].AddAssign(api, negPhiQ)
		table[2].AddAssign(api, phiQ)
		table[3].AddAssign(api, phiQ)
	}

	Acc = table[3]
	// if both high bits are set, then we would get to the incomplete part,
	// handle it separately.
	if k[0].Bit(nbits-1) == 1 && k[1].Bit(nbits-1) == 1 {
		if cfg.CompleteArithmetic {
			Acc.AddUnified(api, Acc)
			Acc.AddUnified(api, table[3])
		} else {
			Acc.Double(api, Acc)
			Acc.AddAssign(api, table[3])
		}
		nbits = nbits - 1
	}
	for i := nbits - 1; i > 0; i-- {
		if cfg.CompleteArithmetic {
			Acc.AddUnified(api, Acc)
			Acc.AddUnified(api, table[k[0].Bit(i)+2*k[1].Bit(i)])
		} else {
			Acc.DoubleAndAdd(api, &Acc, &table[k[0].Bit(i)+2*k[1].Bit(i)])
		}
	}

	// i = 0
	if cfg.CompleteArithmetic {
		negQ.AddUnified(api, Acc)
		Acc.Select(api, k[0].Bit(0), Acc, negQ)
		negPhiQ.AddUnified(api, Acc)
	} else {
		negQ.AddAssign(api, Acc)
		Acc.Select(api, k[0].Bit(0), Acc, negQ)
		negPhiQ.AddAssign(api, Acc)
	}
	Acc.Select(api, k[1].Bit(0), Acc, negPhiQ)
	p.X, p.Y = Acc.X, Acc.Y

	return p
}

// Assign a value to self (witness assignment)
func (p *g2AffP) Assign(p1 *bls12377.G2Affine) {
	p.X.Assign(&p1.X)
	p.Y.Assign(&p1.Y)
}

// AssertIsEqual constraint self to be equal to other into the given constraint system
func (p *g2AffP) AssertIsEqual(api frontend.API, other g2AffP) {
	p.X.AssertIsEqual(api, other.X)
	p.Y.AssertIsEqual(api, other.Y)
}

// DoubleAndAdd computes 2*p1+p2 in affine coords
func (p *g2AffP) DoubleAndAdd(api frontend.API, p1, p2 *g2AffP) *g2AffP {

	var n, d, l1, l2, x3, x4, y4 fields_bls12377.E2

	// compute lambda1 = (y2-y1)/(x2-x1)
	n.Sub(api, p1.Y, p2.Y)
	d.Sub(api, p1.X, p2.X)
	l1.DivUnchecked(api, n, d)

	// compute x3 = lambda1**2-x1-x2
	x3.Square(api, l1).
		Sub(api, x3, p1.X).
		Sub(api, x3, p2.X)

	// omit y3 computation
	// compute lambda2 = -lambda1-2*y1/(x3-x1)
	n.Double(api, p1.Y)
	d.Sub(api, x3, p1.X)
	l2.DivUnchecked(api, n, d)
	l2.Add(api, l2, l1).Neg(api, l2)

	// compute x4 =lambda2**2-x1-x3
	x4.Square(api, l2).
		Sub(api, x4, p1.X).
		Sub(api, x4, x3)

	// compute y4 = lambda2*(x1 - x4)-y1
	y4.Sub(api, p1.X, x4).
		Mul(api, l2, y4).
		Sub(api, y4, p1.Y)

	p.X = x4
	p.Y = y4

	return p
}

// ScalarMulBase computes s * g2 and returns it, where g2 is the fixed generator. It doesn't modify s.
func (p *g2AffP) ScalarMulBase(api frontend.API, s frontend.Variable) *g2AffP {

	points := getTwistPoints()

	sBits := api.ToBinary(s, 253)

	var res, tmp g2AffP

	// i = 1, 2
	// gm[0] = 3g, gm[1] = 5g, gm[2] = 7g
	res.X.Lookup2(api, sBits[1], sBits[2],
		fields_bls12377.E2{
			A0: points.G2x[0],
			A1: points.G2x[1]},
		fields_bls12377.E2{
			A0: points.G2m[0][0],
			A1: points.G2m[0][1]},
		fields_bls12377.E2{
			A0: points.G2m[1][0],
			A1: points.G2m[1][1]},
		fields_bls12377.E2{
			A0: points.G2m[2][0],
			A1: points.G2m[2][1]})
	res.Y.Lookup2(api, sBits[1], sBits[2],
		fields_bls12377.E2{
			A0: points.G2y[0],
			A1: points.G2y[1]},
		fields_bls12377.E2{
			A0: points.G2m[0][2],
			A1: points.G2m[0][3]},
		fields_bls12377.E2{
			A0: points.G2m[1][2],
			A1: points.G2m[1][3]},
		fields_bls12377.E2{
			A0: points.G2m[2][2],
			A1: points.G2m[2][3]})

	for i := 3; i < 253; i++ {
		// gm[i] = [2^i]g
		tmp.X = res.X
		tmp.Y = res.Y
		tmp.AddAssign(api, g2AffP{
			fields_bls12377.E2{
				A0: points.G2m[i][0],
				A1: points.G2m[i][1]},
			fields_bls12377.E2{
				A0: points.G2m[i][2],
				A1: points.G2m[i][3]}})
		res.Select(api, sBits[i], tmp, res)
	}

	// i = 0
	tmp.Neg(api, g2AffP{
		fields_bls12377.E2{A0: points.G2x[0], A1: points.G2x[1]},
		fields_bls12377.E2{A0: points.G2y[0], A1: points.G2y[1]}})
	tmp.AddAssign(api, res)
	res.Select(api, sBits[0], res, tmp)

	p.X = res.X
	p.Y = res.Y

	return p
}

func (p *g2AffP) psi(api frontend.API, q *g2AffP) *g2AffP {
	var x, y fields_bls12377.E2
	x.Conjugate(api, q.X)
	x.MulByFp(api, x, "80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410946")
	y.Conjugate(api, q.Y)
	y.MulByFp(api, y, "216465761340224619389371505802605247630151569547285782856803747159100223055385581585702401816380679166954762214499")

	p.X = x
	p.Y = y

	return p
}

// scalarMulGLVAndFakeGLV computes [s]P using GLV+fakeGLV with r^(1/4) bounds.
// It implements the "GLV + fake GLV" optimization which achieves tighter bounds
// on the sub-scalars, reducing the number of iterations in the scalar multiplication loop.
//
// ⚠️  The scalar s must be nonzero and the point P different from (0,0) unless [algopts.WithCompleteArithmetic] is set.
func (p *g2AffP) scalarMulGLVAndFakeGLV(api frontend.API, P g2AffP, s frontend.Variable, opts ...algopts.AlgebraOption) *g2AffP {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(err)
	}
	cc := getInnerCurveConfig(api.Compiler().Field())

	// handle zero-scalar
	var selector0 frontend.Variable
	_s := s
	if cfg.CompleteArithmetic {
		selector0 = api.IsZero(s)
		_s = api.Select(selector0, 1, s)
	}

	// Instead of computing [s]P=Q, we check that Q-[s]P == 0.
	// Checking Q - [s]P = 0 is equivalent to [v]Q + [-s*v]P = 0 for some nonzero v.
	//
	// The GLV curves supported in gnark have j-invariant 0, which means the eigenvalue
	// of the GLV endomorphism is a primitive cube root of unity λ. Using this we can
	// express the check as:
	//
	// 			[v1 + λ*v2]Q + [u1 + λ*u2]P = 0
	// 			[v1]Q + [v2]phi(Q) + [u1]P + [u2]phi(P) = 0
	//
	// where (v1 + λ*v2)*s = u1 + λ*u2 mod r
	// and u1, u2, v1, v2 < c*r^{1/4} with c ≈ 1.25 (proven bound from LLL lattice reduction).
	//
	// The hint returns u1, u2, v1, v2 and the quotient q.
	// In-circuit we check that (v1 + λ*v2)*s + u1 + λ*u2 = r*q
	//
	// The sub-scalars can be negative. So we return the absolute value in the
	// hint and negate the corresponding points here when needed.
	sd, err := api.NewHint(rationalReconstructExt, 10, _s, cc.lambda)
	if err != nil {
		panic(fmt.Sprintf("rationalReconstructExt hint: %v", err))
	}
	u1, u2, v1, v2, q := sd[0], sd[1], sd[2], sd[3], sd[4]
	isNegu1, isNegu2, isNegv1, isNegv2, isNegq := sd[5], sd[6], sd[7], sd[8], sd[9]

	// We need to check that:
	// 		s*(v1 + λ*v2) + u1 + λ*u2 - r * q = 0
	sv1 := api.Mul(_s, v1)
	sλv2 := api.Mul(_s, api.Mul(cc.lambda, v2))
	λu2 := api.Mul(cc.lambda, u2)
	rq := api.Mul(cc.fr, q)

	lhs1 := api.Select(isNegv1, 0, sv1)
	lhs2 := api.Select(isNegv2, 0, sλv2)
	lhs3 := api.Select(isNegu1, 0, u1)
	lhs4 := api.Select(isNegu2, 0, λu2)
	lhs5 := api.Select(isNegq, rq, 0)
	lhs := api.Add(
		api.Add(lhs1, lhs2),
		api.Add(lhs3, lhs4),
	)
	lhs = api.Add(lhs, lhs5)

	rhs1 := api.Select(isNegv1, sv1, 0)
	rhs2 := api.Select(isNegv2, sλv2, 0)
	rhs3 := api.Select(isNegu1, u1, 0)
	rhs4 := api.Select(isNegu2, λu2, 0)
	rhs5 := api.Select(isNegq, 0, rq)
	rhs := api.Add(
		api.Add(rhs1, rhs2),
		api.Add(rhs3, rhs4),
	)
	rhs = api.Add(rhs, rhs5)

	api.AssertIsEqual(lhs, rhs)

	// Next we compute the hinted scalar mul Q = [s]P
	point, err := api.NewHint(scalarMulGLVG2Hint, 4, P.X.A0, P.X.A1, P.Y.A0, P.Y.A1, s)
	if err != nil {
		panic(fmt.Sprintf("scalar mul hint: %v", err))
	}
	Q := g2AffP{
		X: fields_bls12377.E2{A0: point[0], A1: point[1]},
		Y: fields_bls12377.E2{A0: point[2], A1: point[3]},
	}

	// handle (0,0)-point
	var _selector0, selectorQ0 frontend.Variable
	_P := P
	one := fields_bls12377.E2{A0: 1, A1: 0}
	zero := fields_bls12377.E2{A0: 0, A1: 0}
	if cfg.CompleteArithmetic {
		// if P=(0,0) we assign a dummy point to P and continue
		_selector0 = api.And(P.X.IsZero(api), P.Y.IsZero(api))
		two := fields_bls12377.E2{A0: 2, A1: 0}
		_P.Select(api, _selector0, g2AffP{X: two, Y: one}, P)
		// if Q=(0,0) (either because s=0 or P=(0,0)) we assign a dummy point to Q
		selectorQ0 = api.And(Q.X.IsZero(api), Q.Y.IsZero(api))
		Q.Select(api, selectorQ0, g2AffP{X: one, Y: one}, Q)
	}

	// precompute -P, -Φ(P), Φ(P)
	var tableP, tablePhiP [2]g2AffP
	var negPY fields_bls12377.E2
	negPY.Neg(api, _P.Y)
	tableP[1] = g2AffP{
		X: _P.X,
		Y: fields_bls12377.E2{
			A0: api.Select(isNegu1, negPY.A0, _P.Y.A0),
			A1: api.Select(isNegu1, negPY.A1, _P.Y.A1),
		},
	}
	tableP[0].Neg(api, tableP[1])
	var phiPX fields_bls12377.E2
	phiPX.MulByFp(api, _P.X, cc.thirdRootOne2)
	tablePhiP[1] = g2AffP{
		X: phiPX,
		Y: fields_bls12377.E2{
			A0: api.Select(isNegu2, negPY.A0, _P.Y.A0),
			A1: api.Select(isNegu2, negPY.A1, _P.Y.A1),
		},
	}
	tablePhiP[0].Neg(api, tablePhiP[1])

	// precompute -Q, -Φ(Q), Φ(Q)
	var tableQ, tablePhiQ [2]g2AffP
	var negQY fields_bls12377.E2
	negQY.Neg(api, Q.Y)
	tableQ[1] = g2AffP{
		X: Q.X,
		Y: fields_bls12377.E2{
			A0: api.Select(isNegv1, negQY.A0, Q.Y.A0),
			A1: api.Select(isNegv1, negQY.A1, Q.Y.A1),
		},
	}
	tableQ[0].Neg(api, tableQ[1])
	var phiQX fields_bls12377.E2
	phiQX.MulByFp(api, Q.X, cc.thirdRootOne2)
	tablePhiQ[1] = g2AffP{
		X: phiQX,
		Y: fields_bls12377.E2{
			A0: api.Select(isNegv2, negQY.A0, Q.Y.A0),
			A1: api.Select(isNegv2, negQY.A1, Q.Y.A1),
		},
	}
	tablePhiQ[0].Neg(api, tablePhiQ[1])

	// precompute -P-Q, P+Q, P-Q, -P+Q, -Φ(P)-Φ(Q), Φ(P)+Φ(Q), Φ(P)-Φ(Q), -Φ(P)+Φ(Q)
	// We use AddUnified for table precomputation to handle edge cases like s=1 where Q=P
	// and the points might be equal (requiring doubling instead of addition).
	var tableS, tablePhiS [4]g2AffP
	tableS[0] = tableP[0]
	tableS[0].AddUnified(api, tableQ[0])
	tableS[1].Neg(api, tableS[0])
	tableS[2] = tableP[1]
	tableS[2].AddUnified(api, tableQ[0])
	tableS[3].Neg(api, tableS[2])
	tablePhiS[0] = tablePhiP[0]
	tablePhiS[0].AddUnified(api, tablePhiQ[0])
	tablePhiS[1].Neg(api, tablePhiS[0])
	tablePhiS[2] = tablePhiP[1]
	tablePhiS[2].AddUnified(api, tablePhiQ[0])
	tablePhiS[3].Neg(api, tablePhiS[2])

	// we suppose that the first bits of the sub-scalars are 1 and set:
	// 		Acc = P + Q + Φ(P) + Φ(Q)
	Acc := tableS[1]
	Acc.AddAssign(api, tablePhiS[1])
	// When doing doubleAndAdd(Acc, B) as (Acc+B)+Acc it might happen that
	// Acc==B or -B. So we add the G2 generator to it to avoid incomplete
	// additions in the loop by forcing Acc to be different than the stored B.
	// At the end, since [u1]P + [u2]Φ(P) + [v1]Q + [v2]Φ(Q) = 0,
	// Acc will equal [2^(nbits-1)]G2 (precomputed).
	points := getTwistPoints()
	G2Gen := g2AffP{
		X: fields_bls12377.E2{A0: points.G2x[0], A1: points.G2x[1]},
		Y: fields_bls12377.E2{A0: points.G2y[0], A1: points.G2y[1]},
	}
	Acc.AddAssign(api, G2Gen)

	// u1, u2, v1, v2 < c*r^{1/4} where c ≈ 1.25 (proven bound from LLL lattice reduction).
	// We need ceil(r.BitLen()/4) + 2 bits to account for the constant factor.
	// For BLS12-377, r.BitLen() = 253, so nbits = 64 + 2 = 66.
	nbits := (cc.fr.BitLen()+3)/4 + 2
	u1bits := api.ToBinary(u1, nbits)
	u2bits := api.ToBinary(u2, nbits)
	v1bits := api.ToBinary(v1, nbits)
	v2bits := api.ToBinary(v2, nbits)

	var B g2AffP
	for i := nbits - 1; i > 0; i-- {
		B.X.Select(api, api.Xor(u1bits[i], v1bits[i]), tableS[2].X, tableS[0].X)
		B.Y.Lookup2(api, u1bits[i], v1bits[i], tableS[0].Y, tableS[2].Y, tableS[3].Y, tableS[1].Y)
		Acc.DoubleAndAdd(api, &Acc, &B)
		B.X.Select(api, api.Xor(u2bits[i], v2bits[i]), tablePhiS[2].X, tablePhiS[0].X)
		B.Y.Lookup2(api, u2bits[i], v2bits[i], tablePhiS[0].Y, tablePhiS[2].Y, tablePhiS[3].Y, tablePhiS[1].Y)
		Acc.AddAssign(api, B)
	}

	// i = 0
	// subtract the P, Q, Φ(P), Φ(Q) if the first bits are 0
	tableP[0].AddAssign(api, Acc)
	Acc.Select(api, u1bits[0], Acc, tableP[0])
	tablePhiP[0].AddAssign(api, Acc)
	Acc.Select(api, u2bits[0], Acc, tablePhiP[0])
	tableQ[0].AddAssign(api, Acc)
	Acc.Select(api, v1bits[0], Acc, tableQ[0])
	tablePhiQ[0].AddAssign(api, Acc)
	Acc.Select(api, v2bits[0], Acc, tablePhiQ[0])

	// Acc should be now equal to [2^(nbits-1)]G2 since we added G2 at the beginning
	// and [u1]P + [u2]Φ(P) + [v1]Q + [v2]Φ(Q) = 0.
	// The loop does nbits-1 doublings, so the generator accumulates to [2^(nbits-1)]G2.
	// G2m[i] = [2^i]G2, so we need G2m[nbits-1] = [2^(nbits-1)]G2.
	expected := g2AffP{
		X: fields_bls12377.E2{
			A0: points.G2m[nbits-1][0],
			A1: points.G2m[nbits-1][1],
		},
		Y: fields_bls12377.E2{
			A0: points.G2m[nbits-1][2],
			A1: points.G2m[nbits-1][3],
		},
	}
	if cfg.CompleteArithmetic {
		// if P=(0,0) or s=0 (which makes Q=(0,0)), set Acc to expected to pass the check
		skipCheck := api.Or(selector0, _selector0)
		Acc.Select(api, skipCheck, expected, Acc)
	}
	Acc.AssertIsEqual(api, expected)

	if cfg.CompleteArithmetic {
		// Return (0,0) when s=0 or P=(0,0)
		Q.Select(api, api.Or(selector0, _selector0), g2AffP{X: zero, Y: zero}, Q)
	}

	p.X = Q.X
	p.Y = Q.Y

	return p
}
