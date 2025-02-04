// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package sw_grumpkin

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/grumpkin"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
)

// G1Affine point in affine coords
type G1Affine struct {
	X, Y frontend.Variable
}

// Neg outputs -p
func (p *G1Affine) Neg(api frontend.API, p1 G1Affine) *G1Affine {
	p.X = p1.X
	p.Y = api.Sub(0, p1.Y)
	return p
}

// AddAssign adds p1 to p using the affine formulas with division, and return p
func (p *G1Affine) AddAssign(api frontend.API, p1 G1Affine) *G1Affine {

	// compute lambda = (p1.y-p.y)/(p1.x-p.x)
	lambda := api.DivUnchecked(api.Sub(p1.Y, p.Y), api.Sub(p1.X, p.X))

	// xr = lambda**2-p.x-p1.x
	xr := api.Sub(api.Mul(lambda, lambda), api.Add(p.X, p1.X))

	// p.y = lambda(p.x-xr) - p.y
	p.Y = api.Sub(api.Mul(lambda, api.Sub(p.X, xr)), p.Y)

	//p.x = xr
	p.X = xr
	return p
}

func (p *G1Affine) AddUnified(api frontend.API, q G1Affine) *G1Affine {
	// selector1 = 1 when p is (0,0) and 0 otherwise
	selector1 := api.And(api.IsZero(p.X), api.IsZero(p.Y))
	// selector2 = 1 when q is (0,0) and 0 otherwise
	selector2 := api.And(api.IsZero(q.X), api.IsZero(q.Y))

	// λ = ((p.x+q.x)² - p.x*q.x + a)/(p.y + q.y)
	pxqx := api.Mul(p.X, q.X)
	pxplusqx := api.Add(p.X, q.X)
	num := api.Mul(pxplusqx, pxplusqx)
	num = api.Sub(num, pxqx)
	denum := api.Add(p.Y, q.Y)
	// if p.y + q.y = 0, assign dummy 1 to denum and continue
	selector3 := api.IsZero(denum)
	denum = api.Select(selector3, 1, denum)
	λ := api.Div(num, denum)

	// x = λ^2 - p.x - q.x
	xr := api.Mul(λ, λ)
	xr = api.Sub(xr, pxplusqx)

	// y = λ(p.x - xr) - p.y
	yr := api.Sub(p.X, xr)
	yr = api.Mul(yr, λ)
	yr = api.Sub(yr, p.Y)
	result := G1Affine{
		X: xr,
		Y: yr,
	}

	// if p=(0,0) return q
	result.Select(api, selector1, q, result)
	// if q=(0,0) return p
	result.Select(api, selector2, *p, result)
	// if p.y + q.y = 0, return (0, 0)
	result.Select(api, selector3, G1Affine{0, 0}, result)

	p.X = result.X
	p.Y = result.Y

	return p
}

// Select sets p1 if b=1, p2 if b=0, and returns it. b must be boolean constrained
func (p *G1Affine) Select(api frontend.API, b frontend.Variable, p1, p2 G1Affine) *G1Affine {

	p.X = api.Select(b, p1.X, p2.X)
	p.Y = api.Select(b, p1.Y, p2.Y)

	return p

}

// Lookup2 performs a 2-bit lookup between p1, p2, p3, p4 based on bits b0  and b1.
// Returns:
//   - p1 if b0=0 and b1=0,
//   - p2 if b0=1 and b1=0,
//   - p3 if b0=0 and b1=1,
//   - p4 if b0=1 and b1=1.
func (p *G1Affine) Lookup2(api frontend.API, b1, b2 frontend.Variable, p1, p2, p3, p4 G1Affine) *G1Affine {

	p.X = api.Lookup2(b1, b2, p1.X, p2.X, p3.X, p4.X)
	p.Y = api.Lookup2(b1, b2, p1.Y, p2.Y, p3.Y, p4.Y)

	return p

}

// Double double a point in affine coords
func (p *G1Affine) Double(api frontend.API, p1 G1Affine) *G1Affine {

	var three, two big.Int
	three.SetInt64(3)
	two.SetInt64(2)

	// compute lambda = (3*p1.x**2+a)/2*p1.y, here we assume a=0 (j invariant 0 curve)
	lambda := api.DivUnchecked(api.Mul(p1.X, p1.X, three), api.Mul(p1.Y, two))

	// xr = lambda**2-2*p1.x
	xr := api.Sub(api.Mul(lambda, lambda), api.Mul(p1.X, two))

	// p.y = lambda(p.x-xr) - p.y
	p.Y = api.Sub(api.Mul(lambda, api.Sub(p1.X, xr)), p1.Y)

	//p.x = xr
	p.X = xr

	return p
}

// ScalarMul sets P = [s] Q and returns P.
//
// The method chooses an implementation based on scalar s. If it is constant,
// then the compiled circuit depends on s. If it is variable type, then
// the circuit is independent of the inputs.
func (P *G1Affine) ScalarMul(api frontend.API, Q G1Affine, s interface{}, opts ...algopts.AlgebraOption) *G1Affine {
	if n, ok := api.Compiler().ConstantValue(s); ok {
		return P.constScalarMul(api, Q, n, opts...)
	} else {
		return P.varScalarMul(api, Q, s, opts...)
	}
}

// constScalarMul sets P = [s] Q and returns P.
func (P *G1Affine) constScalarMul(api frontend.API, Q G1Affine, s *big.Int, opts ...algopts.AlgebraOption) *G1Affine {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(err)
	}
	if s.BitLen() == 0 {
		P.X = 0
		P.Y = 0
		return P
	}
	// see the comments in varScalarMul. However, two-bit lookup is cheaper if
	// bits are constant and here it makes sense to use the table in the main
	// loop.
	var Acc, negQ, negPhiQ, phiQ G1Affine
	cc := getInnerCurveConfig(api.Compiler().Field())
	s.Mod(s, cc.fr)
	cc.phi1(api, &phiQ, &Q)

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
	var table [4]G1Affine
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
	P.X, P.Y = Acc.X, Acc.Y

	return P
}

// varScalarMul sets P = [s] Q and returns P.
// It computes the standard little-endian double-and-add algorithm
// (Algorithm 3.26, Guide to Elliptic Curve Cryptography)
//
// TODO: @yelhousni implement endomorphism-based optimization
func (P *G1Affine) varScalarMul(api frontend.API, Q G1Affine, s frontend.Variable, opts ...algopts.AlgebraOption) *G1Affine {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(fmt.Sprintf("parse opts: %v", err))
	}
	*P = Q
	var selector frontend.Variable
	if cfg.CompleteArithmetic {
		// if Q=(0,0) we assign a dummy (1,1) to P and continue
		selector = api.And(api.IsZero(P.X), api.IsZero(P.Y))
		P.Select(api, selector, G1Affine{X: 1, Y: 1}, *P)
	}

	nBits := 254
	sBits := api.ToBinary(s, nBits)

	var temp, doubles G1Affine
	doubles.Double(api, *P)

	for i := 1; i < nBits-1; i++ {
		temp = *P
		temp.AddAssign(api, doubles)
		P.Select(api, sBits[i], temp, *P)
		doubles.Double(api, doubles)
	}

	// i = nBits - 1
	temp = *P
	temp.AddAssign(api, doubles)
	P.Select(api, sBits[nBits-1], temp, *P)

	// i = 0
	// we use AddUnified instead of Add. This is because:
	// 		- when s=0 then R0=P and AddUnified(P, -P) = (0,0). We return (0,0).
	// 		- when s=1 then R0=P AddUnified(Q, -Q) is well defined. We return R0=P.
	temp = *P
	temp.AddUnified(api, *doubles.Neg(api, Q))
	P.Select(api, sBits[0], *P, temp)

	if cfg.CompleteArithmetic {
		// if Q=(0,0), return (0,0)
		P.Select(api, selector, G1Affine{X: 0, Y: 0}, *P)
	}

	return P
}

// Assign a value to self (witness assignment)
func (p *G1Affine) Assign(p1 *grumpkin.G1Affine) {
	p.X = (fr_bn.Element)(p1.X)
	p.Y = (fr_bn.Element)(p1.Y)
}

// AssertIsEqual constraint self to be equal to other into the given constraint system
func (p *G1Affine) AssertIsEqual(api frontend.API, other G1Affine) {
	api.AssertIsEqual(p.X, other.X)
	api.AssertIsEqual(p.Y, other.Y)
}

// DoubleAndAdd computes 2*p1+p in affine coords
func (p *G1Affine) DoubleAndAdd(api frontend.API, p1, p2 *G1Affine) *G1Affine {

	// compute lambda1 = (y2-y1)/(x2-x1)
	l1 := api.DivUnchecked(api.Sub(p1.Y, p2.Y), api.Sub(p1.X, p2.X))

	// compute x3 = lambda1**2-x1-x2
	x3 := api.Mul(l1, l1)
	x3 = api.Sub(x3, api.Add(p1.X, p2.X))

	// omit y3 computation
	// compute lambda2 = lambda1+2*y1/(x3-x1)
	l2 := api.DivUnchecked(api.Mul(p1.Y, big.NewInt(2)), api.Sub(x3, p1.X))
	l2 = api.Add(l2, l1)

	// compute x4 =lambda2**2-x1-x3
	x4 := api.Mul(l2, l2)
	x4 = api.Sub(x4, api.Add(p1.X, x3))

	// compute y4 = lambda2*(x4 - x1)-y1
	y4 := api.Sub(x4, p1.X)
	y4 = api.Mul(l2, y4)
	y4 = api.Sub(y4, p1.Y)

	p.X = x4
	p.Y = y4

	return p
}

// DoubleAndAddSelect computes 2*p1+p2 or condtionally 2*p2+p1 in affine coords
func (p *G1Affine) DoubleAndAddSelect(api frontend.API, b frontend.Variable, p1, p2 *G1Affine) *G1Affine {

	// compute lambda1 = (y2-y1)/(x2-x1)
	l1 := api.DivUnchecked(api.Sub(p1.Y, p2.Y), api.Sub(p1.X, p2.X))

	// compute x3 = lambda1**2-x1-x2
	x3 := api.Mul(l1, l1)
	x3 = api.Sub(x3, api.Add(p1.X, p2.X))

	// omit y3 computation

	// conditional second addition
	var t G1Affine
	t.Select(api, b, *p1, *p2)

	// compute lambda2 = lambda1+2*y1/(x3-x1)
	l2 := api.DivUnchecked(api.Mul(t.Y, big.NewInt(2)), api.Sub(x3, t.X))
	l2 = api.Add(l2, l1)

	// compute x4 =lambda2**2-x1-x3
	x4 := api.Mul(l2, l2)
	x4 = api.Sub(x4, api.Add(t.X, x3))

	// compute y4 = lambda2*(x4 - x1)-y1
	y4 := api.Sub(x4, t.X)
	y4 = api.Mul(l2, y4)
	y4 = api.Sub(y4, t.Y)

	p.X = x4
	p.Y = y4

	return p
}

// ScalarMulBase computes s * g1 and returns it, where g1 is the fixed generator. It doesn't modify s.
func (P *G1Affine) ScalarMulBase(api frontend.API, s frontend.Variable, opts ...algopts.AlgebraOption) *G1Affine {
	g1aff, _ := grumpkin.Generators()
	generator := G1Affine{
		X: g1aff.X.BigInt(new(big.Int)),
		Y: g1aff.Y.BigInt(new(big.Int)),
	}
	return P.ScalarMul(api, generator, s, opts...)
}

func (P *G1Affine) jointScalarMul(api frontend.API, Q, R G1Affine, s, t frontend.Variable, opts ...algopts.AlgebraOption) *G1Affine {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(err)
	}
	if cfg.CompleteArithmetic {
		var tmp G1Affine
		P.ScalarMul(api, Q, s, opts...)
		tmp.ScalarMul(api, R, t, opts...)
		P.AddUnified(api, tmp)
	} else {
		P.jointScalarMulUnsafe(api, Q, R, s, t)
	}
	return P
}

// P = [s]Q + [t]R using Shamir's trick
//
// TODO: @yelhousni implement endomorphism-based optimization
func (P *G1Affine) jointScalarMulUnsafe(api frontend.API, Q, R G1Affine, s, t frontend.Variable) *G1Affine {
	var Acc, B1, QNeg, RNeg G1Affine
	QNeg.Neg(api, Q)
	RNeg.Neg(api, R)

	// Acc = P1 + P2
	Acc = Q
	Acc.AddAssign(api, R)

	nbits := 254
	sbits := api.ToBinary(s, nbits)
	tbits := api.ToBinary(t, nbits)

	for i := nbits - 1; i > 0; i-- {
		B1 = G1Affine{
			X: QNeg.X,
			Y: api.Select(sbits[i], Q.Y, QNeg.Y),
		}
		Acc.DoubleAndAdd(api, &Acc, &B1)
		B1 = G1Affine{
			X: RNeg.X,
			Y: api.Select(tbits[i], R.Y, RNeg.Y),
		}
		Acc.AddAssign(api, B1)

	}

	// i = 0
	QNeg.AddAssign(api, Acc)
	Acc.Select(api, sbits[0], Acc, QNeg)
	RNeg.AddAssign(api, Acc)
	P.Select(api, tbits[0], Acc, RNeg)

	return P
}

// scalarBitsMul computes [s]Q and returns it where sBits is the bit decomposition of s. It doesn't modify Q nor sBits.
// The method is similar to varScalarMul.
//
// TODO: @yelhousni implement endomorphism-based optimization
func (P *G1Affine) scalarBitsMul(api frontend.API, Q G1Affine, sBits []frontend.Variable, opts ...algopts.AlgebraOption) *G1Affine {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(fmt.Sprintf("parse opts: %v", err))
	}
	*P = Q
	var selector frontend.Variable
	if cfg.CompleteArithmetic {
		// if Q=(0,0) we assign a dummy (1,1) to P and continue
		selector = api.And(api.IsZero(P.X), api.IsZero(P.Y))
		P.Select(api, selector, G1Affine{X: 1, Y: 1}, *P)
	}

	var temp, doubles G1Affine
	doubles.Double(api, *P)

	nBits := 254
	for i := 1; i < nBits-1; i++ {
		temp = *P
		temp.AddAssign(api, doubles)
		P.Select(api, sBits[i], temp, *P)
		doubles.Double(api, doubles)
	}

	// i = nBits - 1
	temp = *P
	temp.AddAssign(api, doubles)
	P.Select(api, sBits[nBits-1], temp, *P)

	// i = 0
	// we use AddUnified instead of Add. This is because:
	// 		- when s=0 then R0=P and AddUnified(P, -P) = (0,0). We return (0,0).
	// 		- when s=1 then R0=P AddUnified(Q, -Q) is well defined. We return R0=P.
	temp = *P
	temp.AddUnified(api, *doubles.Neg(api, Q))
	P.Select(api, sBits[0], *P, temp)

	if cfg.CompleteArithmetic {
		// if Q=(0,0), return (0,0)
		P.Select(api, selector, G1Affine{X: 0, Y: 0}, *P)
	}

	return P
}
