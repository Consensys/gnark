/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sw_bls24315

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	"github.com/consensys/gnark-crypto/ecc/bw6-633/fr"
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

	return &result
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

	// xr = lambda**2-p1.x-p1.x
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

// varScalarMul sets P = [s]Q and returns P. It doesn't modify Q nor s.
// It implements an optimized version based on algorithm 1 of [Halo] (see Section 6.2 and appendix C).
//
// ⚠️  The scalar s must be nonzero and the point Q different from (0,0) unless [algopts.WithCompleteArithmetic] is set.
// (0,0) is not on the curve but we conventionally take it as the
// neutral/infinity point as per the [EVM].
//
// [Halo]: https://eprint.iacr.org/2019/1021.pdf
// [EVM]: https://ethereum.github.io/yellowpaper/paper.pdf
func (P *G1Affine) varScalarMul(api frontend.API, Q G1Affine, s frontend.Variable, opts ...algopts.AlgebraOption) *G1Affine {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(err)
	}
	var selector frontend.Variable
	if cfg.CompleteArithmetic {
		// if Q=(0,0) we assign a dummy (1,1) to Q and continue
		selector = api.And(api.IsZero(Q.X), api.IsZero(Q.Y))
		Q.Select(api, selector, G1Affine{X: 1, Y: 1}, Q)
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
	sd, err := api.Compiler().NewHint(decomposeScalarG1Simple, 3, s)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	s1, s2 := sd[0], sd[1]

	// s1 + λ * s2 == s mod r
	api.AssertIsEqual(
		api.Add(s1, api.Mul(s2, cc.lambda)),
		api.Add(s, api.Mul(cc.fr, sd[2])),
	)

	nbits := 127
	s1bits := api.ToBinary(s1, nbits)
	s2bits := api.ToBinary(s2, nbits)

	// precompute -Q, -Φ(Q), Φ(Q)
	var tableQ, tablePhiQ [2]G1Affine
	tableQ[1] = Q
	tableQ[0].Neg(api, Q)
	cc.phi1(api, &tablePhiQ[1], &Q)
	tablePhiQ[0].Neg(api, tablePhiQ[1])

	// we suppose that the first bits of the sub-scalars are 1 and set:
	// 		Acc = Q + Φ(Q) = -Φ²(Q)
	var Acc, B G1Affine
	cc.phi2Neg(api, &Acc, &Q)

	// At each iteration we need to compute:
	// 		[2]Acc ± Q ± Φ(Q).
	// We can compute [2]Acc and look up the (precomputed) point B from:
	// 		B1 = +Q + Φ(Q)
	B1 := Acc
	// 		B2 = -Q - Φ(Q)
	B2 := G1Affine{}
	B2.Neg(api, B1)
	// 		B3 = +Q - Φ(Q)
	B3 := tableQ[1]
	B3.AddAssign(api, tablePhiQ[0])
	// 		B4 = -Q + Φ(Q)
	B4 := G1Affine{}
	B4.Neg(api, B3)
	//
	// Note that half the points are negatives of the other half,
	// hence have the same X coordinates.

	// However when doing doubleAndAdd(Acc, B) as (Acc+B)+Acc it might happen
	// that Acc==B or -B. So we add the point H=(0,1) on BLS12-377 of order 2
	// to it to avoid incomplete additions in the loop by forcing Acc to be
	// different than the stored B.  Normally, the point H should be "killed
	// out" by the first doubling in the loop and the result will remain
	// unchanged. However, we are using affine coordinates that do not encode
	// the infinity point. Given the affine formulae, doubling (0,1) results in
	// (0,-1). Since the loop size N=nbits-1 is even we need to subtract
	// [2^N]H = (0,1) from the result at the end.
	//
	// Acc = Q + Φ(Q) + H
	Acc.AddAssign(api, G1Affine{X: 0, Y: 1})

	for i := nbits - 1; i > 0; i-- {
		B.X = api.Select(api.Xor(s1bits[i], s2bits[i]), B3.X, B2.X)
		B.Y = api.Lookup2(s1bits[i], s2bits[i], B2.Y, B3.Y, B4.Y, B1.Y)
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
		Acc.Select(api, selector, G1Affine{X: 0, Y: 0}, Acc)
	} else {
		tableQ[0].AddAssign(api, Acc)
		Acc.Select(api, s1bits[0], Acc, tableQ[0])
		tablePhiQ[0].AddAssign(api, Acc)
		Acc.Select(api, s2bits[0], Acc, tablePhiQ[0])
	}

	if cfg.CompleteArithmetic {
		// subtract [2^N]G = (0,1) since we added H at the beginning
		Acc.AddUnified(api, G1Affine{X: 0, Y: -1})
		Acc.Select(api, selector, G1Affine{X: 0, Y: 0}, Acc)
	} else {
		// subtract [2^N]G = (0,1) since we added H at the beginning
		Acc.AddAssign(api, G1Affine{X: 0, Y: -1})
	}

	P.X = Acc.X
	P.Y = Acc.Y

	return P
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

// Assign a value to self (witness assignment)
func (p *G1Affine) Assign(p1 *bls24315.G1Affine) {
	p.X = (fr.Element)(p1.X)
	p.Y = (fr.Element)(p1.Y)
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

// ScalarMulBase computes s * g1 and returns it, where g1 is the fixed generator. It doesn't modify s.
func (P *G1Affine) ScalarMulBase(api frontend.API, s frontend.Variable, opts ...algopts.AlgebraOption) *G1Affine {
	_, _, g1aff, _ := bls24315.Generators()
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
func (P *G1Affine) jointScalarMulUnsafe(api frontend.API, Q, R G1Affine, s, t frontend.Variable) *G1Affine {
	cc := getInnerCurveConfig(api.Compiler().Field())

	sd, err := api.Compiler().NewHint(decomposeScalarG1, 3, s)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	s1, s2 := sd[0], sd[1]

	td, err := api.Compiler().NewHint(decomposeScalarG1, 3, t)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	t1, t2 := td[0], td[1]

	api.AssertIsEqual(api.Add(s1, api.Mul(s2, cc.lambda)), api.Add(s, api.Mul(cc.fr, sd[2])))
	api.AssertIsEqual(api.Add(t1, api.Mul(t2, cc.lambda)), api.Add(t, api.Mul(cc.fr, td[2])))

	nbits := cc.lambda.BitLen() + 1

	s1bits := api.ToBinary(s1, nbits)
	s2bits := api.ToBinary(s2, nbits)
	t1bits := api.ToBinary(t1, nbits)
	t2bits := api.ToBinary(t2, nbits)

	// precompute -Q, -Φ(Q), Φ(Q)
	var tableQ, tablePhiQ [2]G1Affine
	tableQ[1] = Q
	tableQ[0].Neg(api, Q)
	cc.phi1(api, &tablePhiQ[1], &Q)
	tablePhiQ[0].Neg(api, tablePhiQ[1])
	// precompute -R, -Φ(R), Φ(R)
	var tableR, tablePhiR [2]G1Affine
	tableR[1] = R
	tableR[0].Neg(api, R)
	cc.phi1(api, &tablePhiR[1], &R)
	tablePhiR[0].Neg(api, tablePhiR[1])
	// precompute Q+R, -Q-R, Q-R, -Q+R, Φ(Q)+Φ(R), -Φ(Q)-Φ(R), Φ(Q)-Φ(R), -Φ(Q)+Φ(R)
	var tableS, tablePhiS [4]G1Affine
	tableS[0] = tableQ[0]
	tableS[0].AddAssign(api, tableR[0])
	tableS[1].Neg(api, tableS[0])
	tableS[2] = Q
	tableS[2].AddAssign(api, tableR[0])
	tableS[3].Neg(api, tableS[2])
	cc.phi1(api, &tablePhiS[0], &tableS[0])
	cc.phi1(api, &tablePhiS[1], &tableS[1])
	cc.phi1(api, &tablePhiS[2], &tableS[2])
	cc.phi1(api, &tablePhiS[3], &tableS[3])

	// suppose first bit is 1 and set:
	// Acc = Q + R + Φ(Q) + Φ(R) = -Φ²(Q+R)
	var Acc G1Affine
	cc.phi2Neg(api, &Acc, &tableS[1])

	// Acc = [2]Acc ± Q ± R ± Φ(Q) ± Φ(R)
	var B G1Affine
	for i := nbits - 1; i > 0; i-- {
		B.X = api.Select(api.Xor(s1bits[i], t1bits[i]), tableS[2].X, tableS[0].X)
		B.Y = api.Lookup2(s1bits[i], t1bits[i], tableS[0].Y, tableS[2].Y, tableS[3].Y, tableS[1].Y)
		Acc.DoubleAndAdd(api, &Acc, &B)
		B.X = api.Select(api.Xor(s2bits[i], t2bits[i]), tablePhiS[2].X, tablePhiS[0].X)
		B.Y = api.Lookup2(s2bits[i], t2bits[i], tablePhiS[0].Y, tablePhiS[2].Y, tablePhiS[3].Y, tablePhiS[1].Y)
		Acc.AddAssign(api, B)
	}

	// i = 0
	// subtract the initial point from the accumulator when first bit was 0
	tableQ[0].AddAssign(api, Acc)
	Acc.Select(api, s1bits[0], Acc, tableQ[0])
	tablePhiQ[0].AddAssign(api, Acc)
	Acc.Select(api, s2bits[0], Acc, tablePhiQ[0])
	tableR[0].AddAssign(api, Acc)
	Acc.Select(api, t1bits[0], Acc, tableR[0])
	tablePhiR[0].AddAssign(api, Acc)
	Acc.Select(api, t2bits[0], Acc, tablePhiR[0])

	P.X = Acc.X
	P.Y = Acc.Y

	return P
}

// scalarBitsMul computes [s]Q and returns it where sBits is the bit decomposition of s. It doesn't modify Q nor sBits.
// The method is similar to varScalarMul.
func (P *G1Affine) scalarBitsMul(api frontend.API, Q G1Affine, s1bits, s2bits []frontend.Variable, opts ...algopts.AlgebraOption) *G1Affine {
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		panic(err)
	}
	var selector frontend.Variable
	if cfg.CompleteArithmetic {
		// if Q=(0,0) we assign a dummy (1,1) to Q and continue
		selector = api.And(api.IsZero(Q.X), api.IsZero(Q.Y))
		Q.Select(api, selector, G1Affine{X: 1, Y: 1}, Q)
	}

	// We use the endomorphism à la GLV to compute [s]Q as
	// 		[s1]Q + [s2]Φ(Q)
	//
	// The context we are working is based on the `outer` curve. However, the
	// points and the operations on the points are performed on the `inner`
	// curve of the outer curve. We require some parameters from the inner
	// curve.
	cc := getInnerCurveConfig(api.Compiler().Field())
	nbits := 127

	// precompute -Q, -Φ(Q), Φ(Q)
	var tableQ, tablePhiQ [2]G1Affine
	tableQ[1] = Q
	tableQ[0].Neg(api, Q)
	cc.phi1(api, &tablePhiQ[1], &Q)
	tablePhiQ[0].Neg(api, tablePhiQ[1])

	// we suppose that the first bits of the sub-scalars are 1 and set:
	// 		Acc = Q + Φ(Q) = -Φ²(Q)
	var Acc, B G1Affine
	cc.phi2Neg(api, &Acc, &Q)

	// At each iteration we need to compute:
	// 		[2]Acc ± Q ± Φ(Q).
	// We can compute [2]Acc and look up the (precomputed) point B from:
	// 		B1 = +Q + Φ(Q)
	B1 := Acc
	// 		B2 = -Q - Φ(Q)
	B2 := G1Affine{}
	B2.Neg(api, B1)
	// 		B3 = +Q - Φ(Q)
	B3 := tableQ[1]
	B3.AddAssign(api, tablePhiQ[0])
	// 		B4 = -Q + Φ(Q)
	B4 := G1Affine{}
	B4.Neg(api, B3)
	//
	// Note that half the points are negatives of the other half,
	// hence have the same X coordinates.

	// However when doing doubleAndAdd(Acc, B) as (Acc+B)+Acc it might happen
	// that Acc==B or -B. So we add the point H=(0,1) on BLS12-377 of order 2
	// to it to avoid incomplete additions in the loop by forcing Acc to be
	// different than the stored B.  Normally, the point H should be "killed
	// out" by the first doubling in the loop and the result will remain
	// unchanged. However, we are using affine coordinates that do not encode
	// the infinity point. Given the affine formulae, doubling (0,1) results in
	// (0,-1). Since the loop size N=nbits-1 is even we need to subtract
	// [2^N]H = (0,1) from the result at the end.
	//
	// Acc = Q + Φ(Q) + H
	Acc.AddAssign(api, G1Affine{X: 0, Y: 1})

	for i := nbits - 1; i > 0; i-- {
		B.X = api.Select(api.Xor(s1bits[i], s2bits[i]), B3.X, B2.X)
		B.Y = api.Lookup2(s1bits[i], s2bits[i], B2.Y, B3.Y, B4.Y, B1.Y)
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
		Acc.Select(api, selector, G1Affine{X: 0, Y: 0}, Acc)
	} else {
		tableQ[0].AddAssign(api, Acc)
		Acc.Select(api, s1bits[0], Acc, tableQ[0])
		tablePhiQ[0].AddAssign(api, Acc)
		Acc.Select(api, s2bits[0], Acc, tablePhiQ[0])
	}

	if cfg.CompleteArithmetic {
		// subtract [2^N]G = (0,1) since we added H at the beginning
		Acc.AddUnified(api, G1Affine{X: 0, Y: -1})
		Acc.Select(api, selector, G1Affine{X: 0, Y: 0}, Acc)
	} else {
		// subtract [2^N]G = (0,1) since we added H at the beginning
		Acc.AddAssign(api, G1Affine{X: 0, Y: -1})

	}

	P.X = Acc.X
	P.Y = Acc.Y

	return P
}
