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

package sw_bls12377

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
)

// G1Jac point in Jacobian coords
type G1Jac struct {
	X, Y, Z frontend.Variable
}

// G1Affine point in affine coords
type G1Affine struct {
	X, Y frontend.Variable
}

// Neg outputs -p
func (p *G1Jac) Neg(api frontend.API, p1 G1Jac) *G1Jac {
	p.X = p1.X
	p.Y = api.Sub(0, p1.Y)
	p.Z = p1.Z
	return p
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

// AddAssign adds 2 point in Jacobian coordinates
// p=p, a=p1
func (p *G1Jac) AddAssign(api frontend.API, p1 G1Jac) *G1Jac {

	// get some Element from our pool
	var Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, r, V frontend.Variable

	Z1Z1 = api.Mul(p1.Z, p1.Z)

	Z2Z2 = api.Mul(p.Z, p.Z)

	U1 = api.Mul(p1.X, Z2Z2)

	U2 = api.Mul(p.X, Z1Z1)

	S1 = api.Mul(p1.Y, p.Z)
	S1 = api.Mul(S1, Z2Z2)

	S2 = api.Mul(p.Y, p1.Z)
	S2 = api.Mul(S2, Z1Z1)

	H = api.Sub(U2, U1)

	I = api.Add(H, H)
	I = api.Mul(I, I)

	J = api.Mul(H, I)

	r = api.Sub(S2, S1)
	r = api.Add(r, r)

	V = api.Mul(U1, I)

	p.X = api.Mul(r, r)
	p.X = api.Sub(p.X, J)
	p.X = api.Sub(p.X, V)
	p.X = api.Sub(p.X, V)

	p.Y = api.Sub(V, p.X)
	p.Y = api.Mul(p.Y, r)

	S1 = api.Mul(J, S1)
	S1 = api.Add(S1, S1)

	p.Y = api.Sub(p.Y, S1)

	p.Z = api.Add(p.Z, p1.Z)
	p.Z = api.Mul(p.Z, p.Z)
	p.Z = api.Sub(p.Z, Z1Z1)
	p.Z = api.Sub(p.Z, Z2Z2)
	p.Z = api.Mul(p.Z, H)

	return p
}

// DoubleAssign doubles the receiver point in jacobian coords and returns it
func (p *G1Jac) DoubleAssign(api frontend.API) *G1Jac {
	// get some Element from our pool
	var XX, YY, YYYY, ZZ, S, M, T frontend.Variable

	XX = api.Mul(p.X, p.X)
	YY = api.Mul(p.Y, p.Y)
	YYYY = api.Mul(YY, YY)
	ZZ = api.Mul(p.Z, p.Z)
	S = api.Add(p.X, YY)
	S = api.Mul(S, S)
	S = api.Sub(S, XX)
	S = api.Sub(S, YYYY)
	S = api.Add(S, S)
	M = api.Mul(XX, 3) // M = 3*XX+a*ZZ², here a=0 (we suppose sw has j invariant 0)
	p.Z = api.Add(p.Z, p.Y)
	p.Z = api.Mul(p.Z, p.Z)
	p.Z = api.Sub(p.Z, YY)
	p.Z = api.Sub(p.Z, ZZ)
	p.X = api.Mul(M, M)
	T = api.Add(S, S)
	p.X = api.Sub(p.X, T)
	p.Y = api.Sub(S, p.X)
	p.Y = api.Mul(p.Y, M)
	YYYY = api.Mul(YYYY, 8)
	p.Y = api.Sub(p.Y, YYYY)

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

// FromJac sets p to p1 in affine and returns it
func (p *G1Affine) FromJac(api frontend.API, p1 G1Jac) *G1Affine {
	s := api.Mul(p1.Z, p1.Z)
	p.X = api.DivUnchecked(p1.X, s)
	p.Y = api.DivUnchecked(p1.Y, api.Mul(s, p1.Z))
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
func (P *G1Affine) ScalarMul(api frontend.API, Q G1Affine, s interface{}) *G1Affine {
	if n, ok := api.Compiler().ConstantValue(s); ok {
		return P.constScalarMul(api, Q, n)
	} else {
		return P.varScalarMul(api, Q, s)
	}
}

var DecomposeScalarG1 = func(scalarField *big.Int, inputs []*big.Int, res []*big.Int) error {
	cc := getInnerCurveConfig(scalarField)
	sp := ecc.SplitScalar(inputs[0], cc.glvBasis)
	res[0].Set(&(sp[0]))
	res[1].Set(&(sp[1]))
	one := big.NewInt(1)
	// add (lambda+1, lambda) until scalar compostion is over Fr to ensure that
	// the high bits are set in decomposition.
	for res[0].Cmp(cc.lambda) < 1 && res[1].Cmp(cc.lambda) < 1 {
		res[0].Add(res[0], cc.lambda)
		res[0].Add(res[0], one)
		res[1].Add(res[1], cc.lambda)
	}
	// figure out how many times we have overflowed
	res[2].Mul(res[1], cc.lambda).Add(res[2], res[0])
	res[2].Sub(res[2], inputs[0])
	res[2].Div(res[2], cc.fr)

	return nil
}

func init() {
	solver.RegisterHint(DecomposeScalarG1)
}

// varScalarMul sets P = [s] Q and returns P.
func (P *G1Affine) varScalarMul(api frontend.API, Q G1Affine, s frontend.Variable) *G1Affine {
	// This method computes [s] Q. We use several methods to reduce the number
	// of added constraints - first, instead of classical double-and-add, we use
	// the optimized version from https://github.com/zcash/zcash/issues/3924
	// which allows to omit computation of several intermediate values.
	// Secondly, we use the GLV scalar multiplication to reduce the number
	// iterations in the main loop. There is a small difference though - as
	// two-bit select takes three constraints, then it takes as many constraints
	// to compute ± Q ± Φ(Q) every iteration instead of selecting the value
	// from a precomputed table. However, precomputing the table adds 12
	// additional constraints and thus table-version is more expensive than
	// addition-version.

	// The context we are working is based on the `outer` curve. However, the
	// points and the operations on the points are performed on the `inner`
	// curve of the outer curve. We require some parameters from the inner
	// curve.
	cc := getInnerCurveConfig(api.Compiler().Field())

	// the hints allow to decompose the scalar s into s1 and s2 such that
	//     s1 + λ * s2 == s mod r,
	// where λ is third root of one in 𝔽_r.
	sd, err := api.Compiler().NewHint(DecomposeScalarG1, 3, s)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	s1, s2 := sd[0], sd[1]

	// when we split scalar, then s1, s2 < lambda by default. However, to have
	// the high 1-2 bits of s1, s2 set, the hint functions compute the
	// decomposition for
	//     s + k*r (for some k)
	// instead and omits the last reduction. Thus, to constrain s1 and s2, we
	// have to assert that
	//     s1 + λ * s2 == s + k*r
	api.AssertIsEqual(api.Add(s1, api.Mul(s2, cc.lambda)), api.Add(s, api.Mul(cc.fr, sd[2])))

	// As the decomposed scalars are not fully reduced, then in addition of
	// having the high bit set, an overflow bit may also be set. Thus, the total
	// number of bits may be one more than the bitlength of λ.
	nbits := cc.lambda.BitLen() + 1

	s1bits := api.ToBinary(s1, nbits)
	s2bits := api.ToBinary(s2, nbits)

	var Acc /*accumulator*/, B, B2 /*tmp vars*/ G1Affine
	// precompute -Q, -Φ(Q), Φ(Q)
	var tableQ, tablePhiQ [2]G1Affine
	tableQ[1] = Q
	tableQ[0].Neg(api, Q)
	cc.phi1(api, &tablePhiQ[1], &Q)
	tablePhiQ[0].Neg(api, tablePhiQ[1])

	// We now initialize the accumulator. Due to the way the scalar is
	// decomposed, either the high bits of s1 or s2 are set and we can use the
	// incomplete addition laws.

	//     Acc = Q + Φ(Q)
	Acc = tableQ[1]
	Acc.AddAssign(api, tablePhiQ[1])

	// However, we can not directly add step value conditionally as we may get
	// to incomplete path of the addition formula. We either add or subtract
	// step value from [2] Acc (instead of conditionally adding step value to
	// Acc):
	//     Acc = [2] (Q + Φ(Q)) ± Q ± Φ(Q)
	// only y coordinate differs for negation, select on that instead.
	B.X = tableQ[0].X
	B.Y = api.Select(s1bits[nbits-1], tableQ[1].Y, tableQ[0].Y)
	Acc.DoubleAndAdd(api, &Acc, &B)
	B.X = tablePhiQ[0].X
	B.Y = api.Select(s2bits[nbits-1], tablePhiQ[1].Y, tablePhiQ[0].Y)
	Acc.AddAssign(api, B)

	// second bit
	B.X = tableQ[0].X
	B.Y = api.Select(s1bits[nbits-2], tableQ[1].Y, tableQ[0].Y)
	Acc.DoubleAndAdd(api, &Acc, &B)
	B.X = tablePhiQ[0].X
	B.Y = api.Select(s2bits[nbits-2], tablePhiQ[1].Y, tablePhiQ[0].Y)
	Acc.AddAssign(api, B)

	B2.X = tablePhiQ[0].X
	for i := nbits - 3; i > 0; i-- {
		B.X = Q.X
		B.Y = api.Select(s1bits[i], tableQ[1].Y, tableQ[0].Y)
		B2.Y = api.Select(s2bits[i], tablePhiQ[1].Y, tablePhiQ[0].Y)
		B.AddAssign(api, B2)
		Acc.DoubleAndAdd(api, &Acc, &B)
	}

	tableQ[0].AddAssign(api, Acc)
	Acc.Select(api, s1bits[0], Acc, tableQ[0])
	tablePhiQ[0].AddAssign(api, Acc)
	Acc.Select(api, s2bits[0], Acc, tablePhiQ[0])

	P.X = Acc.X
	P.Y = Acc.Y

	return P
}

// constScalarMul sets P = [s] Q and returns P.
func (P *G1Affine) constScalarMul(api frontend.API, Q G1Affine, s *big.Int) *G1Affine {
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
	table[0].AddAssign(api, negPhiQ)
	table[1] = Q
	table[1].AddAssign(api, negPhiQ)
	table[2] = negQ
	table[2].AddAssign(api, phiQ)
	table[3] = Q
	table[3].AddAssign(api, phiQ)

	Acc = table[3]
	// if both high bits are set, then we would get to the incomplete part,
	// handle it separately.
	if k[0].Bit(nbits-1) == 1 && k[1].Bit(nbits-1) == 1 {
		Acc.Double(api, Acc)
		Acc.AddAssign(api, table[3])
		nbits = nbits - 1
	}
	for i := nbits - 1; i > 0; i-- {
		Acc.DoubleAndAdd(api, &Acc, &table[k[0].Bit(i)+2*k[1].Bit(i)])
	}

	negQ.AddAssign(api, Acc)
	Acc.Select(api, k[0].Bit(0), Acc, negQ)
	negPhiQ.AddAssign(api, Acc)
	Acc.Select(api, k[1].Bit(0), Acc, negPhiQ)
	P.X, P.Y = Acc.X, Acc.Y

	return P
}

// Assign a value to self (witness assignment)
func (p *G1Jac) Assign(p1 *bls12377.G1Jac) {
	p.X = (fr.Element)(p1.X)
	p.Y = (fr.Element)(p1.Y)
	p.Z = (fr.Element)(p1.Z)
}

// AssertIsEqual constraint self to be equal to other into the given constraint system
func (p *G1Jac) AssertIsEqual(api frontend.API, other G1Jac) {
	api.AssertIsEqual(p.X, other.X)
	api.AssertIsEqual(p.Y, other.Y)
	api.AssertIsEqual(p.Z, other.Z)
}

// Assign a value to self (witness assignment)
func (p *G1Affine) Assign(p1 *bls12377.G1Affine) {
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
	x3 = api.Sub(x3, p1.X)
	x3 = api.Sub(x3, p2.X)

	// omit y3 computation
	// compute lambda2 = lambda1+2*y1/(x3-x1)
	l2 := api.DivUnchecked(api.Add(p1.Y, p1.Y), api.Sub(x3, p1.X))
	l2 = api.Add(l2, l1)

	// compute x4 =lambda2**2-x1-x3
	x4 := api.Mul(l2, l2)
	x4 = api.Sub(x4, p1.X)
	x4 = api.Sub(x4, x3)

	// compute y4 = lambda2*(x1 - x4)-y1
	y4 := api.Sub(x4, p1.X)
	y4 = api.Mul(l2, y4)
	y4 = api.Sub(y4, p1.Y)

	p.X = x4
	p.Y = y4

	return p
}

// ScalarMulBase computes s * g1 and returns it, where g1 is the fixed generator. It doesn't modify s.
func (P *G1Affine) ScalarMulBase(api frontend.API, s frontend.Variable) *G1Affine {
	_, _, g1aff, _ := bls12377.Generators()
	generator := G1Affine{
		X: g1aff.X.BigInt(new(big.Int)),
		Y: g1aff.Y.BigInt(new(big.Int)),
	}
	return P.ScalarMul(api, generator, s)
}

// P = [s]Q + [t]R using Shamir's trick
func (P *G1Affine) jointScalarMul(api frontend.API, Q, R G1Affine, s, t frontend.Variable) *G1Affine {
	cc := getInnerCurveConfig(api.Compiler().Field())

	sd, err := api.Compiler().NewHint(DecomposeScalarG1, 3, s)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	s1, s2 := sd[0], sd[1]

	td, err := api.Compiler().NewHint(DecomposeScalarG1, 3, t)
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
	// Acc = Q + R + Φ(Q) + Φ(R)
	Acc := tableS[1]
	Acc.AddAssign(api, tablePhiS[1])

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

// scalarBitsMul...
func (P *G1Affine) scalarBitsMul(api frontend.API, Q G1Affine, s1bits, s2bits []frontend.Variable, opts ...algopts.AlgebraOption) *G1Affine {
	cc := getInnerCurveConfig(api.Compiler().Field())
	nbits := cc.lambda.BitLen() + 1
	var Acc /*accumulator*/, B, B2 /*tmp vars*/ G1Affine
	// precompute -Q, -Φ(Q), Φ(Q)
	var tableQ, tablePhiQ [2]G1Affine
	tableQ[1] = Q
	tableQ[0].Neg(api, Q)
	cc.phi1(api, &tablePhiQ[1], &Q)
	tablePhiQ[0].Neg(api, tablePhiQ[1])

	// We now initialize the accumulator. Due to the way the scalar is
	// decomposed, either the high bits of s1 or s2 are set and we can use the
	// incomplete addition laws.

	//     Acc = Q + Φ(Q)
	Acc = tableQ[1]
	Acc.AddAssign(api, tablePhiQ[1])

	// However, we can not directly add step value conditionally as we may get
	// to incomplete path of the addition formula. We either add or subtract
	// step value from [2] Acc (instead of conditionally adding step value to
	// Acc):
	//     Acc = [2] (Q + Φ(Q)) ± Q ± Φ(Q)
	// only y coordinate differs for negation, select on that instead.
	B.X = tableQ[0].X
	B.Y = api.Select(s1bits[nbits-1], tableQ[1].Y, tableQ[0].Y)
	Acc.DoubleAndAdd(api, &Acc, &B)
	B.X = tablePhiQ[0].X
	B.Y = api.Select(s2bits[nbits-1], tablePhiQ[1].Y, tablePhiQ[0].Y)
	Acc.AddAssign(api, B)

	// second bit
	B.X = tableQ[0].X
	B.Y = api.Select(s1bits[nbits-2], tableQ[1].Y, tableQ[0].Y)
	Acc.DoubleAndAdd(api, &Acc, &B)
	B.X = tablePhiQ[0].X
	B.Y = api.Select(s2bits[nbits-2], tablePhiQ[1].Y, tablePhiQ[0].Y)
	Acc.AddAssign(api, B)

	B2.X = tablePhiQ[0].X
	for i := nbits - 3; i > 0; i-- {
		B.X = Q.X
		B.Y = api.Select(s1bits[i], tableQ[1].Y, tableQ[0].Y)
		B2.Y = api.Select(s2bits[i], tablePhiQ[1].Y, tablePhiQ[0].Y)
		B.AddAssign(api, B2)
		Acc.DoubleAndAdd(api, &Acc, &B)
	}

	tableQ[0].AddAssign(api, Acc)
	Acc.Select(api, s1bits[0], Acc, tableQ[0])
	tablePhiQ[0].AddAssign(api, Acc)
	Acc.Select(api, s2bits[0], Acc, tablePhiQ[0])

	P.X = Acc.X
	P.Y = Acc.Y

	return P
}
