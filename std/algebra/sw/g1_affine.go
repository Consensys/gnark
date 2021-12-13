package sw

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	bw6633fr "github.com/consensys/gnark-crypto/ecc/bw6-633/fr"
	bw6761fr "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/frontend"
)

// G1Affine point in affine coords
type G1Affine struct {
	X, Y frontend.Variable
	api  frontend.API
	// config is the context of `inner` curve. The context we are working is based
	// on the `outer` curve. However, the points and the operations on the
	// points are performed on the `inner` curve of the outer curve. We require
	// some parameters from the inner curve.
	config *innerConfig
}

func NewG1Affine(api frontend.API) (G1Affine, error) {
	glv, err := getInnerConfig(api.Curve())
	if err != nil {
		return G1Affine{}, fmt.Errorf("get GLV config: %w", err)
	}
	// TODO: set zero
	return G1Affine{
		api:    api,
		config: glv,
	}, nil
}

type G1AffineConstraint interface {
	bls12377.G1Affine | bls24315.G1Affine
}

func FromG1Affine[T G1AffineConstraint](p T) G1Affine {
	var x, y frontend.Variable
	var err error
	var glv *innerConfig
	switch v := (any)(p).(type) {
	case bls12377.G1Affine:
		glv, err = getInnerConfig(ecc.BW6_761)
		x, y = bw6761fr.Element(v.X), bw6761fr.Element(v.Y)
	case bls24315.G1Affine:
		glv, err = getInnerConfig(ecc.BW6_633)
		x, y = bw6633fr.Element(v.X), bw6633fr.Element(v.Y)
	}
	if err != nil {
		panic("incompatible")
	}
	return G1Affine{
		X:      x,
		Y:      y,
		config: glv,
	}
}

func (p *G1Affine) Set(p1 G1Affine) {
	p.X = p1.X
	p.Y = p1.Y
}

// Neg outputs -p
func (p *G1Affine) Neg(p1 G1Affine) *G1Affine {
	api := p.api
	p.X = p1.X
	p.Y = api.Sub(0, p1.Y)
	return p
}

// AddAssign adds p1 to p using the affine formulas with division, and return p
func (p *G1Affine) AddAssign(p1 G1Affine) *G1Affine {
	api := p.api

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
func (p *G1Affine) Select(b frontend.Variable, p1, p2 G1Affine) *G1Affine {
	api := p.api

	p.X = api.Select(b, p1.X, p2.X)
	p.Y = api.Select(b, p1.Y, p2.Y)

	return p

}

// FromJac sets p to p1 in affine and returns it
func (p *G1Affine) FromJac(p1 G1Jac) *G1Affine {
	api := p.api
	s := api.Mul(p1.Z, p1.Z)
	p.X = api.DivUnchecked(p1.X, s)
	p.Y = api.DivUnchecked(p1.Y, api.Mul(s, p1.Z))
	return p
}

// Double double a point in affine coords
func (p *G1Affine) Double(p1 G1Affine) *G1Affine {
	api := p.api

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
func (P *G1Affine) ScalarMul(Q G1Affine, s interface{}) *G1Affine {
	api := P.api
	if api.IsConstant(s) {
		return P.constScalarMul(Q, api.ConstantValue(s))
	} else {
		return P.varScalarMul(Q, s)
	}
}

// varScalarMul sets P = [s] Q and returns P.
func (P *G1Affine) varScalarMul(Q G1Affine, s frontend.Variable) *G1Affine {
	api := P.api
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

	// the hints allow to decompose the scalar s into s1 and s2 such that
	//     s1 + λ * s2 == s mod r,
	// where λ is third root of one in 𝔽_r.
	sd, err := api.NewHint(P.config.decompose, s)
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
	api.AssertIsEqual(api.Add(s1, api.Mul(s2, P.config.lambda)), api.Add(s, api.Mul(P.config.fr, sd[2])))

	// As the decomposed scalars are not fully reduced, then in addition of
	// having the high bit set, an overflow bit may also be set. Thus, the total
	// number of bits may be one more than the bitlength of λ.
	nbits := P.config.lambda.BitLen() + 1

	s1bits := api.ToBinary(s1, nbits)
	s2bits := api.ToBinary(s2, nbits)

	Acc, err := NewG1Affine(P.api)
	if err != nil {
		panic("incompatible api")
	}
	B, err := NewG1Affine(P.api)
	if err != nil {
		panic("incompatible api")
	}
	B2, err := NewG1Affine(P.api)
	if err != nil {
		panic("incompatible api")
	}

	// precompute -Q, -Φ(Q), Φ(Q)
	var tableQ, tablePhiQ [2]G1Affine
	for i := range tableQ {
		tableQ[i], err = NewG1Affine(P.api)
		if err != nil {
			panic("incompatible api")
		}
	}
	for i := range tablePhiQ {
		tablePhiQ[i], err = NewG1Affine(P.api)
		if err != nil {
			panic("incompatible api")
		}
	}

	tableQ[1] = Q
	tableQ[0].Neg(Q)
	P.phi(&tablePhiQ[1], &Q)
	tablePhiQ[0].Neg(tablePhiQ[1])

	// We now initialize the accumulator. Due to the way the scalar is
	// decomposed, either the high bits of s1 or s2 are set and we can use the
	// incomplete addition laws.

	//     Acc = Q + Φ(Q)
	Acc.Set(tableQ[1])
	Acc.AddAssign(tablePhiQ[1])

	// However, we can not directly add step value conditionally as we may get
	// to incomplete path of the addition formula. We either add or subtract
	// step value from [2] Acc (instead of conditionally adding step value to
	// Acc):
	//     Acc = [2] (Q + Φ(Q)) ± Q ± Φ(Q)
	Acc.Double(Acc)
	// only y coordinate differs for negation, select on that instead.
	B.X = tableQ[0].X
	B.Y = api.Select(s1bits[nbits-1], tableQ[1].Y, tableQ[0].Y)
	Acc.AddAssign(B)
	B.X = tablePhiQ[0].X
	B.Y = api.Select(s2bits[nbits-1], tablePhiQ[1].Y, tablePhiQ[0].Y)
	Acc.AddAssign(B)

	// second bit
	Acc.Double(Acc)
	B.X = tableQ[0].X
	B.Y = api.Select(s1bits[nbits-2], tableQ[1].Y, tableQ[0].Y)
	Acc.AddAssign(B)
	B.X = tablePhiQ[0].X
	B.Y = api.Select(s2bits[nbits-2], tablePhiQ[1].Y, tablePhiQ[0].Y)
	Acc.AddAssign(B)

	B2.X = tablePhiQ[0].X
	for i := nbits - 3; i > 0; i-- {
		B.X = Q.X
		B.Y = api.Select(s1bits[i], tableQ[1].Y, tableQ[0].Y)
		B2.Y = api.Select(s2bits[i], tablePhiQ[1].Y, tablePhiQ[0].Y)
		B.AddAssign(B2)
		Acc.DoubleAndAdd(&Acc, &B)
	}

	tableQ[0].AddAssign(Acc)
	Acc.Select(s1bits[0], Acc, tableQ[0])
	tablePhiQ[0].AddAssign(Acc)
	Acc.Select(s2bits[0], Acc, tablePhiQ[0])

	P.Set(Acc)

	return P
}

// constScalarMul sets P = [s] Q and returns P.
func (P *G1Affine) constScalarMul(Q1 G1Affine, s *big.Int) *G1Affine {
	api := P.api
	// see the comments in varScalarMul. However, two-bit lookup is cheaper if
	// bits are constant and here it makes sense to use the table in the main
	// loop.
	// var Acc, B, negQ, negPhiQ, phiQ G1Affine
	Acc, err := NewG1Affine(P.api)
	if err != nil {
		panic("incompatible api")
	}
	B, err := NewG1Affine(P.api)
	if err != nil {
		panic("incompatible api")
	}
	Q, err := NewG1Affine(P.api)
	if err != nil {
		panic("incompatible api")
	}
	negQ, err := NewG1Affine(P.api)
	if err != nil {
		panic("incompatible api")
	}
	negPhiQ, err := NewG1Affine(P.api)
	if err != nil {
		panic("incompatible api")
	}
	phiQ, err := NewG1Affine(P.api)
	if err != nil {
		panic("incompatible api")
	}
	Q.Set(Q1)

	s.Mod(s, P.config.fr)
	P.phi(&phiQ, &Q)

	k := ecc.SplitScalar(s, P.config.glvBasis)
	if k[0].Sign() == -1 {
		k[0].Neg(&k[0])
		Q.Neg(Q)
	}
	if k[1].Sign() == -1 {
		k[1].Neg(&k[1])
		phiQ.Neg(phiQ)
	}
	nbits := k[0].BitLen()
	if k[1].BitLen() > nbits {
		nbits = k[1].BitLen()
	}
	negQ.Neg(Q)
	negPhiQ.Neg(phiQ)
	var table [4]G1Affine
	table[0] = negQ
	table[0].AddAssign(negPhiQ)
	table[1] = Q
	table[1].AddAssign(negPhiQ)
	table[2] = negQ
	table[2].AddAssign(phiQ)
	table[3] = Q
	table[3].AddAssign(phiQ)

	Acc = table[3]
	// if both high bits are set, then we would get to the incomplete part,
	// handle it separately.
	if k[0].Bit(nbits-1) == 1 && k[1].Bit(nbits-1) == 1 {
		Acc.Double(Acc)
		Acc.AddAssign(table[3])
		nbits = nbits - 1
	}
	for i := nbits - 1; i > 0; i-- {
		B.X = api.Lookup2(k[0].Bit(i), k[1].Bit(i), table[0].X, table[1].X, table[2].X, table[3].X)
		B.Y = api.Lookup2(k[0].Bit(i), k[1].Bit(i), table[0].Y, table[1].Y, table[2].Y, table[3].Y)
		Acc.DoubleAndAdd(&Acc, &B)
	}

	negQ.AddAssign(Acc)
	Acc.Select(k[0].Bit(0), Acc, negQ)
	negPhiQ.AddAssign(Acc)
	Acc.Select(k[1].Bit(0), Acc, negPhiQ)
	P.X, P.Y = Acc.X, Acc.Y

	return P
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (p *G1Affine) MustBeEqual(other G1Affine) {
	api := p.api
	api.AssertIsEqual(p.X, other.X)
	api.AssertIsEqual(p.Y, other.Y)
}

// DoubleAndAdd computes 2*p1+p in affine coords
func (p *G1Affine) DoubleAndAdd(p1, p2 *G1Affine) *G1Affine {
	api := p.api

	// compute lambda1 = (y2-y1)/(x2-x1)
	l1 := api.DivUnchecked(api.Sub(p1.Y, p2.Y), api.Sub(p1.X, p2.X))

	// compute x3 = lambda1**2-x1-x2
	x3 := api.Mul(l1, l1)
	x3 = api.Sub(x3, p1.X)
	x3 = api.Sub(x3, p2.X)

	// omit y3 computation
	// compute lambda2 = -lambda1-2*y1/(x3-x1)
	l2 := api.DivUnchecked(api.Add(p1.Y, p1.Y), api.Sub(x3, p1.X))
	l2 = api.Add(l2, l1)
	l2 = api.Neg(l2)

	// compute x4 =lambda2**2-x1-x3
	x4 := api.Mul(l2, l2)
	x4 = api.Sub(x4, p1.X)
	x4 = api.Sub(x4, x3)

	// compute y4 = lambda2*(x1 - x4)-y1
	y4 := api.Sub(p1.X, x4)
	y4 = api.Mul(l2, y4)
	y4 = api.Sub(y4, p1.Y)

	p.X = x4
	p.Y = y4

	return p
}
