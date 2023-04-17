package sw_bn254

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

type G2 struct {
	*fields_bn254.Ext2
}

type G2Affine struct {
	X, Y fields_bn254.E2
}

func NewG2(api frontend.API) G2 {
	return G2{
		Ext2: fields_bn254.NewExt2(api),
	}
}

func NewG2Affine(v bn254.G2Affine) G2Affine {
	return G2Affine{
		X: fields_bn254.E2{
			A0: emulated.ValueOf[emulated.BN254Fp](v.X.A0),
			A1: emulated.ValueOf[emulated.BN254Fp](v.X.A1),
		},
		Y: fields_bn254.E2{
			A0: emulated.ValueOf[emulated.BN254Fp](v.Y.A0),
			A1: emulated.ValueOf[emulated.BN254Fp](v.Y.A1),
		},
	}
}

func (g2 *G2) phi(q *G2Affine) *G2Affine {
	w := emulated.ValueOf[emulated.BN254Fp]("21888242871839275220042445260109153167277707414472061641714758635765020556616")

	var phiq G2Affine
	phiq.X = *g2.Ext2.MulByElement(&q.X, &w)
	phiq.Y = q.Y

	return &phiq
}

func (g2 *G2) psi(q *G2Affine) *G2Affine {
	u := fields_bn254.E2{
		A0: emulated.ValueOf[emulated.BN254Fp]("21575463638280843010398324269430826099269044274347216827212613867836435027261"),
		A1: emulated.ValueOf[emulated.BN254Fp]("10307601595873709700152284273816112264069230130616436755625194854815875713954"),
	}
	v := fields_bn254.E2{
		A0: emulated.ValueOf[emulated.BN254Fp]("2821565182194536844548159561693502659359617185244120367078079554186484126554"),
		A1: emulated.ValueOf[emulated.BN254Fp]("3505843767911556378687030309984248845540243509899259641013678093033130930403"),
	}

	var psiq G2Affine
	psiq.X = *g2.Ext2.Conjugate(&q.X)
	psiq.X = *g2.Ext2.Mul(&psiq.X, &u)
	psiq.Y = *g2.Ext2.Conjugate(&q.Y)
	psiq.Y = *g2.Ext2.Mul(&psiq.Y, &v)

	return &psiq
}

func (g2 *G2) scalarMulBySeed(q *G2Affine) *G2Affine {

	qNeg := g2.neg(q)
	seed := [63]int8{1, 0, 0, 0, -1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, -1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, -1, 0, -1, 0, -1, 0, 1, 0, 1, 0, 0, -1, 0, 1, 0, 1, 0, -1, 0, 0, 1, 0, 1, 0, 0, 0, 1}

	// i = 62
	res := q

	for i := 61; i >= 0; i-- {
		switch seed[i] {
		case 0:
			res = g2.double(res)
		case 1:
			res = g2.doubleAndAdd(res, q)
		case -1:
			res = g2.doubleAndAdd(res, qNeg)
		}
	}

	return res
}

func (g2 G2) add(p, q *G2Affine) *G2Affine {
	// compute λ = (q.y-p.y)/(q.x-p.x)
	qypy := g2.Ext2.Sub(&q.Y, &p.Y)
	qxpx := g2.Ext2.Sub(&q.X, &p.X)
	λ := g2.Ext2.DivUnchecked(qypy, qxpx)

	// xr = λ²-p.x-q.x
	λλ := g2.Ext2.Square(λ)
	qxpx = g2.Ext2.Add(&p.X, &q.X)
	xr := g2.Ext2.Sub(λλ, qxpx)

	// p.y = λ(p.x-r.x) - p.y
	pxrx := g2.Ext2.Sub(&p.X, xr)
	λpxrx := g2.Ext2.Mul(λ, pxrx)
	yr := g2.Ext2.Sub(λpxrx, &p.Y)

	return &G2Affine{
		X: *xr,
		Y: *yr,
	}
}

func (g2 G2) neg(p *G2Affine) *G2Affine {
	xr := &p.X
	yr := g2.Ext2.Neg(&p.Y)
	return &G2Affine{
		X: *xr,
		Y: *yr,
	}
}

func (g2 G2) sub(p, q *G2Affine) *G2Affine {
	qNeg := g2.neg(q)
	return g2.add(p, qNeg)
}

func (g2 *G2) double(p *G2Affine) *G2Affine {
	// compute λ = (3p.x²)/2*p.y
	xx3a := g2.Square(&p.X)
	xx3a = g2.MulByConstElement(xx3a, big.NewInt(3))
	y2 := g2.Double(&p.Y)
	λ := g2.DivUnchecked(xx3a, y2)

	// xr = λ²-2p.x
	x2 := g2.Double(&p.X)
	λλ := g2.Square(λ)
	xr := g2.Sub(λλ, x2)

	// yr = λ(p-xr) - p.y
	pxrx := g2.Sub(&p.X, xr)
	λpxrx := g2.Mul(λ, pxrx)
	yr := g2.Sub(λpxrx, &p.Y)

	return &G2Affine{
		X: *xr,
		Y: *yr,
	}
}

func (g2 G2) doubleAndAdd(p, q *G2Affine) *G2Affine {

	// compute λ1 = (q.y-p.y)/(q.x-p.x)
	yqyp := g2.Ext2.Sub(&q.Y, &p.Y)
	xqxp := g2.Ext2.Sub(&q.X, &p.X)
	λ1 := g2.Ext2.DivUnchecked(yqyp, xqxp)

	// compute x2 = λ1²-p.x-q.x
	λ1λ1 := g2.Ext2.Square(λ1)
	xqxp = g2.Ext2.Add(&p.X, &q.X)
	x2 := g2.Ext2.Sub(λ1λ1, xqxp)

	// ommit y2 computation
	// compute λ2 = -λ1-2*p.y/(x2-p.x)
	ypyp := g2.Ext2.Add(&p.Y, &p.Y)
	x2xp := g2.Ext2.Sub(x2, &p.X)
	λ2 := g2.Ext2.DivUnchecked(ypyp, x2xp)
	λ2 = g2.Ext2.Add(λ1, λ2)
	λ2 = g2.Ext2.Neg(λ2)

	// compute x3 =λ2²-p.x-x3
	λ2λ2 := g2.Ext2.Square(λ2)
	x3 := g2.Ext2.Sub(λ2λ2, &p.X)
	x3 = g2.Ext2.Sub(x3, x2)

	// compute y3 = λ2*(p.x - x3)-p.y
	y3 := g2.Ext2.Sub(&p.X, x3)
	y3 = g2.Ext2.Mul(λ2, y3)
	y3 = g2.Ext2.Sub(y3, &p.Y)

	return &G2Affine{
		X: *x3,
		Y: *y3,
	}
}

// AssertIsEqual asserts that p and q are the same point.
func (g2 *G2) AssertIsEqual(p, q *G2Affine) {
	g2.Ext2.AssertIsEqual(&p.X, &q.X)
	g2.Ext2.AssertIsEqual(&p.Y, &q.Y)
}
