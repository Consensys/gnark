package sw

import (
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/tower"
	"github.com/consensys/gnark/std/algebra/tower/fp2"
	"github.com/consensys/gnark/std/algebra/tower/fp24"
)

// G2Affine point in affine coords
type G2Affine[T tower.Basis, PT tower.BasisPt[T]] struct {
	X, Y T
	api  frontend.API
}

func NewG2Affine[T tower.Basis, PT tower.BasisPt[T]](api frontend.API) (G2Affine[T, PT], error) {
	var x, y T
	PT(&x).SetAPI(api)
	PT(&y).SetAPI(api)
	return G2Affine[T, PT]{
		X:   x,
		Y:   y,
		api: api,
	}, nil
}

type G2AffineConstraint interface {
	bls12377.G2Affine | bls24315.G2Affine
}

func FromG2Affine[TT tower.Basis, PTT tower.BasisPt[TT], T G2AffineConstraint](p T) G2Affine[TT, PTT] {
	var ret G2Affine[TT, PTT]
	switch v := (any)(p).(type) {
	case bls12377.G2Affine:
		retp, ok := (any)(&ret).(*G2Affine[fp2.E2])
		if !ok {
			panic("incompatible function type parameters")
		}
		retp.X = fp2.From(v.X)
		retp.Y = fp2.From(v.Y)
	case bls24315.G2Affine:
		retp, ok := (any)(&ret).(*G2Affine[fp24.E4])
		if !ok {
			panic("incompatible function type parameters")
		}
		retp.X = fp24.FromFp4(v.X)
		retp.Y = fp24.FromFp4(v.Y)
	}
	return ret
}

func (p *G2Affine[T, PT]) Set(p1 G2Affine[T, PT]) {
	PT(&(p.X)).Set(p1.X)
	PT(&(p.Y)).Set(p1.Y)
}

// Neg outputs -p
func (p *G2Affine[T, PT]) Neg(p1 G2Affine[T, PT]) *G2Affine[T, PT] {
	PT(&(p.Y)).Neg(p1.Y)
	PT(&(p.X)).Set(p1.X)
	return p
}

// AddAssign add p1 to p and return p
func (p *G2Affine[T, PT]) AddAssign(p1 G2Affine[T, PT]) *G2Affine[T, PT] {

	var n, d, l, xr, yr T
	PT(&n).SetAPI(p.api)
	PT(&d).SetAPI(p.api)
	PT(&l).SetAPI(p.api)
	PT(&xr).SetAPI(p.api)
	PT(&yr).SetAPI(p.api)

	// compute lambda = (p1.y-p.y)/(p1.x-p.x)
	PT(&n).Sub(p1.Y, p.Y)
	PT(&d).Sub(p1.X, p.X)
	PT(&l).Inverse(d)
	PT(&l).Mul(l, n)

	// xr =lambda**2-p1.x-p.x
	PT(&xr).Square(l)
	PT(&xr).Sub(xr, p1.X)
	PT(&xr).Sub(xr, p.X)

	// yr = lambda(p.x - xr)-p.y
	PT(&yr).Sub(p.X, xr)
	PT(&yr).Mul(l, yr)
	PT(&yr).Sub(yr, p.Y)

	PT(&(p.X)).Set(xr)
	PT(&(p.Y)).Set(yr)

	return p
}

// Double compute 2*p1, assign the result to p and return it
// Only for curve with j invariant 0 (a=0).
func (p *G2Affine[T, PT]) Double(p1 G2Affine[T, PT]) *G2Affine[T, PT] {

	var n, d, l, xr, yr T
	PT(&n).SetAPI(p.api)
	PT(&d).SetAPI(p.api)
	PT(&l).SetAPI(p.api)
	PT(&xr).SetAPI(p.api)
	PT(&yr).SetAPI(p.api)

	// lambda = 3*p1.x**2/2*p.y
	PT(&n).Square(p1.X)
	PT(&n).MulByFp(n, 3)
	PT(&d).MulByFp(p1.Y, 2)
	PT(&l).Inverse(d)
	PT(&l).Mul(l, n)

	// xr = lambda**2-2*p1.x
	PT(&xr).Square(l)
	PT(&xr).Sub(xr, p1.X)
	PT(&xr).Sub(xr, p1.X)

	// yr = lambda*(p.x-xr)-p.y
	PT(&yr).Sub(p1.X, xr)
	PT(&yr).Mul(l, yr)
	PT(&yr).Sub(yr, p1.Y)

	PT(&(p.X)).Set(xr)
	PT(&(p.Y)).Set(yr)

	return p

}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (p *G2Affine[T, PT]) MustBeEqual(other G2Affine[T, PT]) {
	PT(&(p.X)).MustBeEqual(other.X)
	PT(&(p.Y)).MustBeEqual(other.Y)
}

// DoubleAndAdd computes 2*p1+p2 in affine coords
func (p *G2Affine[T, PT]) DoubleAndAdd(p1, p2 G2Affine[T, PT]) *G2Affine[T, PT] {

	var n, d, l1, l2, x3, x4, y4 T
	PT(&n).SetAPI(p.api)
	PT(&d).SetAPI(p.api)
	PT(&l1).SetAPI(p.api)
	PT(&l2).SetAPI(p.api)
	PT(&x3).SetAPI(p.api)
	PT(&x4).SetAPI(p.api)
	PT(&y4).SetAPI(p.api)

	// compute lambda1 = (y2-y1)/(x2-x1)
	PT(&n).Sub(p1.Y, p2.Y)
	PT(&d).Sub(p1.X, p2.X)
	PT(&l1).Inverse(d)
	PT(&l1).Mul(l1, n)

	// compute x3 = lambda1**2-x1-x2
	PT(&x3).Square(l1)
	PT(&x3).Sub(x3, p1.X)
	PT(&x3).Sub(x3, p2.X)

	// omit y3 computation
	// compute lambda2 = -lambda1-2*y1/(x3-x1)
	PT(&n).Double(p1.Y)
	PT(&d).Sub(x3, p1.X)
	PT(&l2).Inverse(d)
	PT(&l2).Mul(l2, n)
	PT(&l2).Add(l2, l1)
	PT(&l2).Neg(l2)

	// compute x4 =lambda2**2-x1-x3
	PT(&x4).Square(l2)
	PT(&x4).Sub(x4, p1.X)
	PT(&x4).Sub(x4, x3)

	// compute y4 = lambda2*(x1 - x4)-y1
	PT(&y4).Sub(p1.X, x4)
	PT(&y4).Mul(l2, y4)
	PT(&y4).Sub(y4, p1.Y)

	PT(&(p.X)).Set(x4)
	PT(&(p.Y)).Set(y4)

	return p
}
