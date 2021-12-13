package sw

import (
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/tower"
	"github.com/consensys/gnark/std/algebra/tower/fp2"
	"github.com/consensys/gnark/std/algebra/tower/fp24"
)

// G2Jac point in Jacobian coords
type G2Jac[T tower.Basis, PT tower.BasisPt[T]] struct {
	X, Y, Z T
	api     frontend.API
}

func NewG2Jac[T tower.Basis, PT tower.BasisPt[T]](api frontend.API) (G2Jac[T, PT], error) {
	var x, y, z T
	PT(&x).SetAPI(api)
	PT(&y).SetAPI(api)
	PT(&z).SetAPI(api)
	return G2Jac[T, PT]{
		X:   x,
		Y:   y,
		Z:   z,
		api: api,
	}, nil
}

type G2JacConstraint interface {
	bls12377.G2Jac | bls24315.G2Jac
}

func FromG2Jac2[T G2JacConstraint](p T) G2Jac[fp2.E2, *fp2.E2] {
	switch v := (any)(p).(type) {
	case bls12377.G2Jac:
		return G2Jac[fp2.E2, *fp2.E2]{
			X: fp2.From(v.X),
			Y: fp2.From(v.Y),
			Z: fp2.From(v.Z),
		}
	default:
		// TODO?
		panic("TODO")
	}
}

func FromG2Jac4[T G2JacConstraint](p T) G2Jac[fp24.E4, *fp24.E4] {
	switch v := (any)(p).(type) {
	case bls24315.G2Jac:
		return G2Jac[fp24.E4, *fp24.E4]{
			X: fp24.FromFp4(v.X),
			Y: fp24.FromFp4(v.Y),
			Z: fp24.FromFp4(v.Z),
		}
	default:
		// TODO?
		panic("TODO")
	}
}

func (p *G2Jac[T, PT]) Set(p1 G2Jac[T, PT]) {
	PT(&(p.X)).Set(p1.X)
	PT(&(p.Y)).Set(p1.Y)
	PT(&(p.Z)).Set(p1.Z)
}

// ToProj sets p to p1 in projective coords and return it
func (p *G2Jac[T, PT]) ToProj(p1 G2Jac[T, PT]) *G2Jac[T, PT] {
	PT(&(p.X)).Mul(p1.X, p1.Z)
	PT(&(p.Y)).Set(p1.Y)
	var t T
	PT(&t).SetAPI(p.api)
	PT(&t).Square(p1.Z)
	PT(&(p.Z)).Mul(p.Z, t)
	return p
}

// Neg outputs -p
func (p *G2Jac[T, PT]) Neg(p1 G2Jac[T, PT]) *G2Jac[T, PT] {
	PT(&(p.Y)).Neg(p1.Y)
	PT(&(p.X)).Set(p1.X)
	PT(&(p.Z)).Set(p1.Z)
	return p
}

// AddAssign adds 2 point in Jacobian coordinates
// p=p, a=p1
func (p *G2Jac[T, PT]) AddAssign(p1 G2Jac[T, PT]) *G2Jac[T, PT] {

	var Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, r, V T
	PT(&Z1Z1).SetAPI(p.api)
	PT(&Z2Z2).SetAPI(p.api)
	PT(&U1).SetAPI(p.api)
	PT(&U2).SetAPI(p.api)
	PT(&S1).SetAPI(p.api)
	PT(&S2).SetAPI(p.api)
	PT(&H).SetAPI(p.api)
	PT(&I).SetAPI(p.api)
	PT(&J).SetAPI(p.api)
	PT(&r).SetAPI(p.api)
	PT(&V).SetAPI(p.api)

	PT(&Z1Z1).Square(p1.Z)
	PT(&Z2Z2).Square(p.Z)
	PT(&U1).Mul(p1.X, Z2Z2)
	PT(&U2).Mul(p.X, Z1Z1)
	PT(&S1).Mul(p1.Y, p.Z)
	PT(&S1).Mul(S1, Z2Z2)
	PT(&S2).Mul(p.Y, p1.Z)
	PT(&S2).Mul(S2, Z1Z1)
	PT(&H).Sub(U2, U1)
	PT(&I).Add(H, H)
	PT(&I).Square(I)
	PT(&J).Mul(H, I)
	PT(&r).Sub(S2, S1)
	PT(&r).Add(r, r)
	PT(&V).Mul(U1, I)
	PT(&(p.X)).Square(r)
	PT(&(p.X)).Sub(p.X, J)
	PT(&(p.X)).Sub(p.X, V)
	PT(&(p.X)).Sub(p.X, V)
	PT(&(p.Y)).Sub(V, p.X)
	PT(&(p.Y)).Mul(p.Y, r)
	PT(&S1).Mul(J, S1)
	PT(&S1).Add(S1, S1)
	PT(&(p.Y)).Sub(p.Y, S1)
	PT(&(p.Z)).Add(p.Z, p1.Z)
	PT(&(p.Z)).Square(p.Z)
	PT(&(p.Z)).Sub(p.Z, Z1Z1)
	PT(&(p.Z)).Sub(p.Z, Z2Z2)
	PT(&(p.Z)).Mul(p.Z, H)

	return p
}

// Double doubles a point in jacobian coords
func (p *G2Jac[T, PT]) Double() *G2Jac[T, PT] {

	var XX, YY, YYYY, ZZ, S, M, W T
	PT(&XX).SetAPI(p.api)
	PT(&YY).SetAPI(p.api)
	PT(&YYYY).SetAPI(p.api)
	PT(&ZZ).SetAPI(p.api)
	PT(&S).SetAPI(p.api)
	PT(&M).SetAPI(p.api)
	PT(&W).SetAPI(p.api)

	PT(&XX).Square(p.X)
	PT(&YY).Square(p.Y)
	PT(&YYYY).Square(YY)
	PT(&ZZ).Square(p.Z)
	PT(&S).Add(p.X, YY)
	PT(&S).Square(S)
	PT(&S).Sub(S, XX)
	PT(&S).Sub(S, YYYY)
	PT(&S).Add(S, S)
	PT(&M).MulByFp(XX, 3) // M = 3*XX+a*ZZ^2, here a=0 (we suppose sw has j invariant 0)
	PT(&(p.Z)).Add(p.Z, p.Y)
	PT(&(p.Z)).Square(p.Z)
	PT(&(p.Z)).Sub(p.Z, YY)
	PT(&(p.Z)).Sub(p.Z, ZZ)
	PT(&(p.X)).Square(M)
	PT(&W).Add(S, S)
	PT(&(p.X)).Sub(p.X, W)
	PT(&(p.Y)).Sub(S, p.X)
	PT(&(p.Y)).Mul(p.Y, M)
	PT(&YYYY).MulByFp(YYYY, 8)
	PT(&(p.Y)).Sub(p.Y, YYYY)

	return p
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (p *G2Jac[T, PT]) MustBeEqual(other G2Jac[T, PT]) {
	PT(&(p.X)).MustBeEqual(other.X)
	PT(&(p.Y)).MustBeEqual(other.Y)
	PT(&(p.Z)).MustBeEqual(other.Z)
}
