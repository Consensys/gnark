package sw

import (
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	bw6633fr "github.com/consensys/gnark-crypto/ecc/bw6-633/fr"
	bw6761fr "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/frontend"
)

// G1Jac point in Jacobian coords
type G1Jac struct {
	X, Y, Z frontend.Variable
	api     frontend.API
}

func NewG1Jac(api frontend.API) (G1Jac, error) {
	// TODO: set zero
	return G1Jac{
		api: api,
	}, nil
}

type G1JacConstraint interface {
	bls12377.G1Jac | bls24315.G1Jac
}

func FromG1Jac[T G1JacConstraint](p T) G1Jac {
	var x, y, z frontend.Variable
	var err error
	switch v := (any)(p).(type) {
	case bls12377.G1Jac:
		x, y, z = bw6761fr.Element(v.X), bw6761fr.Element(v.Y), bw6761fr.Element(v.Z)
	case bls24315.G1Jac:
		x, y, z = bw6633fr.Element(v.X), bw6633fr.Element(v.Y), bw6633fr.Element(v.Z)
	}
	if err != nil {
		panic("incompatible")
	}
	return G1Jac{
		X: x,
		Y: y,
		Z: z,
	}
}

func (p *G1Jac) Set(p1 G1Jac) {
	p.X = p1.X
	p.Y = p1.Y
	p.Z = p1.Z
}

// Neg outputs -p
func (p *G1Jac) Neg(p1 G1Jac) *G1Jac {
	api := p.api
	p.X = p1.X
	p.Y = api.Sub(0, p1.Y)
	p.Z = p1.Z
	return p
}

// AddAssign adds 2 point in Jacobian coordinates
// p=p, a=p1
func (p *G1Jac) AddAssign(p1 G1Jac) *G1Jac {
	api := p.api

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
	M = api.Mul(XX, 3) // M = 3*XX+a*ZZ^2, here a=0 (we suppose sw has j invariant 0)
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

// MustBeEqual constraint self to be equal to other into the given constraint system
func (p *G1Jac) MustBeEqual(other G1Jac) {
	api := p.api
	api.AssertIsEqual(p.X, other.X)
	api.AssertIsEqual(p.Y, other.Y)
	api.AssertIsEqual(p.Z, other.Z)
}
