package sw_bls12377

import (
	"fmt"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/fields_bls12377"
)

type Curve struct {
	api frontend.API
}

func NewCurve(api frontend.API) *Curve {
	return &Curve{
		api: api,
	}
}

func (c *Curve) Add(P, Q *G1Affine) *G1Affine {
	res := &G1Affine{
		X: P.X,
		Y: P.Y,
	}
	res.AddAssign(c.api, *Q)
	return res
}

func (c *Curve) AssertIsEqual(P, Q *G1Affine) {
	P.AssertIsEqual(c.api, *Q)
	panic("todo")
}

func (c *Curve) Neg(P *G1Affine) *G1Affine {
	res := &G1Affine{
		X: P.X,
		Y: P.Y,
	}
	res.Neg(c.api, *P)
	return res
}

func (c *Curve) ScalarMul(P *G1Affine, scalar *frontend.Variable) *G1Affine {
	res := &G1Affine{
		X: P.X,
		Y: P.Y,
	}
	res.ScalarMul(c.api, *P, *scalar)
	return res
}

func (c *Curve) ScalarMulBase(scalar *frontend.Variable) *G1Affine {
	res := new(G1Affine)
	res.ScalarMulBase(c.api, *scalar)
	return res
}

func (c *Curve) MultiScalarMul(P []*G1Affine, scalars []*frontend.Variable) (*G1Affine, error) {
	if len(P) != len(scalars) {
		return nil, fmt.Errorf("mismatching points and scalars slice lengths")
	}
	if len(P) == 0 {
		return &G1Affine{
			X: 0,
			Y: 0,
		}, nil
	}
	res := c.ScalarMul(P[0], scalars[0])
	for i := 1; i < len(P); i++ {
		q := c.ScalarMul(P[i], scalars[i])
		c.Add(res, q)
	}
	return res, nil
}

type Pairing struct {
	api frontend.API
}

func NewPairing(api frontend.API) *Pairing {
	return &Pairing{
		api: api,
	}
}

func (p *Pairing) MillerLoop(P []*G1Affine, Q []*G2Affine) (*GT, error) {
	inP := make([]G1Affine, len(P))
	for i := range P {
		inP[i] = *P[i]
	}
	inQ := make([]G2Affine, len(Q))
	for i := range Q {
		inQ[i] = *Q[i]
	}
	res, err := MillerLoop(p.api, inP, inQ)
	return &res, err
}

func (p *Pairing) FinalExponentiation(e *GT) *GT {
	res := FinalExponentiation(p.api, *e)
	return &res
}

func (p *Pairing) Pair(P []*G1Affine, Q []*G2Affine) (*GT, error) {
	inP := make([]G1Affine, len(P))
	for i := range P {
		inP[i] = *P[i]
	}
	inQ := make([]G2Affine, len(Q))
	for i := range Q {
		inQ[i] = *Q[i]
	}
	res, err := Pair(p.api, inP, inQ)
	return &res, err
}

func (p *Pairing) PairingCheck(P []*G1Affine, Q []*G2Affine) error {
	inP := make([]G1Affine, len(P))
	for i := range P {
		inP[i] = *P[i]
	}
	inQ := make([]G2Affine, len(Q))
	for i := range Q {
		inQ[i] = *Q[i]
	}
	res, err := Pair(p.api, inP, inQ)
	if err != nil {
		return err
	}
	var one fields_bls12377.E12
	one.SetOne()
	res.AssertIsEqual(p.api, one)
	return nil
}

func (p *Pairing) AssertIsEqual(e1, e2 *GT) {
	e1.AssertIsEqual(p.api, *e2)
}

func NewG1Affine(v bls12377.G1Affine) G1Affine {
	return G1Affine{
		X: (fr_bw6761.Element)(v.X),
		Y: (fr_bw6761.Element)(v.Y),
	}
}

func NewG2Affine(v bls12377.G2Affine) G2Affine {
	return G2Affine{
		X: fields_bls12377.E2{
			A0: (fr_bw6761.Element)(v.X.A0),
			A1: (fr_bw6761.Element)(v.X.A1),
		},
		Y: fields_bls12377.E2{
			A0: (fr_bw6761.Element)(v.Y.A0),
			A1: (fr_bw6761.Element)(v.Y.A1),
		},
	}
}
