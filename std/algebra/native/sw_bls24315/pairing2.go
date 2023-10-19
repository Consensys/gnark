package sw_bls24315

import (
	"fmt"

	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	fr_bw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/fields_bls24315"
)

// Curve allows G1 operations in BLS24-315.
type Curve struct {
	api frontend.API
}

// NewCurve initializes a new [Curve] instance.
func NewCurve(api frontend.API) *Curve {
	return &Curve{
		api: api,
	}
}

// Add points P and Q and return the result. Does not modify the inputs.
func (c *Curve) Add(P, Q *G1Affine) *G1Affine {
	res := &G1Affine{
		X: P.X,
		Y: P.Y,
	}
	res.AddAssign(c.api, *Q)
	return res
}

// AssertIsEqual asserts the equality of P and Q.
func (c *Curve) AssertIsEqual(P, Q *G1Affine) {
	P.AssertIsEqual(c.api, *Q)
	panic("todo")
}

// Neg negates P and returns the result. Does not modify P.
func (c *Curve) Neg(P *G1Affine) *G1Affine {
	res := &G1Affine{
		X: P.X,
		Y: P.Y,
	}
	res.Neg(c.api, *P)
	return res
}

// ScalarMul computes scalar*P and returns the result. It doesn't modify the
// inputs.
func (c *Curve) ScalarMul(P *G1Affine, scalar *Scalar) *G1Affine {
	res := &G1Affine{
		X: P.X,
		Y: P.Y,
	}
	res.ScalarMul(c.api, *P, *scalar)
	return res
}

// ScalarMulBase computes scalar*G where G is the standard base point of the
// curve. It doesn't modify the scalar.
func (c *Curve) ScalarMulBase(scalar *Scalar) *G1Affine {
	res := new(G1Affine)
	res.ScalarMulBase(c.api, *scalar)
	return res
}

// MultiScalarMul computes ∑scalars_i * P_i and returns it. It doesn't modify
// the inputs. It returns an error if there is a mismatch in the lengths of the
// inputs.
func (c *Curve) MultiScalarMul(P []*G1Affine, scalars []*Scalar) (*G1Affine, error) {
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

// Pairing allows computing pairing-related operations in BLS24-315.
type Pairing struct {
	api frontend.API
}

// NewPairing initializes a [Pairing] instance.
func NewPairing(api frontend.API) *Pairing {
	return &Pairing{
		api: api,
	}
}

// MillerLoop computes the Miller loop between the pairs of inputs. It doesn't
// modify the inputs. It returns an error if there is a mismatch betwen the
// lengths of the inputs.
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

// FinalExponentiation performs the final exponentiation on the target group
// element. It doesn't modify the input.
func (p *Pairing) FinalExponentiation(e *GT) *GT {
	res := FinalExponentiation(p.api, *e)
	return &res
}

// Pair computes a full multi-pairing on the input pairs.
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

// PairingCheck computes the multi-pairing of the input pairs and asserts that
// the result is an identity element in the target group. It returns an error if
// there is a mismatch between the lengths of the inputs.
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
	var one fields_bls24315.E24
	one.SetOne()
	res.AssertIsEqual(p.api, one)
	return nil
}

// DoublePairingFixedQCheck computes the multi-pairing of size 2 where one of
// the inputs is the fixed canonical generatortor of G2Affine and asserts that
// the result is an identity element in the target group. It returns an error
// if there is a mismatch between the lengths of the inputs.
func (p *Pairing) DoublePairingFixedQCheck(P [2]*G1Affine, Q *G2Affine) error {
	var inP [2]G1Affine
	for i := range P {
		inP[i] = *P[i]
		inP[i] = *P[i]
	}
	res, err := DoublePairFixedQ(p.api, inP, *Q)
	if err != nil {
		return err
	}
	var one fields_bls24315.E24
	one.SetOne()
	res.AssertIsEqual(p.api, one)
	return nil
}

// AssertIsEqual asserts the equality of the target group elements.
func (p *Pairing) AssertIsEqual(e1, e2 *GT) {
	e1.AssertIsEqual(p.api, *e2)
}

// NewG1Affine allocates a witness from the native G1 element and returns it.
func NewG1Affine(v bls24315.G1Affine) G1Affine {
	return G1Affine{
		X: (fr_bw6633.Element)(v.X),
		Y: (fr_bw6633.Element)(v.Y),
	}
}

// NewG2Affine allocates a witness from the native G2 element and returns it.
func NewG2Affine(v bls24315.G2Affine) G2Affine {
	return G2Affine{
		X: fields_bls24315.E4{
			B0: fields_bls24315.E2{
				A0: (fr_bw6633.Element)(v.X.B0.A0),
				A1: (fr_bw6633.Element)(v.X.B0.A1),
			},
			B1: fields_bls24315.E2{
				A0: (fr_bw6633.Element)(v.X.B1.A0),
				A1: (fr_bw6633.Element)(v.X.B1.A1),
			},
		},
		Y: fields_bls24315.E4{
			B0: fields_bls24315.E2{
				A0: (fr_bw6633.Element)(v.Y.B0.A0),
				A1: (fr_bw6633.Element)(v.Y.B0.A1),
			},
			B1: fields_bls24315.E2{
				A0: (fr_bw6633.Element)(v.Y.B1.A0),
				A1: (fr_bw6633.Element)(v.Y.B1.A1),
			},
		},
	}
}

// NewGTEl allocates a witness from the native target group element and returns it.
func NewGTEl(v bls24315.GT) GT {
	return GT{
		D0: fields_bls24315.E12{
			C0: fields_bls24315.E4{
				B0: fields_bls24315.E2{
					A0: (fr_bw6633.Element)(v.D0.C0.B0.A0),
					A1: (fr_bw6633.Element)(v.D0.C0.B0.A1),
				},
				B1: fields_bls24315.E2{
					A0: (fr_bw6633.Element)(v.D0.C0.B1.A0),
					A1: (fr_bw6633.Element)(v.D0.C0.B1.A1),
				},
			},
			C1: fields_bls24315.E4{
				B0: fields_bls24315.E2{
					A0: (fr_bw6633.Element)(v.D0.C1.B0.A0),
					A1: (fr_bw6633.Element)(v.D0.C1.B0.A1),
				},
				B1: fields_bls24315.E2{
					A0: (fr_bw6633.Element)(v.D0.C1.B1.A0),
					A1: (fr_bw6633.Element)(v.D0.C1.B1.A1),
				},
			},
			C2: fields_bls24315.E4{
				B0: fields_bls24315.E2{
					A0: (fr_bw6633.Element)(v.D0.C2.B0.A0),
					A1: (fr_bw6633.Element)(v.D0.C2.B0.A1),
				},
				B1: fields_bls24315.E2{
					A0: (fr_bw6633.Element)(v.D0.C2.B1.A0),
					A1: (fr_bw6633.Element)(v.D0.C2.B1.A1),
				},
			},
		},
		D1: fields_bls24315.E12{
			C0: fields_bls24315.E4{
				B0: fields_bls24315.E2{
					A0: (fr_bw6633.Element)(v.D1.C0.B0.A0),
					A1: (fr_bw6633.Element)(v.D1.C0.B0.A1),
				},
				B1: fields_bls24315.E2{
					A0: (fr_bw6633.Element)(v.D1.C0.B1.A0),
					A1: (fr_bw6633.Element)(v.D1.C0.B1.A1),
				},
			},
			C1: fields_bls24315.E4{
				B0: fields_bls24315.E2{
					A0: (fr_bw6633.Element)(v.D1.C1.B0.A0),
					A1: (fr_bw6633.Element)(v.D1.C1.B0.A1),
				},
				B1: fields_bls24315.E2{
					A0: (fr_bw6633.Element)(v.D1.C1.B1.A0),
					A1: (fr_bw6633.Element)(v.D1.C1.B1.A1),
				},
			},
			C2: fields_bls24315.E4{
				B0: fields_bls24315.E2{
					A0: (fr_bw6633.Element)(v.D1.C2.B0.A0),
					A1: (fr_bw6633.Element)(v.D1.C2.B0.A1),
				},
				B1: fields_bls24315.E2{
					A0: (fr_bw6633.Element)(v.D1.C2.B1.A0),
					A1: (fr_bw6633.Element)(v.D1.C2.B1.A1),
				},
			},
		},
	}
}

// Scalar is a scalar in the groups. As the implementation is defined on a
// 2-chain, then this type is an alias to [frontend.Variable].
type Scalar = frontend.Variable
