package sw_bls24315

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	fr_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	fr_bw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/native/fields_bls24315"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

// Curve allows G1 operations in BLS24-315.
type Curve struct {
	api frontend.API
	fr  *emulated.Field[ScalarField]
}

// NewCurve initializes a new [Curve] instance.
func NewCurve(api frontend.API) (*Curve, error) {
	f, err := emulated.NewField[ScalarField](api)
	if err != nil {
		return nil, fmt.Errorf("scalar field")
	}
	return &Curve{
		api: api,
		fr:  f,
	}, nil
}

// MarshalScalar returns
func (c *Curve) MarshalScalar(s Scalar) []frontend.Variable {
	nbBits := 8 * ((ScalarField{}.Modulus().BitLen() + 7) / 8)
	ss := c.fr.Reduce(&s)
	x := c.fr.ToBits(ss)
	for i, j := 0, nbBits-1; i < j; {
		x[i], x[j] = x[j], x[i]
		i++
		j--
	}
	return x
}

// MarshalG1 returns [P.X || P.Y] in binary. Both P.X and P.Y are
// in little endian.
func (c *Curve) MarshalG1(P G1Affine) []frontend.Variable {
	nbBits := 8 * ((ecc.BLS24_315.BaseField().BitLen() + 7) / 8)
	res := make([]frontend.Variable, 2*nbBits)
	x := bits.ToBinary(c.api, P.X, bits.WithNbDigits(nbBits))
	y := bits.ToBinary(c.api, P.Y, bits.WithNbDigits(nbBits))
	for i := 0; i < nbBits; i++ {
		res[i] = x[nbBits-1-i]
		res[i+nbBits] = y[nbBits-1-i]
	}
	xZ := c.api.IsZero(P.X)
	yZ := c.api.IsZero(P.Y)
	res[1] = c.api.Mul(xZ, yZ)
	return res
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

// JointScalarMul computes s1*P+s2*P2 and returns the result. It doesn't modify the
// inputs.
func (c *Curve) JointScalarMul(P1, P2 *G1Affine, s1, s2 *Scalar, opts ...algopts.AlgebraOption) *G1Affine {
	res := &G1Affine{}
	varScalar1 := c.packScalarToVar(s1)
	varScalar2 := c.packScalarToVar(s2)
	res.JointScalarMul(c.api, *P1, *P2, varScalar1, varScalar2)
	return res
}

// ScalarMul computes scalar*P and returns the result. It doesn't modify the
// inputs.
func (c *Curve) ScalarMul(P *G1Affine, s *Scalar, opts ...algopts.AlgebraOption) *G1Affine {
	res := &G1Affine{
		X: P.X,
		Y: P.Y,
	}
	varScalar := c.packScalarToVar(s)
	res.ScalarMul(c.api, *P, varScalar)
	return res
}

// ScalarMulBase computes scalar*G where G is the standard base point of the
// curve. It doesn't modify the scalar.
func (c *Curve) ScalarMulBase(s *Scalar, opts ...algopts.AlgebraOption) *G1Affine {
	res := new(G1Affine)
	varScalar := c.packScalarToVar(s)
	res.ScalarMulBase(c.api, varScalar)
	return res
}

// MultiScalarMul computes ∑scalars_i * P_i and returns it. It doesn't modify
// the inputs. It returns an error if there is a mismatch in the lengths of the
// inputs.
func (c *Curve) MultiScalarMul(P []*G1Affine, scalars []*Scalar, opts ...algopts.AlgebraOption) (*G1Affine, error) {

	if len(P) == 0 {
		return &G1Affine{
			X: 0,
			Y: 0,
		}, nil
	}
	cfg, err := algopts.NewConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("new config: %w", err)
	}
	if !cfg.FoldMulti {
		if len(P) != len(scalars) {
			return nil, fmt.Errorf("mismatching points and scalars slice lengths")
		}
		res := c.ScalarMul(P[0], scalars[0])
		for i := 1; i < len(P); i++ {
			q := c.ScalarMul(P[i], scalars[i], opts...)

			// check for infinity...
			isInfinity := c.api.And(c.api.IsZero(P[i].X), c.api.IsZero(P[i].Y))
			tmp := c.Add(res, q)
			res.X = c.api.Select(isInfinity, res.X, tmp.X)
			res.Y = c.api.Select(isInfinity, res.Y, tmp.Y)
		}
		return res, nil
	} else {
		// scalars are powers
		if len(scalars) == 0 {
			return nil, fmt.Errorf("need scalar for folding")
		}
		gamma := scalars[0]
		res := c.ScalarMul(P[len(P)-1], gamma, opts...)
		for i := len(P) - 2; i > 0; i-- {
			isInfinity := c.api.And(c.api.IsZero(P[i].X), c.api.IsZero(P[i].Y))
			tmp := c.Add(P[i], res)
			res.X = c.api.Select(isInfinity, res.X, tmp.X)
			res.Y = c.api.Select(isInfinity, res.Y, tmp.Y)
			res = c.ScalarMul(res, gamma, opts...)
		}
		res = c.Add(P[0], res)
		return res, nil
	}
}

// SameScalarMul computes scalar*P1 and scalar*P2 and returns the results. It doesn't modify the
// inputs.
func (c *Curve) SameScalarMul(P1, P2 *G1Affine, s *Scalar, opts ...algopts.AlgebraOption) (*G1Affine, *G1Affine) {
	res1 := &G1Affine{
		X: P1.X,
		Y: P1.Y,
	}
	res2 := &G1Affine{
		X: P2.X,
		Y: P2.Y,
	}
	varScalar := c.packScalarToVar(s)
	res1.ScalarMul(c.api, *P1, varScalar)
	res2.ScalarMul(c.api, *P2, varScalar)
	return res1, res2
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
type Scalar = emulated.Element[ScalarField]

// NewScalar allocates a witness from the native scalar and returns it.
func NewScalar(v fr_bls24315.Element) Scalar {
	return emulated.ValueOf[ScalarField](v)
}

// packScalarToVar packs the limbs of emulated scalar to a frontend.Variable.
//
// The method is for compatibility for existing scalar multiplication
// implementation which assumes as an input frontend.Variable.
func (c *Curve) packScalarToVar(s *Scalar) frontend.Variable {
	var fr ScalarField
	reduced := c.fr.Reduce(s)
	var res frontend.Variable = 0
	nbBits := fr.BitsPerLimb()
	coef := new(big.Int)
	one := big.NewInt(1)
	for i := range reduced.Limbs {
		res = c.api.Add(res, c.api.Mul(reduced.Limbs[i], coef.Lsh(one, nbBits*uint(i))))
	}
	return res
}

// ScalarField defines the [emulated.FieldParams] implementation on a one limb of the scalar field.
type ScalarField = emparams.BLS12315Fr
