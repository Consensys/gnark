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
	"github.com/consensys/gnark/std/selector"
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

// AddUnified adds any two points and returns the sum. It does not modify the input
// points.
func (c *Curve) AddUnified(P, Q *G1Affine) *G1Affine {
	res := &G1Affine{
		X: P.X,
		Y: P.Y,
	}
	res.AddUnified(c.api, *Q)
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

// jointScalarMul computes s1*P+s2*P2 and returns the result. It doesn't modify the
// inputs.
func (c *Curve) jointScalarMul(P1, P2 *G1Affine, s1, s2 *Scalar, opts ...algopts.AlgebraOption) *G1Affine {
	res := &G1Affine{}
	varScalar1 := c.packScalarToVar(s1)
	varScalar2 := c.packScalarToVar(s2)
	res.jointScalarMul(c.api, *P1, *P2, varScalar1, varScalar2, opts...)
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
	res.ScalarMul(c.api, *P, varScalar, opts...)
	return res
}

// ScalarMulBase computes scalar*G where G is the standard base point of the
// curve. It doesn't modify the scalar.
func (c *Curve) ScalarMulBase(s *Scalar, opts ...algopts.AlgebraOption) *G1Affine {
	res := new(G1Affine)
	varScalar := c.packScalarToVar(s)
	res.ScalarMulBase(c.api, varScalar, opts...)
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
	addFn := c.Add
	if cfg.CompleteArithmetic {
		addFn = c.AddUnified
	}
	if !cfg.FoldMulti {
		if len(P) != len(scalars) {
			return nil, fmt.Errorf("mismatching points and scalars slice lengths")
		}
		// points and scalars must be non-zero
		n := len(P)
		var res *G1Affine
		if n%2 == 1 {
			res = c.ScalarMul(P[n-1], scalars[n-1], opts...)
		} else {
			res = c.jointScalarMul(P[n-2], P[n-1], scalars[n-2], scalars[n-1], opts...)
		}
		for i := 1; i < n-1; i += 2 {
			q := c.jointScalarMul(P[i-1], P[i], scalars[i-1], scalars[i], opts...)
			res = addFn(res, q)
		}
		return res, nil
	} else {
		// scalars are powers
		if len(scalars) == 0 {
			return nil, fmt.Errorf("need scalar for folding")
		}
		gamma := c.packScalarToVar(scalars[0])
		// decompose gamma in the endomorphism eigenvalue basis and bit-decompose the sub-scalars
		cc := getInnerCurveConfig(c.api.Compiler().Field())
		sd, err := c.api.Compiler().NewHint(decomposeScalarG1Simple, 3, gamma)
		if err != nil {
			panic(err)
		}
		gamma1, gamma2 := sd[0], sd[1]
		c.api.AssertIsEqual(
			c.api.Add(gamma1, c.api.Mul(gamma2, cc.lambda)),
			c.api.Add(gamma, c.api.Mul(cc.fr, sd[2])),
		)
		nbits := 127
		gamma1Bits := c.api.ToBinary(gamma1, nbits)
		gamma2Bits := c.api.ToBinary(gamma2, nbits)

		// points and scalars must be non-zero
		var res G1Affine
		res.scalarBitsMul(c.api, *P[len(P)-1], gamma1Bits, gamma2Bits, opts...)
		for i := len(P) - 2; i > 0; i-- {
			res = *addFn(P[i], &res)
			res.scalarBitsMul(c.api, res, gamma1Bits, gamma2Bits, opts...)
		}
		res = *addFn(P[0], &res)
		return &res, nil
	}
}

// Select sets p1 if b=1, p2 if b=0, and returns it. b must be boolean constrained
func (c *Curve) Select(b frontend.Variable, p1, p2 *G1Affine) *G1Affine {
	return &G1Affine{
		X: c.api.Select(b, p1.X, p2.X),
		Y: c.api.Select(b, p1.Y, p2.Y),
	}
}

// Lookup2 performs a 2-bit lookup between p1, p2, p3, p4 based on bits b0  and b1.
// Returns:
//   - p1 if b0=0 and b1=0,
//   - p2 if b0=1 and b1=0,
//   - p3 if b0=0 and b1=1,
//   - p4 if b0=1 and b1=1.
func (c *Curve) Lookup2(b1, b2 frontend.Variable, p1, p2, p3, p4 *G1Affine) *G1Affine {
	return &G1Affine{
		X: c.api.Lookup2(b1, b2, p1.X, p2.X, p3.X, p4.X),
		Y: c.api.Lookup2(b1, b2, p1.Y, p2.Y, p3.Y, p4.Y),
	}
}

// Mux performs a lookup from the inputs and returns inputs[sel]. It is most
// efficient for power of two lengths of the inputs, but works for any number of
// inputs.
func (c *Curve) Mux(sel frontend.Variable, inputs ...*G1Affine) *G1Affine {
	xs := make([]frontend.Variable, len(inputs))
	ys := make([]frontend.Variable, len(inputs))
	for i := range inputs {
		xs[i] = inputs[i].X
		ys[i] = inputs[i].Y
	}
	return &G1Affine{
		X: selector.Mux(c.api, sel, xs...),
		Y: selector.Mux(c.api, sel, ys...),
	}
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

func (p *Pairing) AssertIsOnG1(P *G1Affine) {
	panic("not implemented")
}

func (p *Pairing) AssertIsOnG2(P *G2Affine) {
	panic("not implemented")
}

// NewG1Affine allocates a witness from the native G1 element and returns it.
func NewG1Affine(v bls24315.G1Affine) G1Affine {
	return G1Affine{
		X: (fr_bw6633.Element)(v.X),
		Y: (fr_bw6633.Element)(v.Y),
	}
}

// NewG2Affine allocates a witness from the native G2 element and returns it.
func newG2AffP(v bls24315.G2Affine) g2AffP {
	return g2AffP{
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

func NewG2Affine(v bls24315.G2Affine) G2Affine {
	return G2Affine{
		P: newG2AffP(v),
	}
}

// NewG2AffineFixed returns witness of v with precomputations for efficient
// pairing computation.
func NewG2AffineFixed(v bls24315.G2Affine) G2Affine {
	lines := precomputeLines(v)
	return G2Affine{
		P:     newG2AffP(v),
		Lines: &lines,
	}
}

// NewG2AffineFixedPlaceholder returns a placeholder for the circuit compilation
// when witness will be given with line precomputations using
// [NewG2AffineFixed].
func NewG2AffineFixedPlaceholder() G2Affine {
	var lines lineEvaluations
	for i := 0; i < len(bls24315.LoopCounter)-1; i++ {
		lines[0][i] = &lineEvaluation{}
		lines[1][i] = &lineEvaluation{}
	}
	return G2Affine{
		Lines: &lines,
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
type ScalarField = emparams.BLS24315Fr
