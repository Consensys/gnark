package maptocurve

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/rangecheck"
)

const T = 256 // increment window size (8 bits)

// Mapper provides increment-and-check map-to-curve operations for emulated
// short Weierstrass curves y² = x³ + ax + b.
type Mapper[F emulated.FieldParams] struct {
	api   frontend.API
	field *emulated.Field[F]
	a, b  *big.Int
	s     int // 2-adicity v₂(q-1) for x-increment inverse-exclusion
}

// NewMapper creates a new Mapper for the curve defined by field type F.
// Curve coefficients are read from [sw_emulated.GetCurveParams] when available.
// The 2-adicity s (for x-increment) is auto-detected from the field modulus.
func NewMapper[F emulated.FieldParams](api frontend.API) (*Mapper[F], error) {
	field, err := emulated.NewField[F](api)
	if err != nil {
		return nil, err
	}
	a, b := curveCoefficients[F]()
	s := twoAdicity[F]()
	return &Mapper[F]{api: api, field: field, a: a, b: b, s: s}, nil
}

// XIncrement maps msg to a curve point (x, y) using the x-increment method:
//
//	X = msg·256 + k, Y² = X³ + aX + b, Z^{2^s} = Y
//
// where k ∈ [0, 256) is found by the hint, and the Z witness chain ensures Y
// is not the inverse of a valid y-coordinate (needed for j=0 curves).
func (m *Mapper[F]) XIncrement(msg *emulated.Element[F]) (x, y *emulated.Element[F], err error) {
	fp := m.field

	// hint inputs: [nbLimbs, q_limbs..., a, b, s, msg_limbs...]
	// hint outputs: [k, x_limbs..., y_limbs..., z_limbs...]
	var fparams F
	nbLimbs := int(fparams.NbLimbs())
	hintOutputs := 1 + 3*nbLimbs // k + x + y + z
	hintInputs := m.buildHintInputs(msg, nbLimbs)

	res, err := m.api.Compiler().NewHint(xIncrementHint, hintOutputs, hintInputs...)
	if err != nil {
		return nil, nil, err
	}

	k := res[0]
	xLimbs := res[1 : 1+nbLimbs]
	yLimbs := res[1+nbLimbs : 1+2*nbLimbs]
	zLimbs := res[1+2*nbLimbs : 1+3*nbLimbs]

	xEl := fp.NewElement(xLimbs)
	yEl := fp.NewElement(yLimbs)
	zEl := fp.NewElement(zLimbs)

	// (1) Curve equation: Y² = X³ + a·X + b
	m.assertOnCurve(xEl, yEl)

	// (2) Encoding: X = msg*T + K
	kEl := m.nativeToEmulated(k)
	Tconst := fp.NewElement(big.NewInt(T))
	fp.AssertIsEqual(xEl, fp.Add(fp.Mul(msg, Tconst), kEl))

	// (3) Range: 0 ≤ K < 256
	rangecheck.New(m.api).Check(k, 8)

	// (4) 2^S-th power witness: Z^{2^S} = Y
	w := zEl
	for i := 0; i < m.s; i++ {
		w = fp.Mul(w, w)
	}
	fp.AssertIsEqual(w, yEl)

	return xEl, yEl, nil
}

// YIncrement maps msg to a curve point (x, y) using the y-increment method:
//
//	Y = msg·256 + k, Y² = X³ + aX + b
//
// where k ∈ [0, 256) is found by the hint. No inverse-exclusion witness is
// needed, making this simpler and recommended for j=0 curves.
func (m *Mapper[F]) YIncrement(msg *emulated.Element[F]) (x, y *emulated.Element[F], err error) {
	fp := m.field

	var fparams F
	nbLimbs := int(fparams.NbLimbs())
	hintOutputs := 1 + nbLimbs // k + x
	hintInputs := m.buildHintInputs(msg, nbLimbs)

	res, err := m.api.Compiler().NewHint(yIncrementHint, hintOutputs, hintInputs...)
	if err != nil {
		return nil, nil, err
	}

	k := res[0]
	xLimbs := res[1 : 1+nbLimbs]

	xEl := fp.NewElement(xLimbs)

	// Reconstruct Y = msg*T + K
	kEl := m.nativeToEmulated(k)
	Tconst := fp.NewElement(big.NewInt(T))
	yEl := fp.Add(fp.Mul(msg, Tconst), kEl)

	// (1) Curve equation: Y² = X³ + a·X + b
	m.assertOnCurve(xEl, yEl)

	// (2) Range: 0 ≤ K < 256
	rangecheck.New(m.api).Check(k, 8)

	return xEl, yEl, nil
}

// buildHintInputs constructs hint inputs: [nbLimbs, q_limbs..., msg_limbs...]
// Curve coefficients are not passed; the hint dispatches on q to look them up.
func (m *Mapper[F]) buildHintInputs(msg *emulated.Element[F], nbLimbs int) []frontend.Variable {
	fp := m.field
	var fparams F
	q := fparams.Modulus()

	inputs := make([]frontend.Variable, 0, 1+2*nbLimbs)
	inputs = append(inputs, nbLimbs)

	qLimbs := decomposeBigInt(q, nbLimbs)
	for _, l := range qLimbs {
		inputs = append(inputs, l)
	}

	msgLimbs := fp.Reduce(msg).Limbs
	for i := 0; i < nbLimbs; i++ {
		inputs = append(inputs, msgLimbs[i])
	}
	return inputs
}

// decomposeBigInt splits v into nbLimbs 64-bit limbs (little-endian) as *big.Int values.
func decomposeBigInt(v *big.Int, nbLimbs int) []*big.Int {
	mask := new(big.Int).SetUint64(^uint64(0))
	tmp := new(big.Int).Set(v)
	result := make([]*big.Int, nbLimbs)
	for i := 0; i < nbLimbs; i++ {
		result[i] = new(big.Int).And(tmp, mask)
		tmp.Rsh(tmp, 64)
	}
	return result
}

// assertOnCurve checks Y² = X³ + a·X + b.
func (m *Mapper[F]) assertOnCurve(x, y *emulated.Element[F]) {
	fp := m.field
	lhs := fp.Mul(y, y)
	x2 := fp.Mul(x, x)
	rhs := fp.Mul(x2, x)
	if m.a.Sign() != 0 {
		aVal := fp.NewElement(m.a)
		rhs = fp.Add(rhs, fp.Mul(aVal, x))
	}
	bVal := fp.NewElement(m.b)
	rhs = fp.Add(rhs, bVal)
	fp.AssertIsEqual(lhs, rhs)
}

// nativeToEmulated converts a native variable (fitting in one limb) to an
// emulated element.
func (m *Mapper[F]) nativeToEmulated(v frontend.Variable) *emulated.Element[F] {
	var fparams F
	nbLimbs := int(fparams.NbLimbs())
	limbs := make([]frontend.Variable, nbLimbs)
	limbs[0] = v
	for i := 1; i < nbLimbs; i++ {
		limbs[i] = 0
	}
	return m.field.NewElement(limbs)
}

// curveCoefficients returns the short Weierstrass coefficients (a, b) for the
// curve over field F.
func curveCoefficients[F emulated.FieldParams]() (a, b *big.Int) {
	p := sw_emulated.GetCurveParams[F]()
	return p.A, p.B
}

// twoAdicity returns v₂(q-1) for the field modulus q.
func twoAdicity[F emulated.FieldParams]() int {
	var t F
	qm1 := new(big.Int).Sub(t.Modulus(), big.NewInt(1))
	s := 0
	for qm1.Bit(s) == 0 {
		s++
	}
	return s
}
