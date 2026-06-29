package maptocurve_increment

import (
	"fmt"
	"math/big"

	bn254fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	secp256k1fp "github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	secp256r1fp "github.com/consensys/gnark-crypto/ecc/secp256r1/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/rangecheck"
)

// T is the increment window size: K is searched in [0, T).
const T = 256

// Mapper provides increment-and-check map-to-curve operations for an emulated
// short Weierstrass curve y² = x³ + ax + b.
//
// See the package documentation for the security caveats — in particular the
// mapping is non-unique and does not clear the cofactor.
type Mapper[B, S emulated.FieldParams] struct {
	api   frontend.API
	curve *sw_emulated.Curve[B, S]
	field *emulated.Field[B]
	a, b  *big.Int
	s     int // 2-adicity v₂(q-1); used by XIncrement only.
}

// NewMapper returns a [Mapper] bound to the given emulated curve. The curve
// must use a supported base field — currently BN254, secp256k1 or P-256.
// Any other base field is rejected here so that an unsupported curve fails at
// circuit-definition time rather than at proving time.
func NewMapper[B, S emulated.FieldParams](api frontend.API, curve *sw_emulated.Curve[B, S]) (*Mapper[B, S], error) {
	if curve == nil {
		return nil, fmt.Errorf("curve is nil")
	}
	if !isSupportedField[B]() {
		var fp B
		return nil, fmt.Errorf("unsupported base field modulus %s: only BN254, secp256k1 and P-256 are supported", fp.Modulus().String())
	}
	field, err := emulated.NewField[B](api)
	if err != nil {
		return nil, fmt.Errorf("new base field: %w", err)
	}
	params := sw_emulated.GetCurveParams[B]()
	return &Mapper[B, S]{
		api:   api,
		curve: curve,
		field: field,
		a:     params.A,
		b:     params.B,
		s:     twoAdicity[B](),
	}, nil
}

// Increment maps msg to a curve point using the variant best suited to the
// instantiated curve: [Mapper.XIncrement] for low-2-adicity curves with a ≠ 0
// (e.g. P-256) and [Mapper.YIncrement] for j=0 curves and high-2-adicity
// fields (e.g. BN254, secp256k1, Grumpkin, BLS12-377).
//
// Callers that need a specific variant should call [Mapper.XIncrement] or
// [Mapper.YIncrement] directly.
func (m *Mapper[B, S]) Increment(msg *emulated.Element[B]) (*sw_emulated.AffinePoint[B], error) {
	// For j=0 curves, the XIncrement inverse-exclusion check is the load-
	// bearing soundness witness against the algebraic attack from the paper
	// (eprint 2026/590). YIncrement sidesteps the attack entirely and is the
	// preferred variant whenever a Cbrt witness is available — which it is
	// for every supported curve.
	if m.a.Sign() == 0 {
		return m.YIncrement(msg)
	}
	// For curves with a ≠ 0 we use YIncrement when 2-adicity is too high for
	// XIncrement to be practical (the 2^s-th root search runs in O(2^s)).
	if m.s > 4 {
		return m.YIncrement(msg)
	}
	return m.XIncrement(msg)
}

// XIncrement maps msg to a curve point (x, y) using the x-increment method:
//
//	X = msg·256 + k, Y² = X³ + aX + b, Z^{2^s} = Y
//
// The Z witness chain forbids Y from being the negation of a valid
// y-coordinate, which is what makes the construction sound on j=0 curves
// against the algebraic attack from eprint 2026/590.
//
// Caller-side precondition: msg < q/256 (q is the curve base modulus). The
// precondition is NOT enforced in-circuit; see the package doc.
func (m *Mapper[B, S]) XIncrement(msg *emulated.Element[B]) (*sw_emulated.AffinePoint[B], error) {
	// hint outputs: 1 native (k), 3 emulated (x, y, z).
	nOut, emOut, err := m.field.NewHintGeneric(xIncrementHint, 1, 3, nil, []*emulated.Element[B]{msg})
	if err != nil {
		return nil, fmt.Errorf("x-increment hint: %w", err)
	}
	k := nOut[0]
	xEl, yEl, zEl := emOut[0], emOut[1], emOut[2]

	// (1) curve equation: Y² = X³ + aX + b
	p := &sw_emulated.AffinePoint[B]{X: *xEl, Y: *yEl}
	m.curve.AssertIsOnCurve(p)

	// (2) encoding: X = msg·T + K
	kEl := m.nativeAsEmulated(k)
	tEl := m.field.NewElement(big.NewInt(T))
	m.field.AssertIsEqual(xEl, m.field.Add(m.field.Mul(msg, tEl), kEl))

	// (3) range: 0 ≤ K < T
	rangecheck.New(m.api).Check(k, 8)

	// (4) 2^s-th power witness: Z^{2^s} = Y
	w := zEl
	for i := 0; i < m.s; i++ {
		w = m.field.Mul(w, w)
	}
	m.field.AssertIsEqual(w, yEl)

	return p, nil
}

// YIncrement maps msg to a curve point (x, y) using the y-increment method:
//
//	Y = msg·256 + k, Y² = X³ + aX + b
//
// No inverse-exclusion witness is needed, so this variant works for any
// 2-adicity and is the recommended method for j=0 curves.
//
// Caller-side precondition: msg < q/256 (q is the curve base modulus). The
// precondition is NOT enforced in-circuit; see the package doc.
func (m *Mapper[B, S]) YIncrement(msg *emulated.Element[B]) (*sw_emulated.AffinePoint[B], error) {
	// hint outputs: 1 native (k), 1 emulated (x).
	nOut, emOut, err := m.field.NewHintGeneric(yIncrementHint, 1, 1, nil, []*emulated.Element[B]{msg})
	if err != nil {
		return nil, fmt.Errorf("y-increment hint: %w", err)
	}
	k := nOut[0]
	xEl := emOut[0]

	// reconstruct Y = msg·T + K
	kEl := m.nativeAsEmulated(k)
	tEl := m.field.NewElement(big.NewInt(T))
	yEl := m.field.Add(m.field.Mul(msg, tEl), kEl)

	// (1) curve equation: Y² = X³ + aX + b
	p := &sw_emulated.AffinePoint[B]{X: *xEl, Y: *yEl}
	m.curve.AssertIsOnCurve(p)

	// (2) range: 0 ≤ K < T
	rangecheck.New(m.api).Check(k, 8)

	return p, nil
}

// nativeAsEmulated lifts a small native variable (must fit in one limb; the
// caller enforces the range) into an emulated element of width nbLimbs by
// padding the higher limbs with zero. We can't use [emulated.Field.NewElement]
// directly here because it expects exactly nbLimbs limbs.
func (m *Mapper[B, S]) nativeAsEmulated(v frontend.Variable) *emulated.Element[B] {
	nbLimbs, _ := emulated.GetEffectiveFieldParams[B](m.api.Compiler().Field())
	limbs := make([]frontend.Variable, nbLimbs)
	limbs[0] = v
	for i := uint(1); i < nbLimbs; i++ {
		limbs[i] = 0
	}
	return m.field.NewElement(limbs)
}

// isSupportedField reports whether the base field B is one of the curves the
// increment hints know how to solve (BN254, secp256k1, P-256). It must stay in
// sync with the modulus dispatch in xIncrementHint / yIncrementHint.
func isSupportedField[F emulated.FieldParams]() bool {
	var t F
	q := t.Modulus()
	switch {
	case q.Cmp(bn254fp.Modulus()) == 0,
		q.Cmp(secp256k1fp.Modulus()) == 0,
		q.Cmp(secp256r1fp.Modulus()) == 0:
		return true
	default:
		return false
	}
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
