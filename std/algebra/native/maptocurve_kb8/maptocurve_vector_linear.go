package maptocurve_kb8

import (
	"errors"

	"github.com/consensys/gnark-crypto/ecc/kb8"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/fields_kb8"
	"github.com/consensys/gnark/std/rangecheck"
)

// Linear-separator vector ECMSH parameters (paper §4, App. B "T=128" row).
// These must match the native side (ecc/kb8/multiset-hash/vector_multiset_hash_linear.go).
const (
	LinearN = 23
	LinearT = 128
	LinearM = 1 << 18
)

// MapLinear maps msg to LinearN points on kb8 using the linear domain
// separator y_i(msg, k_i) = LinearT*(msg + i*LinearM) + k_i.
//
// The expensive cubic solve for each coordinate is performed outside the
// circuit by yIncrementLinearHint; the circuit only enforces:
//   - msg < LinearM   (binary decomposition)
//   - k_i < LinearT   (range check)
//   - y_i = LinearT*(msg + i*LinearM) + k_i in the base subfield
//   - y_i² = x_i³ - 3 x_i + b in Fp^8
//
// Inverse-freeness is structural: LinearN*LinearM*LinearT = 23*2^18*128 < p/2.
func MapLinear(api frontend.API, msg frontend.Variable) ([LinearN]G1Affine, error) {
	var pts [LinearN]G1Affine

	if !IsCompatible(api) {
		return pts, errors.New("expected KoalaBear native field for kb8 linear map-to-curve")
	}

	// msg < 2^18 = LinearM
	_ = api.ToBinary(msg, 18)

	const coeffsPerCoord = 9 // 1 tweak k + 8 E8 coefficients of x
	out, err := api.Compiler().NewHint(yIncrementLinearHint, LinearN*coeffsPerCoord, msg)
	if err != nil {
		return pts, err
	}

	_, b := kb8.CurveCoefficients()
	bE8 := newE8(b)

	rc := rangecheck.New(api)
	for i := 0; i < LinearN; i++ {
		base := out[i*coeffsPerCoord:]
		k := base[0]
		x := fromCoeffs(base[1:coeffsPerCoord])

		// k_i < LinearT = 128 ⇒ 7 bits
		rc.Check(k, 7)

		// baseY_i = LinearT * (msg + i*LinearM). The (i*LinearM) term is a
		// compile-time constant, so the api.Add folds into a linear combination.
		baseY := api.Mul(LinearT, api.Add(msg, i*LinearM))

		var y fields_kb8.E8
		y.SetZero()
		y.C0.B0.A0 = api.Add(baseY, k)
		p := G1Affine{X: x, Y: y}

		assertIsOnCurveWithB(api, &p, bE8)
		pts[i] = p
	}
	return pts, nil
}

// assertIsOnCurveWithB is the per-coordinate version of assertIsOnCurve that
// takes the precomputed b ∈ Fp^8 to avoid recomputing CurveCoefficients in the
// inner loop. Behaviour matches assertIsOnCurve in maptocurve.go.
func assertIsOnCurveWithB(api frontend.API, p *G1Affine, bE8 fields_kb8.E8) {
	var ySquared fields_kb8.E8
	ySquared.SetZero()
	ySquared.C0.B0.A0 = api.Mul(p.Y.C0.B0.A0, p.Y.C0.B0.A0)

	rhs := *new(fields_kb8.E8).Cube(api, p.X)
	rhs.Sub(api, rhs, *new(fields_kb8.E8).MulByFp(api, p.X, 3))
	rhs.Add(api, rhs, bE8)

	ySquared.AssertIsEqual(api, rhs)
}
