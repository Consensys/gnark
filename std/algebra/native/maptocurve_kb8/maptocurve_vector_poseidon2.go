package maptocurve_kb8

import (
	"encoding/binary"
	"errors"

	"github.com/consensys/gnark-crypto/ecc/kb8"
	multisethash "github.com/consensys/gnark-crypto/ecc/kb8/multiset-hash"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/fields_kb8"
	"github.com/consensys/gnark/std/permutation/poseidon2"
	"github.com/consensys/gnark/std/rangecheck"
)

// Poseidon2-sponge vector ECMSH parameters (paper §4.3 "preferred" derivation).
// These must match the native side
// (ecc/kb8/multiset-hash/vector_multiset_hash_poseidon2.go).
const (
	PqN               = 23
	PqT               = 256
	PqWidth           = 16
	PqSqueezeRate     = 8
	PqPermutations    = 3  // ceil(PqN / PqSqueezeRate)
	pqRangeS          = 23 // ⌊p/(2T)⌋ = 4_161_536 < 2^23 (with T=256)
	pqRangeQ          = 9  // q ≤ ⌊(p-1)/B⌋ = 2T-1 = 511 < 2^9
	pqRangeK          = 8  // k < T = 256
	pqOutputsPerCoord = 11 // q, s, k + 8 E8 coefficients of x
)

// MapPoseidon2 maps a 64-bit message (split into a low and a high 32-bit half
// to fit into the koalabear field) to PqN points on kb8 using a width-16
// Poseidon2 sponge with rate PqSqueezeRate.
//
// Both halves are expected to be ≤ 2^32 − 1. The function constrains each
// half to fit in 32 bits.
//
// The expensive cubic solve per coordinate is performed outside the circuit by
// yIncrementPoseidon2Hint; the circuit only enforces:
//   - msgLow, msgHigh < 2^32
//   - Poseidon2(state) computed in-circuit matches the squeezed slots fed to
//     the range-reduction
//   - For each i: squeezed[i] = q_i * B + s_i with s_i < B, q_i < 2T
//   - k_i < T
//   - y_i = T * s_i + k_i in the base subfield
//   - y_i² = x_i³ - 3 x_i + b in Fp^8
//
// Inverse-freeness is structural: s_i < ⌊p/(2T)⌋ ⇒ y_i < p/2.
func MapPoseidon2(api frontend.API, msgLow, msgHigh frontend.Variable) ([PqN]G1Affine, error) {
	var pts [PqN]G1Affine

	if !IsCompatible(api) {
		return pts, errors.New("expected KoalaBear native field for kb8 Poseidon2 map-to-curve")
	}

	// Constrain msgLow, msgHigh < 2^32.
	_ = api.ToBinary(msgLow, 32)
	_ = api.ToBinary(msgHigh, 32)

	// Build sponge state and absorb (domainTag, msgLow, msgHigh) into the
	// rate slots. The 8-byte tag is split into two big-endian uint32 halves to
	// match the native packing in vector_multiset_hash_poseidon2.go.
	tag := multisethash.PqDomainTag()
	tag0 := binary.BigEndian.Uint32(tag[0:4])
	tag1 := binary.BigEndian.Uint32(tag[4:8])
	state := make([]frontend.Variable, PqWidth)
	state[0] = tag0
	state[1] = tag1
	state[2] = msgLow
	state[3] = msgHigh
	for i := 4; i < PqWidth; i++ {
		state[i] = frontend.Variable(0)
	}

	perm, err := poseidon2.NewPoseidon2FromParameters(api, PqWidth, 6, 21)
	if err != nil {
		return pts, err
	}

	// 3 squeeze permutations, 8 elements each → 24 squeezed (23 used).
	squeezed := make([]frontend.Variable, PqPermutations*PqSqueezeRate)
	for p := 0; p < PqPermutations; p++ {
		if err := perm.Permutation(state); err != nil {
			return pts, err
		}
		copy(squeezed[p*PqSqueezeRate:(p+1)*PqSqueezeRate], state[:PqSqueezeRate])
	}

	// Hint inputs: the 23 squeezed values used. The hint computes (q, s, k, x)
	// per coordinate so the in-circuit code only verifies the relations.
	hintInputs := make([]frontend.Variable, PqN)
	copy(hintInputs, squeezed[:PqN])
	out, err := api.Compiler().NewHint(yIncrementPoseidon2Hint, PqN*pqOutputsPerCoord, hintInputs...)
	if err != nil {
		return pts, err
	}

	_, b := kb8.CurveCoefficients()
	bE8 := newE8(b)
	bound := multisethash.PqReducerBound()

	rc := rangecheck.New(api)
	for i := 0; i < PqN; i++ {
		base := out[i*pqOutputsPerCoord:]
		q := base[0]
		s := base[1]
		k := base[2]
		x := fromCoeffs(base[3:pqOutputsPerCoord])

		// squeezed[i] = q * B + s
		api.AssertIsEqual(squeezed[i], api.Add(api.Mul(q, bound), s))

		// Range checks. (We range-check s to one less bit than the bound width
		// since s < B = 4_161_536 ⇒ s ≤ 4_161_535 < 2^pqRangeS.)
		rc.Check(s, pqRangeS)
		rc.Check(q, pqRangeQ)
		rc.Check(k, pqRangeK)

		// baseY = T * s; y = (T*s + k, 0, ..., 0) in E8.
		baseY := api.Mul(PqT, s)
		var y fields_kb8.E8
		y.SetZero()
		y.C0.B0.A0 = api.Add(baseY, k)
		pt := G1Affine{X: x, Y: y}

		assertIsOnCurveWithB(api, &pt, bE8)
		pts[i] = pt
	}
	return pts, nil
}
