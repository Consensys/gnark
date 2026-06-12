package sw_octobear

import (
	"errors"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/maptocurve_octobear"
)

var errPoseidon2MismatchedHalves = errors.New("octobear Poseidon2 multiset hash: msgsLow and msgsHigh must have the same length")

// Poseidon2Accumulator stores the N-coordinate Poseidon2-sponge vector ECMSH
// state. Each coordinate accumulator starts at the fixed offset generator,
// preserving the same incomplete-addition safety argument as the one-point
// Accumulator and the LinearAccumulator.
type Poseidon2Accumulator struct {
	curve *Curve
	sums  [maptocurve_octobear.PqN]G1Affine
}

// NewPoseidon2Accumulator returns a zero Poseidon2 accumulator. Each coordinate
// is initialized to the fixed offset generator.
func NewPoseidon2Accumulator(curve *Curve) *Poseidon2Accumulator {
	a := &Poseidon2Accumulator{curve: curve}
	for i := range a.sums {
		a.sums[i] = accumulatorOffset
	}
	return a
}

// Insert maps a 64-bit message — supplied as two 32-bit halves (msgLow,
// msgHigh) — via the Poseidon2 sponge separator and adds each of the PqN
// mapped points to the matching accumulator coordinate.
func (a *Poseidon2Accumulator) Insert(msgLow, msgHigh frontend.Variable) error {
	pts, err := maptocurve_octobear.MapPoseidon2(a.curve.api, msgLow, msgHigh)
	if err != nil {
		return err
	}
	for i := range a.sums {
		pm := fromMapPoint(pts[i])
		a.sums[i].AddAssign(a.curve.api, pm)
	}
	return nil
}

// Digest returns the current vector of accumulator points.
func (a *Poseidon2Accumulator) Digest() [maptocurve_octobear.PqN]G1Affine {
	return a.sums
}

// Reset clears the accumulator back to the per-coordinate offset.
func (a *Poseidon2Accumulator) Reset() {
	for i := range a.sums {
		a.sums[i] = accumulatorOffset
	}
}

// HashPoseidon2 returns the Poseidon2-sponge vector multiset hash of msgs.
// Each message is supplied as (low, high) 32-bit halves of a 64-bit value.
func (c *Curve) HashPoseidon2(msgsLow, msgsHigh []frontend.Variable) ([maptocurve_octobear.PqN]G1Affine, error) {
	if len(msgsLow) != len(msgsHigh) {
		return [maptocurve_octobear.PqN]G1Affine{}, errPoseidon2MismatchedHalves
	}
	acc := NewPoseidon2Accumulator(c)
	for i := range msgsLow {
		if err := acc.Insert(msgsLow[i], msgsHigh[i]); err != nil {
			return [maptocurve_octobear.PqN]G1Affine{}, err
		}
	}
	return acc.Digest(), nil
}
