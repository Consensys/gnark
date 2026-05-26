package sw_octobear

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/maptocurve_octobear"
)

// LinearAccumulator stores the N-coordinate linear-separator vector ECMSH state.
// Each coordinate accumulator starts at the fixed offset point G and uses the
// same incomplete-addition safety argument as the one-point Accumulator: with
// G ≠ O, the per-coordinate sum is never the identity, and a malicious prover
// hitting acc_i = ±Map_i(m) succeeds with negligible probability over the 2^248
// group (and produces an unsatisfiable division by zero otherwise).
type LinearAccumulator struct {
	curve *Curve
	sums  [maptocurve_octobear.LinearN]G1Affine
}

// NewLinearAccumulator returns a zero linear accumulator. Each coordinate is
// initialized to the fixed offset generator.
func NewLinearAccumulator(curve *Curve) *LinearAccumulator {
	a := &LinearAccumulator{curve: curve}
	for i := range a.sums {
		a.sums[i] = accumulatorOffset
	}
	return a
}

// Insert maps msg via the linear separator and adds each of the N mapped
// points to the matching accumulator coordinate.
func (a *LinearAccumulator) Insert(msg frontend.Variable) error {
	pts, err := maptocurve_octobear.MapLinear(a.curve.api, msg)
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
func (a *LinearAccumulator) Digest() [maptocurve_octobear.LinearN]G1Affine {
	return a.sums
}

// Reset clears the accumulator back to (offset, offset, ..., offset).
func (a *LinearAccumulator) Reset() {
	for i := range a.sums {
		a.sums[i] = accumulatorOffset
	}
}

// HashLinear returns the linear-separator vector multiset hash of msgs.
func (c *Curve) HashLinear(msgs []frontend.Variable) ([maptocurve_octobear.LinearN]G1Affine, error) {
	acc := NewLinearAccumulator(c)
	for _, msg := range msgs {
		if err := acc.Insert(msg); err != nil {
			return [maptocurve_octobear.LinearN]G1Affine{}, err
		}
	}
	return acc.Digest(), nil
}
