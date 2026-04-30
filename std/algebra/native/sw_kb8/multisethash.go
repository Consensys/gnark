package sw_kb8

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/maptocurve_kb8"
)

// Accumulator stores the 1-point multiset hash state.
type Accumulator struct {
	curve *Curve
	sum   G1Affine
}

// NewAccumulator returns a zero accumulator.
func NewAccumulator(curve *Curve) *Accumulator {
	return &Accumulator{
		curve: curve,
		sum:   accumulatorOffset,
	}
}

// Insert maps msg and adds it to the accumulator.
func (a *Accumulator) Insert(msg frontend.Variable) error {
	p, err := maptocurve_kb8.YIncrement(a.curve.api, msg)
	if err != nil {
		return err
	}
	pm := fromMapPoint(p)
	a.sum.AddBrierJoye(a.curve.api, pm)
	return nil
}

// Digest returns the current digest.
func (a *Accumulator) Digest() G1Affine {
	return a.sum
}

// Reset clears the accumulator.
func (a *Accumulator) Reset() {
	a.sum = accumulatorOffset
}

// Hash returns the multiset hash of msgs.
func (c *Curve) Hash(msgs []frontend.Variable) (G1Affine, error) {
	acc := NewAccumulator(c)
	for _, msg := range msgs {
		if err := acc.Insert(msg); err != nil {
			return G1Affine{}, err
		}
	}
	return acc.Digest(), nil
}
