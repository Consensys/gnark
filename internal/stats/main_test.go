package main

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

func TestCircuitStatistics(t *testing.T) {
	assert := test.NewAssert(t)

	// load reference
	reference := newStats()
	assert.NoError(reference.load(refPath))

	// for each circuit, on each curve, on each backend
	// compare with reference stats
	for _, c := range allCircuits {
		// check that we have it.
		ref, ok := reference.mStats[c.name]
		if !ok {
			assert.Log("warning: no stats for circuit", c.name)
			return
		}
		for _, curve := range ecc.Implemented() {
			for _, b := range backend.Implemented() {
				curve := curve
				backendID := b
				name := c.name
				// copy the circuit now in case assert calls t.Parallel()
				circuit := c.circuit
				assert.Run(func(assert *test.Assert) {
					rs := ref[backendID][curve]

					s, err := newCircuitStats(curve, backendID, circuit, name)
					assert.NoError(err, "building stats for circuit "+name)

					if s != rs {
						assert.Failf("unexpected stats count", "expected %v (reference), got %v. %s - %s - %s", rs, s, name, backendID.String(), curve.String())
					}
				}, name, curve.String(), backendID.String())
			}
		}

	}

}
