package stats

import (
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

func TestCircuitStatistics(t *testing.T) {
	const refPath = "latest.stats"
	assert := test.NewAssert(t)

	// load reference
	reference := NewGlobalStats()
	assert.NoError(reference.Load(refPath))

	snippets := GetSnippets()
	// for each circuit, on each curve, on each backend
	// compare with reference stats
	for name, c := range snippets {
		// check that we have it.
		ref, ok := reference.Stats[name]
		if !ok {
			assert.Log("warning: no stats for circuit", name)
			return
		}
		for _, curve := range c.Curves {
			for _, b := range backend.Implemented() {
				curve := curve
				backendID := b
				name := name
				// copy the circuit now in case assert calls t.Parallel()
				circuit := c.Circuit
				assert.Run(func(assert *test.Assert) {
					rs := ref[backendID][CurveIdx(curve)]

					s, err := NewSnippetStats(curve, backendID, circuit)
					assert.NoError(err, "building stats for circuit "+name)

					if s != rs {
						assert.Failf("unexpected stats count", "expected %s (reference), got %s. %s - %s - %s", rs, s, name, backendID.String(), curve.String())
					}
				}, name, curve.String(), backendID.String())
			}
		}

	}

}
