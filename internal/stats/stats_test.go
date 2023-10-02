package stats

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/stretchr/testify/require"
)

func TestCircuitStatistics(t *testing.T) {
	const refPath = "latest.stats"
	assert := require.New(t)

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
			t.Log("warning: no stats for circuit", name)
			return
		}
		for _, curve := range c.Curves {
			for _, b := range backend.Implemented() {
				curve := curve
				backendID := b
				name := name
				// copy the circuit now in case assert calls t.Parallel()
				circuit := c.Circuit
				t.Run(fmt.Sprintf("%s/%s/%s", name, curve.String(), backendID.String()), func(t *testing.T) {
					assert := require.New(t)
					rs := ref[backendID][CurveIdx(curve)]

					s, err := NewSnippetStats(curve, backendID, circuit)
					assert.NoError(err, "building stats for circuit "+name)

					if s != rs {
						assert.Failf("unexpected stats count", "expected %s (reference), got %s. %s - %s - %s", rs, s, name, backendID.String(), curve.String())
					}
				})
			}
		}

	}

}
