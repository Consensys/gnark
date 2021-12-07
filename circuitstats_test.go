package gnark

import (
	"encoding/gob"
	"os"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/backend/circuits"
	"github.com/consensys/gnark/test"
)

const (
	fileStats        = "init.stats"
	generateNewStats = false
)

var statsM sync.Mutex

func TestCircuitStatistics(t *testing.T) {
	assert := test.NewAssert(t)
	for k := range circuits.Circuits {
		for _, curve := range ecc.Implemented() {
			for _, b := range backend.Implemented() {
				curve := curve
				b := b
				name := k
				// copy the circuit now in case assert calls t.Parallel()
				tData := circuits.Circuits[k]
				assert.Run(func(assert *test.Assert) {
					ccs, err := frontend.Compile(curve, b, tData.Circuit)
					assert.NoError(err)

					// ensure we didn't introduce regressions that make circuits less efficient
					nbConstraints := ccs.GetNbConstraints()
					internal, secret, public := ccs.GetNbVariables()
					checkStats(t, name, nbConstraints, internal, secret, public, curve, b)
				}, name, curve.String(), b.String())
			}
		}

	}

	// serialize newStats
	if generateNewStats {
		fStats, err := os.Create(fileStats)
		assert.NoError(err)

		encoder := gob.NewEncoder(fStats)
		err = encoder.Encode(mStats)
		assert.NoError(err)
	}
}

type circuitStats struct {
	NbConstraints, Internal, Secret, Public int
}

var mStats map[string][backend.PLONK + 1][ecc.BW6_633 + 1]circuitStats

func checkStats(t *testing.T, circuitName string, nbConstraints, internal, secret, public int, curve ecc.ID, backendID backend.ID) {
	statsM.Lock()
	defer statsM.Unlock()
	if generateNewStats {
		rs := mStats[circuitName]
		rs[backendID][curve] = circuitStats{nbConstraints, internal, secret, public}
		mStats[circuitName] = rs
		return
	}
	if referenceStats, ok := mStats[circuitName]; !ok {
		t.Log("warning: no stats for circuit", circuitName)
	} else {
		ref := referenceStats[backendID][curve]
		if ref.NbConstraints != nbConstraints {
			t.Errorf("expected %d nbConstraints (reference), got %d. %s, %s, %s", ref.NbConstraints, nbConstraints, circuitName, backendID.String(), curve.String())
		}
		if ref.Internal != internal {
			t.Errorf("expected %d internal (reference), got %d. %s, %s, %s", ref.Internal, internal, circuitName, backendID.String(), curve.String())
		}
		if ref.Secret != secret {
			t.Errorf("expected %d secret (reference), got %d. %s, %s, %s", ref.Secret, secret, circuitName, backendID.String(), curve.String())
		}
		if ref.Public != public {
			t.Errorf("expected %d public (reference), got %d. %s, %s, %s", ref.Public, public, circuitName, backendID.String(), curve.String())
		}
	}
}

func init() {
	mStats = make(map[string][backend.PLONK + 1][ecc.BW6_633 + 1]circuitStats)

	if !generateNewStats {
		fStats, err := os.Open(fileStats)
		if err != nil {
			panic(err)
		}
		decoder := gob.NewDecoder(fStats)
		err = decoder.Decode(&mStats)
		if err != nil {
			panic(err)
		}
	}

}
