package gnark

import (
	"encoding/gob"
	"os"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
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
				backendID := b
				name := k
				// copy the circuit now in case assert calls t.Parallel()
				tData := circuits.Circuits[k]
				assert.Run(func(assert *test.Assert) {
					var newBuilder frontend.NewBuilder

					switch backendID {
					case backend.GROTH16:
						newBuilder = r1cs.NewBuilder
					case backend.PLONK:
						newBuilder = scs.NewBuilder
					default:
						panic("not implemented")
					}

					ccs, err := frontend.Compile(curve, newBuilder, tData.Circuit)
					assert.NoError(err)

					// ensure we didn't introduce regressions that make circuits less efficient
					nbConstraints := ccs.GetNbConstraints()
					internal, secret, public := ccs.GetNbVariables()
					checkStats(assert, name, nbConstraints, internal, secret, public, curve, backendID)
				}, name, curve.String(), backendID.String())
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

func checkStats(assert *test.Assert, circuitName string, nbConstraints, internal, secret, public int, curve ecc.ID, backendID backend.ID) {
	statsM.Lock()
	defer statsM.Unlock()
	if generateNewStats {
		rs := mStats[circuitName]
		rs[backendID][curve] = circuitStats{nbConstraints, internal, secret, public}
		mStats[circuitName] = rs
		return
	}
	if referenceStats, ok := mStats[circuitName]; !ok {
		assert.Log("warning: no stats for circuit", circuitName)
	} else {
		ref := referenceStats[backendID][curve]
		if ref.NbConstraints != nbConstraints {
			assert.Failf("unexpected constraint count", "expected %d nbConstraints (reference), got %d. %s, %s, %s", ref.NbConstraints, nbConstraints, circuitName, backendID.String(), curve.String())
		}
		if ref.Internal != internal {
			assert.Failf("unexpected internal variable count", "expected %d internal (reference), got %d. %s, %s, %s", ref.Internal, internal, circuitName, backendID.String(), curve.String())
		}
		if ref.Secret != secret {
			assert.Failf("unexpected secret variable count", "expected %d secret (reference), got %d. %s, %s, %s", ref.Secret, secret, circuitName, backendID.String(), curve.String())
		}
		if ref.Public != public {
			assert.Failf("unexpected public variable count", "expected %d public (reference), got %d. %s, %s, %s", ref.Public, public, circuitName, backendID.String(), curve.String())
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
