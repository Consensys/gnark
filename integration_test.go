/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gnark

import (
	"encoding/gob"
	"os"
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

func TestIntegrationAPI(t *testing.T) {

	assert := test.NewAssert(t)

	// create temporary dir for integration test
	parentDir := "./integration_test"
	os.RemoveAll(parentDir)
	defer os.RemoveAll(parentDir)
	if err := os.MkdirAll(parentDir, 0700); err != nil {
		t.Fatal(err)
	}

	curves := []ecc.ID{ecc.BN254, ecc.BLS12_377, ecc.BLS12_381, ecc.BW6_761, ecc.BLS24_315}
	for name, circuit := range circuits.Circuits {

		if testing.Short() {
			if name == "reference_small" {
				continue
			}
		}

		assert.ProverSucceeded(circuit.Circuit, circuit.Good)
		assert.ProverFailed(circuit.Circuit, circuit.Bad)

		for _, curve := range curves {
			{
				t.Log(name, curve.String(), "groth16")

				ccs, err := frontend.Compile(curve, backend.GROTH16, circuit.Circuit)
				assert.NoError(err)

				// ensure we didn't introduce regressions that make circuits less efficient
				nbConstraints := ccs.GetNbConstraints()
				internal, secret, public := ccs.GetNbVariables()
				checkStats(t, name, nbConstraints, internal, secret, public, curve, backend.GROTH16)

			}
			{
				t.Log(name, curve.String(), "plonk")

				ccs, err := frontend.Compile(curve, backend.PLONK, circuit.Circuit)
				assert.NoError(err)

				// ensure we didn't introduce regressions that make circuits less efficient
				nbConstraints := ccs.GetNbConstraints()
				internal, secret, public := ccs.GetNbVariables()
				checkStats(t, name, nbConstraints, internal, secret, public, curve, backend.PLONK)
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
