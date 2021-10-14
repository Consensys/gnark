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
	"bytes"
	"encoding/gob"
	"os"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/backend/circuits"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
)

const (
	fileStats        = "init.stats"
	generateNewStats = false
)

func TestIntegrationAPINew(t *testing.T) {
	assert := require.New(t)
	for name, v := range circuits.NewCircuits {
		t.Log("testing", name)
		assert.NoError(test.Run(v))
		if f, ok := v.(frontend.FuzzableCircuit); ok {
			t.Log("fuzzing", name)
			assert.NoError(test.Fuzz(f))
		}
	}
}

func TestIntegrationAPI(t *testing.T) {

	assert := require.New(t)

	// create temporary dir for integration test
	parentDir := "./integration_test"
	os.RemoveAll(parentDir)
	defer os.RemoveAll(parentDir)
	if err := os.MkdirAll(parentDir, 0700); err != nil {
		t.Fatal(err)
	}

	curves := []ecc.ID{ecc.BN254, ecc.BLS12_377, ecc.BLS12_381, ecc.BW6_761, ecc.BLS24_315}
	var buf bytes.Buffer
	for name, circuit := range circuits.Circuits {

		if testing.Short() {
			if name == "reference_small" {
				continue
			}
		}

		for _, curve := range curves {
			{
				t.Log(name, curve.String(), "groth16")

				ccs1, err := frontend.Compile(curve, backend.GROTH16, circuit.Circuit)
				assert.NoError(err)

				ccs, err := frontend.Compile(curve, backend.GROTH16, circuit.Circuit)
				assert.NoError(err)

				if !reflect.DeepEqual(ccs, ccs1) {
					// cs may have been mutated, or output data struct is not deterministic
					t.Fatal("compiling CS -> R1CS is not deterministic")
				}

				// ensure we didn't introduce regressions that make circuits less efficient
				nbConstraints := ccs.GetNbConstraints()
				internal, secret, public := ccs.GetNbVariables()
				checkStats(t, name, nbConstraints, internal, secret, public, curve, backend.GROTH16)

				if !generateNewStats {
					pk, vk, err := groth16.Setup(ccs)
					assert.NoError(err)

					correctProof, err := groth16.Prove(ccs, pk, circuit.Good)
					assert.NoError(err)

					wrongProof, err := groth16.Prove(ccs, pk, circuit.Bad, backend.IgnoreSolverError)
					assert.NoError(err)

					assert.NoError(groth16.Verify(correctProof, vk, circuit.Good))
					assert.Error(groth16.Verify(wrongProof, vk, circuit.Good))

					// witness serialization tests.
					{
						buf.Reset()

						_, err := witness.WriteFullTo(&buf, curve, circuit.Good)
						assert.NoError(err)

						correctProof, err := groth16.ReadAndProve(ccs, pk, &buf)
						assert.NoError(err)

						buf.Reset()

						_, err = witness.WritePublicTo(&buf, curve, circuit.Good)
						assert.NoError(err)

						err = groth16.ReadAndVerify(correctProof, vk, &buf)
						assert.NoError(err)
					}
				}

			}
			{
				t.Log(name, curve.String(), "plonk")

				ccs1, err := frontend.Compile(curve, backend.PLONK, circuit.Circuit)
				assert.NoError(err)

				ccs, err := frontend.Compile(curve, backend.PLONK, circuit.Circuit)
				assert.NoError(err)

				if !reflect.DeepEqual(ccs, ccs1) {
					// cs may have been mutated, or output data struct is not deterministic
					t.Fatal("compiling CS -> SparseR1CS is not deterministic")
				}

				// ensure we didn't introduce regressions that make circuits less efficient
				nbConstraints := ccs.GetNbConstraints()
				internal, secret, public := ccs.GetNbVariables()
				checkStats(t, name, nbConstraints, internal, secret, public, curve, backend.PLONK)
				if generateNewStats {
					continue
				}
				srs, err := plonk.NewSRS(ccs)
				assert.NoError(err)

				pk, vk, err := plonk.Setup(ccs, srs)
				assert.NoError(err)

				correctProof, err := plonk.Prove(ccs, pk, circuit.Good)
				assert.NoError(err)

				wrongProof, err := plonk.Prove(ccs, pk, circuit.Bad, backend.IgnoreSolverError)
				assert.NoError(err)

				assert.NoError(plonk.Verify(correctProof, vk, circuit.Good))
				assert.Error(plonk.Verify(wrongProof, vk, circuit.Good))

				// witness serialization tests.
				{
					buf.Reset()

					_, err := witness.WriteFullTo(&buf, curve, circuit.Good)
					assert.NoError(err)

					correctProof, err := plonk.ReadAndProve(ccs, pk, &buf)
					assert.NoError(err)

					buf.Reset()

					_, err = witness.WritePublicTo(&buf, curve, circuit.Good)
					assert.NoError(err)

					err = plonk.ReadAndVerify(correctProof, vk, &buf)
					assert.NoError(err)
				}

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
