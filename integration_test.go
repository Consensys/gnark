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
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/backend/circuits"
	"github.com/stretchr/testify/require"
)

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

		t.Log(name)

		if testing.Short() {
			if name != "lut01" && name != "frombinary" {
				continue
			}
		}

		for _, curve := range curves {
			t.Log(curve.String())

			r1cs, err := frontend.Compile(curve, backend.GROTH16, circuit.Circuit)
			assert.NoError(err)

			pk, vk, err := groth16.Setup(r1cs)
			assert.NoError(err)

			correctProof, err := groth16.Prove(r1cs, pk, circuit.Good)
			assert.NoError(err)

			wrongProof, err := groth16.Prove(r1cs, pk, circuit.Bad, true)
			assert.NoError(err)

			assert.NoError(groth16.Verify(correctProof, vk, circuit.Public))
			assert.Error(groth16.Verify(wrongProof, vk, circuit.Public))

			// witness serialization tests.
			{
				buf.Reset()

				_, err := witness.WriteFullTo(&buf, curve, circuit.Good)
				assert.NoError(err)

				correctProof, err := groth16.ReadAndProve(r1cs, pk, &buf)
				assert.NoError(err)

				buf.Reset()

				_, err = witness.WritePublicTo(&buf, curve, circuit.Good)
				assert.NoError(err)

				err = groth16.ReadAndVerify(correctProof, vk, &buf)
				assert.NoError(err)
			}

		}
	}
}
