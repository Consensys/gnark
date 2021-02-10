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

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/backend/circuits"
	"github.com/consensys/gurvy"
)

func TestIntegrationAPI(t *testing.T) {

	// create temporary dir for integration test
	parentDir := "./integration_test"
	os.RemoveAll(parentDir)
	defer os.RemoveAll(parentDir)
	if err := os.MkdirAll(parentDir, 0700); err != nil {
		t.Fatal(err)
	}

	curves := []gurvy.ID{gurvy.BN256, gurvy.BLS377, gurvy.BLS381, gurvy.BW761}
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
			if err != nil {
				t.Fatal(err)
			}

			pk, vk, err := groth16.Setup(r1cs)
			if err != nil {
				t.Fatal(err)
			}
			correctProof, err := groth16.Prove(r1cs, pk, circuit.Good)
			if err != nil {
				t.Fatal(err)
			}
			wrongProof, err := groth16.Prove(r1cs, pk, circuit.Bad, true)
			if err != nil {
				t.Fatal(err)
			}

			err = groth16.Verify(correctProof, vk, circuit.Public)
			if err != nil {
				t.Fatal("Verify should have succeeded")
			}
			err = groth16.Verify(wrongProof, vk, circuit.Public)
			if err == nil {
				t.Fatal("Verify should have failed")
			}

			// witness serialization tests.
			{
				buf.Reset()
				if err = witness.WriteFull(&buf, circuit.Good, curve); err != nil {
					t.Fatal("serializing full witness failed.", err)
				}
				correctProof, err := groth16.DeserializeAndProve(r1cs, pk, buf.Bytes())
				if err != nil {
					t.Fatal(err)
				}
				buf.Reset()
				if err = witness.WritePublic(&buf, circuit.Public, curve); err != nil {
					t.Fatal("serializing public witness failed.")
				}
				if err = groth16.DeserializeAndVerify(correctProof, vk, buf.Bytes()); err != nil {
					t.Fatal("DeserializeAndVerify should have succeeded", err)
				}
			}

		}
	}
}
