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

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/circuits"
	"github.com/consensys/gnark/encoding/gob"
	"github.com/consensys/gurvy"
)

func TestIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration tests for circleCI")
	}
	// create temporary dir for integration test
	parentDir := "./integration_test"
	os.RemoveAll(parentDir)
	defer os.RemoveAll(parentDir)
	if err := os.MkdirAll(parentDir, 0700); err != nil {
		t.Fatal(err)
	}

	// spv: setup, prove, verify
	spv := func(name string, good, bad map[string]interface{}) {
		t.Log("circuit", name)
		// path for files
		fCircuit := filepath.Join(parentDir, name+".r1cs")
		fPk := filepath.Join(parentDir, name+".pk")
		fVk := filepath.Join(parentDir, name+".vk")
		fProof := filepath.Join(parentDir, name+".proof")
		fInputGood := filepath.Join(parentDir, name+".good.input")
		fInputBad := filepath.Join(parentDir, name+".bad.input")

		buildTags := "debug"

		// 2: input files to disk
		if err := backend.WriteVariables(fInputGood, good); err != nil {
			t.Fatal(err)
		}
		if err := backend.WriteVariables(fInputBad, bad); err != nil {
			t.Fatal(err)
		}

		// 3: run setup
		{
			cmd := exec.Command("go", "run", "-tags", buildTags, "main.go", "setup", fCircuit, "--pk", fPk, "--vk", fVk)
			out, err := cmd.CombinedOutput()
			t.Log(string(out))

			if err != nil {
				t.Fatal(err)
			}
		}

		pv := func(fInput string, expectedVerifyResult bool) {
			// 4: run prove
			{
				cmd := exec.Command("go", "run", "-tags", buildTags, "main.go", "prove", fCircuit, "--pk", fPk, "--input", fInput, "--proof", fProof)
				out, err := cmd.CombinedOutput()
				t.Log(string(out))
				if expectedVerifyResult && err != nil {
					// proving should pass
					t.Fatal(err)
				}
			}

			// 4: run verify
			{
				cmd := exec.Command("go", "run", "-tags", buildTags, "main.go", "verify", fProof, "--vk", fVk, "--input", fInput)
				out, err := cmd.CombinedOutput()
				t.Log(string(out))
				if expectedVerifyResult && err != nil {
					t.Fatal(err)
				} else if !expectedVerifyResult && err == nil {
					t.Fatal("verify should have failed but apparently succeeded")
				}
			}
		}

		pv(fInputGood, true)
		pv(fInputBad, false)
	}

	curves := []gurvy.ID{gurvy.BLS377, gurvy.BLS381, gurvy.BN256}

	for name, circuit := range circuits.Circuits {
		if name == "reference_large" {
			// be nice with circleci.
			continue
		}
		for _, curve := range curves {
			// serialize to disk
			fCircuit := filepath.Join(parentDir, name+".r1cs")
			typedR1CS := circuit.R1CS.ToR1CS(curve)
			if err := gob.Write(fCircuit, typedR1CS, curve); err != nil {
				t.Fatal(err)
			}
			spv(name, circuit.Good, circuit.Bad)
		}
	}
}
