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

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/backend/circuits"
	"github.com/consensys/gnark/io"
	"github.com/consensys/gurvy"
)

func TestIntegrationCLI(t *testing.T) {

	// create temporary dir for integration test
	parentDir := "./integration_test"
	os.RemoveAll(parentDir)
	defer os.RemoveAll(parentDir)
	if err := os.MkdirAll(parentDir, 0700); err != nil {
		t.Fatal(err)
	}

	// spv: setup, prove, verify
	spv := func(curveID gurvy.ID, name string, _good, _bad, _public frontend.Circuit) {

		t.Logf("%s circuit (%s)", name, curveID.String())

		// path for files
		fCircuit := filepath.Join(parentDir, name+".r1cs")
		fPk := filepath.Join(parentDir, name+".pk")
		fVk := filepath.Join(parentDir, name+".vk")
		fProof := filepath.Join(parentDir, name+".proof")

		fInputGoodProver := filepath.Join(parentDir, name+"_prover.good.input")
		fInputBadProver := filepath.Join(parentDir, name+"_prover.bad.input")

		fInputVerifier := filepath.Join(parentDir, name+"_public.good.input")

		// 2: input files to disk

		// 2.1 data for the prover
		proverGood, err := frontend.ParseSecretWitness(_good)
		if err != nil {
			panic("invalid good secret assignment:" + err.Error())
		}
		proverBad, err := frontend.ParseSecretWitness(_bad)
		if err != nil {
			panic("invalid bad secret assignment:" + err.Error())
		}

		// 2.2 data for the verifier
		verifier, err := frontend.ParsePublicWitness(_public)
		if err != nil {
			panic("invalid good public assignment:" + err.Error())
		}

		// 2.3  dump prover data on disk
		if err := io.WriteWitness(fInputGoodProver, proverGood); err != nil {
			t.Fatal(err)
		}
		if err := io.WriteWitness(fInputBadProver, proverBad); err != nil {
			t.Fatal(err)
		}

		// 2.4 dump verifier data on disk
		if err := io.WriteWitness(fInputVerifier, verifier); err != nil {
			t.Fatal(err)
		}

		// 3: run setup
		{
			cmd := exec.Command("go", "run", "main.go", "setup", fCircuit, "--pk", fPk, "--vk", fVk)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Log(string(out))
				t.Fatal(err)
			}
		}

		pv := func(fInputProver, fInputVerifier string, expectedVerifyResult bool) {
			// 4: run prove
			{
				cmd := exec.Command("go", "run", "main.go", "prove", fCircuit, "--pk", fPk, "--input", fInputProver, "--proof", fProof)
				out, err := cmd.CombinedOutput()
				if expectedVerifyResult && err != nil {
					t.Log(string(out))
					t.Fatal(err)
				}
			}

			// note: here we ain't testing much when the prover failed. verify will not find a proof file, and that's it.

			// 4: run verify
			{
				cmd := exec.Command("go", "run", "main.go", "verify", fProof, "--vk", fVk, "--input", fInputVerifier)
				out, err := cmd.CombinedOutput()
				if expectedVerifyResult && err != nil {
					t.Log(string(out))
					t.Fatal(err)
				} else if !expectedVerifyResult && err == nil {
					t.Log(string(out))
					t.Fatal("verify should have failed but apparently succeeded")
				}
			}
		}

		pv(fInputGoodProver, fInputVerifier, true)
		pv(fInputBadProver, fInputVerifier, false)
	}

	curves := []gurvy.ID{gurvy.BN256, gurvy.BLS377, gurvy.BLS381, gurvy.BW761}

	for name, circuit := range circuits.Circuits {

		if testing.Short() {
			if name != "lut01" && name != "frombinary" {
				continue
			}
		}
		for _, curve := range curves {
			// serialize to disk
			fCircuit := filepath.Join(parentDir, name+".r1cs")
			typedR1CS := circuit.R1CS.ToR1CS(curve)
			if err := io.WriteFile(fCircuit, typedR1CS); err != nil {
				t.Fatal(err)
			}
			spv(curve, name, circuit.Good, circuit.Bad, circuit.Public)
		}
	}
}

func TestIntegrationAPI(t *testing.T) {

	// create temporary dir for integration test
	parentDir := "./integration_test"
	os.RemoveAll(parentDir)
	defer os.RemoveAll(parentDir)
	if err := os.MkdirAll(parentDir, 0700); err != nil {
		t.Fatal(err)
	}

	curves := []gurvy.ID{gurvy.BN256, gurvy.BLS377, gurvy.BLS381, gurvy.BW761}

	for name, circuit := range circuits.Circuits {

		if testing.Short() {
			if name != "lut01" && name != "frombinary" {
				continue
			}
		}
		for _, curve := range curves {

			typedR1CS := circuit.R1CS.ToR1CS(curve)

			pk, vk := groth16.Setup(typedR1CS)
			correctProof, err := groth16.Prove(typedR1CS, pk, circuit.Good)
			if err != nil {
				t.Fatal(err)
			}
			wrongProof, err := groth16.Prove(typedR1CS, pk, circuit.Bad, groth16.Unsafe)
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

		}
	}

}
