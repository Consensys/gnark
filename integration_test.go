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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/curve"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/utils/encoding/gob"
)

func TestIntegration(t *testing.T) {
	// create temporary dir for integration test
	parentDir := "./internal/tests/integration"
	os.RemoveAll(parentDir)
	if err := os.Mkdir(parentDir, 0700); err != nil {
		t.Fatal(err)
	}

	// path for files
	fCircuit := filepath.Join(parentDir, "testcircuit.r1cs")
	fPk := filepath.Join(parentDir, "testcircuit.pk")
	fVk := filepath.Join(parentDir, "testcircuit.vk")
	fProof := filepath.Join(parentDir, "testcircuit.proof")
	fInput := filepath.Join(parentDir, "testcircuit.input")
	fPublicInput := filepath.Join(parentDir, "testcircuit.public.input")

	c, good, bad := testCircuit()

	// 1: serialize circuit to disk
	if err := gob.Write(fCircuit, c, curve.ID); err != nil {
		t.Fatal(err)
	}

	// spv: setup, prove, verify
	spv := func(x backend.Assignments, expectedVerifyResult bool) {
		buildTags := curve.ID.String() + ",debug"
		// 2: input files to disk
		if err := x.Write(fInput); err != nil {
			t.Fatal(err)
		}
		y := filterOutPrivateAssignment(x)
		if err := y.Write(fPublicInput); err != nil {
			t.Fatal(err)
		}

		// 3: run setup
		{
			cmd := exec.Command("go", "run", "-tags", buildTags, "main.go", "setup", fCircuit, "--pk", fPk, "--vk", fVk)
			out, err := cmd.Output()
			t.Log(string(out))

			if err != nil {
				t.Fatal(err)
			}
		}

		// 4: run prove
		{
			cmd := exec.Command("go", "run", "-tags", buildTags, "main.go", "prove", fCircuit, "--pk", fPk, "--input", fInput, "--proof", fProof)
			out, err := cmd.Output()
			t.Log(string(out))
			if expectedVerifyResult && err != nil {
				// proving should pass
				t.Fatal(err)
			}
		}

		// 4: run verify
		{
			cmd := exec.Command("go", "run", "-tags", buildTags, "main.go", "verify", fProof, "--vk", fVk, "--input", fPublicInput)
			out, err := cmd.Output()
			t.Log(string(out))
			if expectedVerifyResult && err != nil {
				t.Fatal(err)
			} else if !expectedVerifyResult && err == nil {
				t.Fatal("verify should have failed but apparently succeeded")
			}
		}

	}

	spv(good, true)
	spv(bad, false)

}

func filterOutPrivateAssignment(assignments backend.Assignments) backend.Assignments {
	toReturn := backend.NewAssignment()
	for k, v := range assignments {
		if v.IsPublic {
			toReturn[k] = v
		}
	}

	return toReturn
}

func testCircuit() (*backend.R1CS, backend.Assignments, backend.Assignments) {
	circuit := frontend.New()

	// declare inputs
	x := circuit.SECRET_INPUT("x")
	y := circuit.PUBLIC_INPUT("y")

	const nbConstraints = 5

	for i := 0; i < nbConstraints; i++ {
		x = circuit.MUL(x, x)
		x.Tag(fmt.Sprintf("x^%d", i+2))
	}
	circuit.MUSTBE_EQ(x, y)

	good := backend.NewAssignment()
	good.Assign(backend.Secret, "x", 2)

	// compute expected Y
	expectedY := frontend.Element(2)

	for i := 0; i < nbConstraints; i++ {
		expectedY.MulAssign(&expectedY)
	}

	good.Assign(backend.Public, "y", expectedY)

	bad := backend.NewAssignment()
	bad.Assign(backend.Secret, "x", 2)
	bad.Assign(backend.Public, "y", 3)

	return circuit.ToR1CS(), good, bad
}
