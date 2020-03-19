// +build !dispatcher

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

// Package cmd is a CLI tool to use gnark framework
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/curve"
	"github.com/consensys/gnark/internal/templates/generator"
	"github.com/consensys/gnark/utils/encoding/gob"
	"github.com/spf13/cobra"
)

func cmdProve(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println("missing circuit path -- gnark prove -h for help")
		os.Exit(-1)
	}
	circuitPath := filepath.Clean(args[0])
	circuitName := filepath.Base(circuitPath)
	circuitExt := filepath.Ext(circuitName)
	circuitName = circuitName[0 : len(circuitName)-len(circuitExt)]

	// ensure pk and input flags are set and valid
	if fPkPath == "" {
		fmt.Println("please specify proving key path")
		_ = cmd.Usage()
		os.Exit(-1)
	}
	if fInputPath == "" {
		fmt.Println("please specify input file path")
		_ = cmd.Usage()
		os.Exit(-1)
	}
	fPkPath = filepath.Clean(fPkPath)
	if !fileExists(fPkPath) {
		fmt.Println(fPkPath, errNotFound)
		os.Exit(-1)
	}
	fInputPath = filepath.Clean(fInputPath)
	if !fileExists(fInputPath) {
		fmt.Println(fInputPath, errNotFound)
		os.Exit(-1)
	}

	// load circuit
	r1cs, err := loadCircuit(circuitPath)
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(-1)
	}
	fmt.Printf("%-30s %-30s %-d constraints\n", "loaded circuit", circuitPath, r1cs.NbConstraints)

	// parse proving key
	var pk groth16.ProvingKey
	if err := gob.Read(fPkPath, &pk, curve.ID); err != nil {
		fmt.Println("can't load proving key")
		fmt.Println(err)
		os.Exit(-1)
	}
	fmt.Printf("%-30s %-30s\n", "loaded proving key", fPkPath)

	// parse input file
	r1csInput := backend.NewAssignment()
	err = r1csInput.Read(fInputPath)
	if err != nil {
		fmt.Println("can't parse input", err)
		os.Exit(-1)
	}
	fmt.Printf("%-30s %-30s %-d inputs\n", "loaded input", fInputPath, len(r1csInput))

	// compute proof
	start := time.Now()
	proof, err := groth16.Prove(r1cs, &pk, r1csInput)
	if err != nil {
		fmt.Println("Error proof generation", err)
		os.Exit(-1)
	}
	for i := uint(1); i < fCount; i++ {
		_, _ = groth16.Prove(r1cs, &pk, r1csInput)
	}
	duration := time.Since(start)
	if fCount > 1 {
		duration = time.Duration(int64(duration) / int64(fCount))
	}

	// default proof path
	proofPath := filepath.Join(".", circuitName+".proof")
	if fProofPath != "" {
		proofPath = fProofPath
	}

	if err := gob.Write(proofPath, proof, curve.ID); err != nil {
		fmt.Println("error:", err)
		os.Exit(-1)
	}

	fmt.Printf("%-30s %-30s %-30s\n", "generated proof", proofPath, duration)
}

func cmdSetup(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println("missing circuit path -- gnark setup -h for help")
		os.Exit(-1)
	}
	circuitPath := filepath.Clean(args[0])
	circuitName := filepath.Base(circuitPath)
	circuitExt := filepath.Ext(circuitName)
	circuitName = circuitName[0 : len(circuitName)-len(circuitExt)]

	vkPath := filepath.Join(".", circuitName+".vk")
	pkPath := filepath.Join(".", circuitName+".pk")

	if fVkPath != "" {
		vkPath = fVkPath
	}
	if fPkPath != "" {
		pkPath = fPkPath
	}

	// load circuit
	r1cs, err := loadCircuit(circuitPath)
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(-1)
	}
	fmt.Printf("%-30s %-30s %-d constraints\n", "loaded circuit", circuitPath, r1cs.NbConstraints)

	// run setup
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	start := time.Now()
	groth16.Setup(r1cs, &pk, &vk)
	duration := time.Since(start)
	fmt.Printf("%-30s %-30s %-30s\n", "setup completed", "", duration)

	if err := gob.Write(vkPath, &vk, curve.ID); err != nil {
		fmt.Println("error:", err)
		os.Exit(-1)
	}
	fmt.Printf("%-30s %s\n", "generated verifying key", vkPath)
	if err := gob.Write(pkPath, &pk, curve.ID); err != nil {
		fmt.Println("error:", err)
		os.Exit(-1)
	}
	fmt.Printf("%-30s %s\n", "generated proving key", pkPath)
}

func cmdVerify(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println("missing proof path -- gnark verify -h for help")
		os.Exit(-1)
	}
	proofPath := filepath.Clean(args[0])

	// ensure vk and input flags are set and valid
	if fVkPath == "" {
		fmt.Println("please specify verifying key path")
		_ = cmd.Usage()
		os.Exit(-1)
	}
	if fInputPath == "" {
		fmt.Println("please specify input file path")
		_ = cmd.Usage()
		os.Exit(-1)
	}
	fVkPath = filepath.Clean(fVkPath)
	if !fileExists(fVkPath) {
		fmt.Println(fVkPath, errNotFound)
		os.Exit(-1)
	}
	fInputPath = filepath.Clean(fInputPath)
	if !fileExists(fInputPath) {
		fmt.Println(fInputPath, errNotFound)
		os.Exit(-1)
	}

	// parse verifying key
	var vk groth16.VerifyingKey
	if err := gob.Read(fVkPath, &vk, curve.ID); err != nil {
		fmt.Println("can't load verifying key")
		fmt.Println(err)
		os.Exit(-1)
	}
	fmt.Printf("%-30s %-30s\n", "loaded verifying key", fVkPath)

	// parse input file
	r1csInput := backend.NewAssignment()
	err := r1csInput.Read(fInputPath)
	if err != nil {
		fmt.Println("can't parse input", err)
		os.Exit(-1)
	}
	fmt.Printf("%-30s %-30s %-d inputs\n", "loaded input", fInputPath, len(r1csInput))
	if len(vk.PublicInputs)-1 != len(r1csInput) {
		fmt.Printf("invalid input size. expected %d got %d\n", len(vk.PublicInputs), len(r1csInput))
		os.Exit(-1)
	}

	// load proof
	var proof groth16.Proof
	if err := gob.Read(proofPath, &proof, curve.ID); err != nil {
		fmt.Println("can't parse proof", err)
		os.Exit(-1)
	}

	// verify proof
	start := time.Now()
	result, err := groth16.Verify(&proof, &vk, r1csInput)
	if err != nil || !result {
		fmt.Printf("%-30s %-30s %-30s\n", "proof is invalid", proofPath, time.Since(start))
		if err != nil {
			fmt.Println(err)
		}
		os.Exit(-1)
	}
	fmt.Printf("%-30s %-30s %-30s\n", "proof is valid", proofPath, time.Since(start))
}

func loadCircuit(circuitPath string) (*backend.R1CS, error) {
	// first, let's ensure provided circuit exists.
	if !fileExists(circuitPath) {
		return nil, errNotFound
	}

	// now let's deserialize the R1CS
	var circuit backend.R1CS
	if err := gob.Read(circuitPath, &circuit, curve.ID); err != nil {
		return nil, err
	}
	return &circuit, nil
}

func cmdExport(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println("missing circuit path -- gnark prove -h for help")
		os.Exit(-1)
	}
	circuitPath := filepath.Clean(args[0])
	circuitName := filepath.Base(circuitPath)
	circuitExt := filepath.Ext(circuitName)
	circuitName = circuitName[0 : len(circuitName)-len(circuitExt)]

	if !fGo {
		fmt.Println("--go not set")
		os.Exit(-1)
	}
	if fPackageName == "" {
		fmt.Println("--package not set")
		os.Exit(-1)
	}

	// load circuit
	r1cs, err := loadCircuit(circuitPath)
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(-1)
	}
	fmt.Printf("%-30s %-30s %-d constraints\n", "loaded circuit", circuitPath, r1cs.NbConstraints)

	// create output dir, if it doesn't exist
	fOutputDir = filepath.Clean(fOutputDir)
	if err := os.MkdirAll(filepath.Join(fOutputDir, "groth16"), 0700); err != nil {
		fmt.Println("can't create output dir:", err)
		os.Exit(-1)
	}

	d := generator.GenerateData{
		fOutputDir,
		strings.ToUpper(curve.ID.String()),
	}
	if err := generator.GenerateGroth16(d); err != nil {
		fmt.Println("can't generate groth16 code:", err)
		os.Exit(-1)
	}

}
