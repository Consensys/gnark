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

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	backend_bls377 "github.com/consensys/gnark/backend/static/bls377"
	groth16_bls377 "github.com/consensys/gnark/backend/static/bls377/groth16"
	backend_bls381 "github.com/consensys/gnark/backend/static/bls381"
	groth16_bls381 "github.com/consensys/gnark/backend/static/bls381/groth16"
	backend_bn256 "github.com/consensys/gnark/backend/static/bn256"
	groth16_bn256 "github.com/consensys/gnark/backend/static/bn256/groth16"
	"github.com/consensys/gnark/internal/utils/encoding/gob"
	"github.com/consensys/gurvy"
	"github.com/spf13/cobra"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:     "verify [proof]",
	Short:   "verifies a proof against a verifying key and a partial / public solution",
	Run:     cmdVerify,
	Version: Version,
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	verifyCmd.PersistentFlags().StringVar(&fVkPath, "vk", "", "specifies full path for verifying key")
	verifyCmd.PersistentFlags().StringVar(&fInputPath, "input", "", "specifies full path for input file")

	_ = verifyCmd.MarkPersistentFlagRequired("vk")
	_ = verifyCmd.MarkPersistentFlagRequired("input")
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
	if !fileExists(fVkPath) {
		fmt.Println("error:", errNotFound)
		os.Exit(-1)
	}

	// check curve ID
	curveID, err := gob.PeekCurveID(fVkPath)
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(-1)
	}

	// TODO clean that up with interfaces and type casts
	switch curveID {
	case gurvy.BLS377:
		var vk groth16_bls377.VerifyingKey
		if err := gob.Read(fVkPath, &vk, curveID); err != nil {
			fmt.Println("can't load verifying key")
			fmt.Println(err)
			os.Exit(-1)
		}
		fmt.Printf("%-30s %-30s\n", "loaded verifying key", fVkPath)

		// parse input file
		r1csInput := backend_bls377.NewAssignment()
		err := r1csInput.ReadFile(fInputPath)
		if err != nil {
			fmt.Println("can't parse input", err)
			os.Exit(-1)
		}
		fmt.Printf("%-30s %-30s %-d inputs\n", "loaded input", fInputPath, len(r1csInput))

		// load proof
		var proof groth16_bls377.Proof
		if err := gob.Read(proofPath, &proof, curveID); err != nil {
			fmt.Println("can't parse proof", err)
			os.Exit(-1)
		}

		// verify proof
		start := time.Now()
		result, err := groth16_bls377.Verify(&proof, &vk, r1csInput)
		if err != nil || !result {
			fmt.Printf("%-30s %-30s %-30s\n", "proof is invalid", proofPath, time.Since(start))
			if err != nil {
				fmt.Println(err)
			}
			os.Exit(-1)
		}
		fmt.Printf("%-30s %-30s %-30s\n", "proof is valid", proofPath, time.Since(start))
	case gurvy.BLS381:
		var vk groth16_bls381.VerifyingKey
		if err := gob.Read(fVkPath, &vk, curveID); err != nil {
			fmt.Println("can't load verifying key")
			fmt.Println(err)
			os.Exit(-1)
		}
		fmt.Printf("%-30s %-30s\n", "loaded verifying key", fVkPath)

		// parse input file
		r1csInput := backend_bls381.NewAssignment()
		err := r1csInput.ReadFile(fInputPath)
		if err != nil {
			fmt.Println("can't parse input", err)
			os.Exit(-1)
		}
		fmt.Printf("%-30s %-30s %-d inputs\n", "loaded input", fInputPath, len(r1csInput))

		// load proof
		var proof groth16_bls381.Proof
		if err := gob.Read(proofPath, &proof, curveID); err != nil {
			fmt.Println("can't parse proof", err)
			os.Exit(-1)
		}

		// verify proof
		start := time.Now()
		result, err := groth16_bls381.Verify(&proof, &vk, r1csInput)
		if err != nil || !result {
			fmt.Printf("%-30s %-30s %-30s\n", "proof is invalid", proofPath, time.Since(start))
			if err != nil {
				fmt.Println(err)
			}
			os.Exit(-1)
		}
		fmt.Printf("%-30s %-30s %-30s\n", "proof is valid", proofPath, time.Since(start))
	case gurvy.BN256:
		var vk groth16_bn256.VerifyingKey
		if err := gob.Read(fVkPath, &vk, curveID); err != nil {
			fmt.Println("can't load verifying key")
			fmt.Println(err)
			os.Exit(-1)
		}
		fmt.Printf("%-30s %-30s\n", "loaded verifying key", fVkPath)

		// parse input file
		r1csInput := backend_bn256.NewAssignment()
		err := r1csInput.ReadFile(fInputPath)
		if err != nil {
			fmt.Println("can't parse input", err)
			os.Exit(-1)
		}
		fmt.Printf("%-30s %-30s %-d inputs\n", "loaded input", fInputPath, len(r1csInput))

		// load proof
		var proof groth16_bn256.Proof
		if err := gob.Read(proofPath, &proof, curveID); err != nil {
			fmt.Println("can't parse proof", err)
			os.Exit(-1)
		}

		// verify proof
		start := time.Now()
		result, err := groth16_bn256.Verify(&proof, &vk, r1csInput)
		if err != nil || !result {
			fmt.Printf("%-30s %-30s %-30s\n", "proof is invalid", proofPath, time.Since(start))
			if err != nil {
				fmt.Println(err)
			}
			os.Exit(-1)
		}
		fmt.Printf("%-30s %-30s %-30s\n", "proof is valid", proofPath, time.Since(start))
	default:
		fmt.Println("error:", errUnknownCurve)
		os.Exit(-1)
	}

}
