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

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
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

	vk, err := groth16.ReadVerifyingKey(fVkPath)
	if err != nil {
		fmt.Println("can't load verifying key")
		fmt.Println(err)
		os.Exit(-1)
	}

	// parse input file
	// TODO fix serialization here
	r1csInput := make(map[string]interface{})
	if err := backend.ReadVariables(fInputPath, r1csInput); err != nil {
		fmt.Println("can't parse input", err)
		os.Exit(-1)
	}
	fmt.Printf("%-30s %-30s %-d inputs\n", "loaded input", fInputPath, len(r1csInput))

	// load proof
	proof, err := groth16.ReadProof(proofPath)
	if err != nil {
		fmt.Println("can't parse proof", err)
		os.Exit(-1)
	}

	// verify proof
	start := time.Now()
	if err := groth16.Verify(proof, vk, r1csInput); err != nil {
		fmt.Printf("%-30s %-30s %-30s\n", "proof is invalid", proofPath, time.Since(start))
		if err != nil {
			fmt.Println(err)
		}
		os.Exit(-1)
	}
	fmt.Printf("%-30s %-30s %-30s\n", "proof is valid", proofPath, time.Since(start))

}
