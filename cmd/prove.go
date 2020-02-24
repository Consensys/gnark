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
	"github.com/spf13/cobra"
)

// proveCmd represents the prove command
var proveCmd = &cobra.Command{
	Use: "prove [circuit.r1cs]",

	Short:   "creates a (zk)proof for provided circuit and solution",
	Run:     cmdProve,
	Version: buildString(),
}

var (
	fProofPath string
	fInputPath string
	fCount     uint
)

func init() {
	rootCmd.AddCommand(proveCmd)
	proveCmd.PersistentFlags().StringVar(&fProofPath, "proof", "", "specifies full path for proof -- default is ./[circuit].proof")
	proveCmd.PersistentFlags().StringVar(&fPkPath, "pk", "", "specifies full path for proving key")
	proveCmd.PersistentFlags().StringVar(&fInputPath, "input", "", "specifies full path for input file")
	proveCmd.PersistentFlags().UintVar(&fCount, "count", 1, "specifies number of times the prover algorithm is ran (benchmarking purposes)")
	_ = proveCmd.MarkPersistentFlagRequired("pk")
	_ = proveCmd.MarkPersistentFlagRequired("input")
}
