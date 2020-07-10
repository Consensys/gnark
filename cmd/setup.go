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

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/encoding/gob"
	"github.com/spf13/cobra"
)

// setupCmd represents the setup command
var setupCmd = &cobra.Command{
	Use:     "setup [circuit.r1cs]",
	Short:   "outputs proving and verifying keys for a given circuit",
	Run:     cmdSetup,
	Version: Version,
}

var (
	fVkPath, fPkPath string
)

func init() {
	rootCmd.AddCommand(setupCmd)

	setupCmd.PersistentFlags().StringVar(&fVkPath, "vk", "", "specifies full path for verifying key -- default is ./[circuit].vk")
	setupCmd.PersistentFlags().StringVar(&fPkPath, "pk", "", "specifies full path for proving key   -- default is ./[circuit].pk")

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
	if !fileExists(circuitPath) {
		fmt.Println("error:", errNotFound)
		os.Exit(-1)
	}

	// check curve ID (TODO is curve.ID necessary now? Because the circuits are serialized with big.Int, here the curve.ID is "unknown")
	curveID, err := gob.PeekCurveID(circuitPath)
	fmt.Println("test-----" + curveID.String())
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(-1)
	}

	r1cs, err := r1cs.Read(circuitPath)
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(-1)
	}

	fmt.Printf("%-30s %-30s %-d constraints\n", "loaded circuit", circuitPath, r1cs.GetNbConstraints())
	start := time.Now()
	pk, vk := groth16.Setup(r1cs)
	duration := time.Since(start)
	fmt.Printf("%-30s %-30s %-30s\n", "setup completed", "", duration)

	if err := gob.Write(vkPath, vk, curveID); err != nil {
		fmt.Println("error:", err)
		os.Exit(-1)
	}
	fmt.Printf("%-30s %s\n", "generated verifying key", vkPath)
	if err := gob.Write(pkPath, pk, curveID); err != nil {
		fmt.Println("error:", err)
		os.Exit(-1)
	}
	fmt.Printf("%-30s %s\n", "generated proving key", pkPath)

}
