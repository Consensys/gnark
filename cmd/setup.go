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

// setupCmd represents the setup command
var setupCmd = &cobra.Command{
	Use:     "setup [circuit.r1cs]",
	Short:   "outputs proving and verifying keys for a given circuit",
	Run:     cmdSetup,
	Version: buildString(),
}

var (
	fVkPath, fPkPath string
)

func init() {
	rootCmd.AddCommand(setupCmd)

	setupCmd.PersistentFlags().StringVar(&fVkPath, "vk", "", "specifies full path for verifying key -- default is ./[circuit].vk")
	setupCmd.PersistentFlags().StringVar(&fPkPath, "pk", "", "specifies full path for proving key   -- default is ./[circuit].pk")

}
