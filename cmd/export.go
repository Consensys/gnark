/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

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

// exportCmd represents the export command
var exportCmd = &cobra.Command{
	Use:     "export [circuit.r1cs]",
	Short:   "export generates typed code from a R1CS or a Verifying key. Examples: gnark export circuit.r1cs --go or gnark export circuit.vk --solidity",
	Run:     cmdExport,
	Version: buildString(),
}

var (
	fGo          bool
	fOutputDir   string
	fPackageName string
)

func init() {
	rootCmd.AddCommand(exportCmd)

	exportCmd.PersistentFlags().BoolVar(&fGo, "go", false, "if set, try to export input into golang code")
	exportCmd.PersistentFlags().StringVarP(&fOutputDir, "output", "o", "", "destination path to create output files")
	exportCmd.PersistentFlags().StringVarP(&fPackageName, "package", "p", "", "package name in generated files")
	_ = exportCmd.MarkPersistentFlagRequired("output")
}
