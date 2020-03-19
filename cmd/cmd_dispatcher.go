// +build dispatcher

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
	"os/exec"
	"path/filepath"

	"github.com/consensys/gnark/backend/encoding/gob"
	"github.com/consensys/gnark/ecc"
	"github.com/spf13/cobra"
)

var fCurve string

func init() {
	cobra.OnInitialize(initConfig)
}

func dispatch(inputFile string) {
	curveID, err := gob.PeekCurveID(inputFile)
	if err != nil || curveID == ecc.UNKNOWN {
		fmt.Println("invalid input file: " + inputFile)
		os.Exit(-1)
	}
	binary := "gnark_" + curveID.String()

	// TODO check binary with a md5 sum that's injected in makefile at build time

	cmd := exec.Command(binary, os.Args[1:]...)
	out, err := cmd.CombinedOutput()
	fmt.Println(string(out))
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func cmdProve(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println("missing circuit path -- gnark prove -h for help")
		os.Exit(-1)
	}
	dispatch(filepath.Clean(args[0]))
}

func cmdSetup(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println("missing circuit path -- gnark setup -h for help")
		os.Exit(-1)
	}
	dispatch(filepath.Clean(args[0]))
}

func cmdVerify(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println("missing proof path -- gnark verify -h for help")
		os.Exit(-1)
	}
	dispatch(filepath.Clean(args[0]))
}

func cmdExport(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println("missing circuit path -- gnark export -h for help")
		os.Exit(-1)
	}
	dispatch(filepath.Clean(args[0]))
}
