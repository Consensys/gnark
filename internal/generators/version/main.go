package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/consensys/bavard"
)

//go:generate go run main.go
func main() {
	v, err := exec.Command("git", "describe", "--abbrev=0").CombinedOutput()
	if err != nil {
		panic(err)
	}
	version := strings.TrimSpace(string(v))
	src := []string{
		versionTemplate,
	}

	if err := bavard.Generate("../../../cmd/version.go", src,
		struct{ Version string }{version},
		bavard.Apache2("ConsenSys AG", 2020),
		bavard.Package("cmd"),
		bavard.GeneratedBy("gnark/internal/generators/version")); err != nil {
		fmt.Println("error", err)
		os.Exit(-1)
	}
}

const versionTemplate = `
// Version gnark version
const Version = "{{.Version}}"
`
