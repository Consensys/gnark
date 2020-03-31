package cmd

import (
	"os/exec"
	"strings"
	"testing"
)

func TestVersionIsGenerated(t *testing.T) {
	// goal of this test is to ensure version.go contains up to date Version string
	// that is: if a new SemVer tag is pushed, go generate should run to re-generate version.go
	v, err := exec.Command("git", "describe", "--abbrev=0").CombinedOutput()
	if err != nil {
		panic(err)
	}
	version := strings.TrimSpace(string(v))

	if version != Version {
		t.Fatal("version was not generated, need to run go generate ./... at root of repo", "got", Version, "expected", version)
	}
}
