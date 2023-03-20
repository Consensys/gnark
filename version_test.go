package gnark

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/blang/semver/v4"
	"github.com/stretchr/testify/require"
)

func TestVersion(t *testing.T) {
	assert := require.New(t)
	// git describe --abbrev=0 --> doesn't work on CI
	// git -c 'versionsort.suffix=-' ls-remote --exit-code --refs --sort='version:refname' --tags https://github.com/consensys/gnark-crypto '*.*.*'
	cmd := exec.Command("git", "-c", "versionsort.suffix=-", "ls-remote", "--exit-code", "--refs", "--sort=version:refname",
		"--tags", "https://github.com/ConsenSys/gnark", "*.*.*")
	stdout, err := cmd.Output()
	assert.NoError(err)

	splitted := strings.Split(string(stdout), "/")
	lastTag := splitted[len(splitted)-1]

	// lastTag := strings.TrimSpace(string(stdout))
	lastVersion, err := semver.ParseTolerant(lastTag)
	assert.NoError(err)

	if lastVersion.Compare(Version) == 1 {
		t.Fatal("latest git tag is more recent than hardcoded Version")
	}
}
