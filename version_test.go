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
	// git describe --abbrev=0
	cmd := exec.Command("git", "describe", "--abbrev=0")
	stdout, err := cmd.Output()
	assert.NoError(err)

	lastTag := strings.TrimSpace(string(stdout))
	lastVersion, err := semver.ParseTolerant(lastTag)
	assert.NoError(err)

	if lastVersion.Compare(Version) == 1 {
		t.Fatal("latest git tag is more recent than hardcoded Version")
	}
}
