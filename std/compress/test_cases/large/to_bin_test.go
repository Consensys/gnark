package large

import (
	"encoding/hex"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestToBin(t *testing.T) {
	x, err := os.ReadFile("test.log")
	require.NoError(t, err)
	b, err := hex.DecodeString(string(x))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile("data.bin", b, 0600))
}
