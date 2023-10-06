package compress

import (
	"bytes"
	"encoding/hex"
	"github.com/consensys/gnark/frontend"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

// These are not actually tests, but utilities to convert hex files

const TestCase = //"705b24/"

"777003/"

//"c9b5a2/"
//"fa4a22/"
//"e4207e/"

//"3c2943/"

func TestFlatHexToBinary(t *testing.T) {
	in, err := os.ReadFile("bug/data.hex")
	require.NoError(t, err)

	out, err := hex.DecodeString(string(in))
	require.NoError(t, err)

	require.NoError(t, os.WriteFile("bug/data.bin", out, 0644))
}

// TODO Edge case where "compressed" is longer than original data

func TestHexToBinary(t *testing.T) {
	in, err := os.ReadFile("test_cases/" + TestCase + "data.hex")
	require.NoError(t, err)

	var out bytes.Buffer

	for i := 0; len(in) != 0; i++ {
		_, err = expect(&in, '[')
		require.NoError(t, err)

		var n int
		n, err = expectNumber(&in)
		require.NoError(t, err)
		require.Equal(t, i, n)

		require.NoError(t, expectString(&in, "]:"))
		expectStar(&in, ' ')

		require.NoError(t, readHex(&out, &in, 32))

		_, err = expect(&in, '\n')
		require.NoError(t, err)
	}
	require.NoError(t, os.WriteFile("test_cases/"+TestCase+"data.bin", out.Bytes(), 0644))
}

func BytesToVars(d []byte) []frontend.Variable {
	vars := make([]frontend.Variable, len(d))
	for i := range d {
		vars[i] = d[i]
	}
	return vars
}
