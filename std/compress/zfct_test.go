package compress

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/require"
	"io"
	"os"
	"testing"
)

func compressZero255Counter(out io.ByteWriter, in []byte) error {
	for i := 0; i < len(in); i++ {
		if err := out.WriteByte(in[i]); err != nil {
			return err
		}
		if in[i] == 0 || in[i] == 255 {
			i0 := i
			for i < len(in) && in[i] == in[i0] && i-i0 < 256 {
				i++
			}
			i--
			if err := out.WriteByte(byte(i - i0)); err != nil {
				return err
			}
		}
	}
	return nil
}

func decompressZero255Counter(out io.ByteWriter, in []byte) error {
	for i := 0; i < len(in); i++ {
		if err := out.WriteByte(in[i]); err != nil {
			return err
		}
		if in[i] == 0 || in[i] == 255 {
			i0 := i
			i++
			for l := in[i]; l > 0; l-- {
				if err := out.WriteByte(in[i0]); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func TestCompressZero255Counter(t *testing.T) {
	var out bytes.Buffer
	in, err := os.ReadFile(TestCase + "data.bin")
	require.NoError(t, err)

	require.NoError(t, compressZero255Counter(&out, in))

	compressed := out.Bytes()

	require.NoError(t, os.WriteFile(TestCase+"data.zfct", compressed, 0644))
	fmt.Printf("achieved %D%% compression", 100*len(compressed)/len(in))

	// decompress and check match
	var decompressed bytes.Buffer
	require.NoError(t, decompressZero255Counter(&decompressed, compressed))

	require.Equal(t, in, decompressed.Bytes())
}
