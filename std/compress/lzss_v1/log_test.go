package lzss_v1

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"testing"
)

func backRefsToCsv(t *testing.T, filename string) {
	in, err := os.OpenFile(filename+"data.lzssv1", os.O_RDONLY, 0600)
	assert.NoError(t, err)

	out, err := os.OpenFile(filename+"backrefs.csv", os.O_CREATE|os.O_WRONLY, 0600)
	assert.NoError(t, err)

	_, err = out.WriteString("dst,src,len,offset\n")
	assert.NoError(t, err)

	outI := 0
	buff := []byte{0, 0, 0}
	_, err = in.Read(buff[:1])
	for err == nil {
		if buff[0] == 0 {
			_, err = in.Read(buff)
			offs := (uint16(buff[0]) | (uint16(buff[1]) << 8)) + 1
			length := uint16(buff[2]) + 1
			_, err = out.WriteString(fmt.Sprintf("%d,%d,%d,%d\n", outI, outI-int(offs), length, offs))
			outI += int(length)
		} else {
			outI++
		}
		_, err = in.Read(buff[:1])
	}
	if err != io.EOF {
		assert.NoError(t, err)
	}

	assert.NoError(t, out.Close())
	assert.NoError(t, in.Close())
}

func TestBackrefsToCsv(t *testing.T) {
	backRefsToCsv(t, "../test_cases/large/")
}
