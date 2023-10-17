package lzss_v1

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"strings"
	"testing"
)

func backRefsToCsv(t *testing.T, filename string) {
	in, err := os.OpenFile(filename+"data.lzssv1", os.O_RDONLY, 0600)
	assert.NoError(t, err)

	out, err := os.OpenFile(filename+"backrefs.csv", os.O_CREATE|os.O_WRONLY, 0600)
	assert.NoError(t, err)

	_, err = out.WriteString("dst,src,len,offset,content\n")
	assert.NoError(t, err)

	d := make([]byte, 256)
	buff := []byte{0, 0, 0}
	_, err = in.Read(buff[:1])
	for err == nil {
		if buff[0] == 0 {
			_, err = in.Read(buff)
			offs := (uint16(buff[0]) | (uint16(buff[1]) << 8)) + 1
			length := uint16(buff[2]) + 1

			src := len(d) - int(offs)
			dst := len(d)
			d = appnd(d, src, int(length))

			_, err = out.WriteString(
				fmt.Sprintf("%d,%d,%d,%d,%s\n", dst-256, src-256, length, offs, toHex(d[dst:])),
			)
		} else {
			d = append(d, buff[0])
		}
		_, err = in.Read(buff[:1])
	}
	if err != io.EOF {
		assert.NoError(t, err)
	}

	assert.NoError(t, out.Close())
	assert.NoError(t, in.Close())
}

// not sub-slice friendly
func appnd(slice []byte, src, length int) []byte {
	for i := 0; i < length; i++ {
		slice = append(slice, slice[src+i])
	}
	return slice
}

func TestBackrefsToCsv(t *testing.T) {
	backRefsToCsv(t, "../test_cases/large/")
}

func toHex(slice []byte) string {
	slice = append(slice, 1)
	var sbb strings.Builder
	nbZeros := 0
	for _, b := range slice {
		if b == 0 {
			nbZeros++
		} else {
			if nbZeros > 3 {
				sbb.WriteString(fmt.Sprintf("[00^%d]", nbZeros))
				nbZeros = 0
			}
			for nbZeros > 0 {
				sbb.WriteString("00")
				nbZeros--
			}
			sbb.WriteByte(toHexDigit(b >> 4))
			sbb.WriteByte(toHexDigit(b & 0xf))
		}
	}
	return sbb.String()[0 : len(sbb.String())-1]
}

func toHexDigit(b byte) byte {
	if b < 10 {
		return b + '0'
	}
	return b - 10 + 'a'
}
