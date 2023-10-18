package lzss_v1

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestBackrefsToCsv(t *testing.T) {
	backRefsToCsv(t, "../test_cases/large/")
}

func TestCompareCoverage(t *testing.T) {
	compareBackrefs(t, "../test_cases/large/backrefs.csv", "../test_cases/large/backrefs_new.csv")
}

func backRefsToCsv(t *testing.T, filename string) {
	in, err := os.OpenFile(filename+"data.lzssv1", os.O_RDONLY, 0600)
	assert.NoError(t, err)

	out, err := os.OpenFile(filename+"backrefs_new.csv", os.O_CREATE|os.O_WRONLY, 0600)
	assert.NoError(t, err)

	_, err = out.WriteString("dst,src,len,offset,content\n")
	assert.NoError(t, err)

	d := make([]byte, 256)
	buff := []byte{0, 0, 0}
	_, err = in.Read(buff[:1])
	for err == nil {
		if buff[0] == 0 {
			_, err = in.Read(buff)
			assert.NoError(t, err)
			offs := (uint16(buff[0]) | (uint16(buff[1]) << 8)) + 1
			length := uint16(buff[2]) + 1

			src := len(d) - int(offs)
			dst := len(d)
			d = appnd(d, src, int(length))

			_, err = out.WriteString(
				fmt.Sprintf("%d,%d,%d,%d,%s\n", dst-256, src-256, length, offs, toHex(d[dst:])),
			)
			assert.NoError(t, err)
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

func compareBackrefs(t *testing.T, oldFilename, newFilename string) {
	old := readBackrefRecords(t, oldFilename)
	nw := readBackrefRecords(t, newFilename)

	oldCov := coverageList(old)
	newCov := coverageList(nw)

	// coverage for new must be no less than old
	for i := range oldCov {
		if oldCov[i] != -1 && newCov[i] == -1 && old[oldCov[i]].length >= 4 {
			j := i - 1
			for newCov[j] == -1 {
				j--
			}
			oldBr := old[oldCov[i]]
			newBr := nw[newCov[j]]

			// if there was a neutral choice here, the non-coverage is okay
			if j != newBr.dst+newBr.length && newBr.length < oldBr.length {
				t.Errorf("index %d is covered by backref %v in old but not in new\n\tlast new backref is %v", i, oldBr, newBr)
			}
		}
	}
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
	return sbb.String()[0 : len(sbb.String())-2]
}

func toHexDigit(b byte) byte {
	if b < 10 {
		return b + '0'
	}
	return b - 10 + 'a'
}

type backrefRecord struct {
	dst, src, length, offset int
	content                  string
}

func readBackrefRecords(t *testing.T, filename string) []backrefRecord {
	res := make([]backrefRecord, 0)
	file, err := os.ReadFile(filename)
	assert.NoError(t, err)
	lines := strings.Split(string(file), "\n")
	for i, line := range lines[1:] {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) != 5 {
			fmt.Println("uh oh", i, line)
		}
		assert.Equal(t, 5, len(fields))
		var r backrefRecord
		r.dst, err = strconv.Atoi(fields[0])
		assert.NoError(t, err)
		r.src, err = strconv.Atoi(fields[1])
		assert.NoError(t, err)
		r.length, err = strconv.Atoi(fields[2])
		assert.NoError(t, err)
		r.offset, err = strconv.Atoi(fields[3])
		assert.NoError(t, err)
		r.content = fields[4]
		res = append(res, r)
	}
	return res
}

func coverageList(br []backrefRecord) []int {
	res := make([]int, 0)
	for i, r := range br {
		for len(res) < r.dst+r.length {
			val := -1
			if len(res) >= r.dst {
				val = i
			}
			res = append(res, val)
		}
	}
	return res
}

// not sub-slice friendly
func appnd(slice []byte, src, length int) []byte {
	for i := 0; i < length; i++ {
		slice = append(slice, slice[src+i])
	}
	return slice
}
