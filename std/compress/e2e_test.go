package compress

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

const substringReferenceSize = 3

func TestSimpleE2E(t *testing.T) {
	d := []byte{0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8}
	cRef := []byte{0, 9, 4, 1, 2, 3, 4, 5, 6, 7, 8, 0, 2, 0, 192, 0, 0, 1, 0, 192, 0}
	c := compressE2E(d)
	assert.Equal(t, cRef, c)

	dPrime := decompressE2E(c)
	assert.Equal(t, d, dPrime)
}

func TestE2ELargeData(t *testing.T) {
	d, err := os.ReadFile(TestCase + "data.bin")
	require.NoError(t, err)
	c := compressE2E(d)
	fmt.Println("Compression rate:", float64(len(c))/float64(len(d)))
	dPrime := decompressE2E(c)
	assert.Equal(t, d, dPrime)
}

func TestE2EAnalyzeLargeData(t *testing.T) {
	d, err := os.ReadFile(TestCase + "data.bin")
	require.NoError(t, err)
	m := newSubstringsMap(d)
	m.prune()
	substrings := m.score()
	serialized := writeSubstrings(substrings)
	assert.NoError(t, os.WriteFile(TestCase+"substrings.bin", serialized, 0644))
}

func TestCompressFromSubstringsLargeData(t *testing.T) {
	d, err := os.ReadFile(TestCase + "data.bin")
	require.NoError(t, err)
	substrings, err := os.ReadFile(TestCase + "substrings.bin")
	require.NoError(t, err)
	c := compressWithCandidates(d, readSubstrings(substrings)[:100])
	fmt.Println("Compression rate:", float64(len(c))/float64(len(d)))
	fmt.Println("decompressing")
	dPrime := decompressE2E(c)

	for i := range d {
		if d[i] != dPrime[i] {
			fmt.Println("mismatch at", i)
			break
		}
	}

	assert.Equal(t, d, dPrime)

}

func compressE2E(d []byte) []byte {
	m := newSubstringsMap(d)
	m.prune()
	substrings := m.score()
	return compressWithCandidates(d, substrings)
}

func writeSubstrings(substrings []substring) []byte {
	var bb bytes.Buffer
	for _, s := range substrings {
		if s.length >= 65536 {
			panic("substring too long")
		}
		if err := binary.Write(&bb, binary.BigEndian, uint16(s.length)); err != nil {
			panic(err)
		}
		if s.score > 65536 {
			panic("score too large")
		}
		if err := binary.Write(&bb, binary.BigEndian, uint16(s.score)); err != nil {
			panic(err)
		}
		if len(s.starts) >= 65536 {
			panic("too many starts")
		}
		if err := binary.Write(&bb, binary.BigEndian, uint16(len(s.starts))); err != nil {
			panic(err)
		}
		for _, st := range s.starts {
			if st >= 65536 {
				panic("start too large")
			}
			if err := binary.Write(&bb, binary.BigEndian, uint16(st)); err != nil {
				panic(err)
			}
		}
	}
	return bb.Bytes()
}

func readSubstrings(b []byte) []substring {
	var substrings []substring
	for i := 0; i < len(b); {
		var s substring
		s.length = int(b[i])*256 + int(b[i+1])
		i += 2
		s.score = int(b[i])*256 + int(b[i+1])
		i += 2
		startsLen := int(b[i])*256 + int(b[i+1])
		i += 2
		s.starts = make([]int, startsLen)
		for j := range s.starts {
			s.starts[j] = int(b[i])*256 + int(b[i+1])
			i += 2
		}
		substrings = append(substrings, s)
	}
	return substrings
}

func compressWithCandidates(d []byte, candidates []substring) []byte {
	fmt.Println(len(candidates), "candidates")
	var metadata bytes.Buffer
	metadata.WriteByte(0) // to be specified later
	metadata.WriteByte(0)
	candidateSpecIndex := make(map[*substring]int)

	fmt.Println("composing candidates list")
	candidatesList := make([][]*substring, len(d))
	var out bytes.Buffer

	for _, c := range candidates {
		for j := range c.starts {
			candidatesList[c.starts[j]] = append(candidatesList[c.starts[j]], &c)
		}
	}

	fmt.Println("compressing")
	i := 0
	for i < len(d) {
		if d[i] == 0 { // zero counting
			j := i + 1
			for j < len(d) && d[j] == 0 && j-i <= 192 {
				j++
			}
			out.WriteByte(0)
			out.WriteByte(byte(j - i - 1))
			i = j
			continue
		}
		if len(candidatesList[i]) == 0 {
			out.WriteByte(d[i])
			i++
			continue
		}
		// review candidates, greedily
		best := candidatesList[i][0]
		for j := range candidatesList[i] {
			if candidatesList[i][j].score > best.score {
				best = candidatesList[i][j]
			}
		}
		if _, ok := candidateSpecIndex[best]; !ok {
			candidateSpecIndex[best] = metadata.Len()
			metadata.WriteByte(byte(best.length - substringReferenceSize - 1))
			metadata.Write(d[best.starts[0] : best.starts[0]+best.length])
		}
		ref := candidateSpecIndex[best] - 2
		out.WriteByte(0)
		out.WriteByte(192)
		out.WriteByte(byte(ref))
		i += best.length
	}

	fmt.Println(len(candidates), "used candidates")
	for _, c := range candidates {
		fmt.Println(c.score, "@", len(c.starts), hex.EncodeToString(d[c.starts[0]:c.starts[0]+c.length]))
	}

	fmt.Println("metadata length:", metadata.Len(), ", roughly", metadata.Len()*100/(metadata.Len()+out.Len()), "% of total compressed")

	metadataLen := metadata.Len() - 2
	metadata.Write(out.Bytes())
	res := metadata.Bytes()
	res[0] = byte(metadataLen / 256)
	res[1] = byte(metadataLen % 256)
	return res
}

func decompressE2E(c []byte) []byte {
	var bb bytes.Buffer
	i := int(c[0])*256 + int(c[1]) + 2
	b := 0
	for i < len(c) {

		if bb.Len() >= 1114 {
			fmt.Println("mismatch already occurred, troubled started at", b)
		}
		b = bb.Len()
		if c[i] == 0 {
			if c[i+1] < 192 { // zero count
				bb.Write(make([]byte, int(c[i+1])+1))
				i += 2
				continue
			}
			// substring reference
			ref := int(c[i+2]) + 2 + int(c[i+1]-192)*256
			substringSize := int(c[ref]) + 4
			bb.Write(c[ref+1 : ref+1+substringSize])
			i += 3
			continue
		}
		bb.WriteByte(c[i])
		i++
	}
	return bb.Bytes()
}
