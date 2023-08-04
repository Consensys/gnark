package compress

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/consensys/gnark/internal/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
)

type patternRecord struct {
	length int
	starts []int
	score  int
}

func (p patternRecord) count() int {
	return len(p.starts)
}

type patternMap struct {
	m    map[uint64]patternRecord
	data []byte
	mtx  sync.Mutex
}

func (m *patternMap) add(i, j int) {
	sha := sha256.Sum256(m.data[i:j])
	h := binary.BigEndian.Uint64(sha[:8])
	var starts []int
	m.mtx.Lock()
	if r, ok := m.m[h]; ok {
		//i = r.count + 1
		starts = r.starts
	}
	starts = append(starts, i)
	m.m[h] = patternRecord{j - i, starts, 0}
	m.mtx.Unlock()
	if len(starts) > 1 && !bytes.Equal(m.data[i:j], m.data[starts[0]:starts[0]+j-i]) {
		panic("hash collision")
	}
}

func TestFindPatterns(t *testing.T) {
	in, err := os.ReadFile(TestCase + "data.zct")
	require.NoError(t, err)
	findPatterns(in)
}

// very inefficient
func findPatterns(d []byte) {
	fmt.Println("building map")
	m := patternMap{m: make(map[uint64]patternRecord, len(d)*len(d)/2), data: d}
	fmt.Println("matching patterns")
	done := 0
	utils.Parallelize(len(d), func(start, end int) {
		for i := start; i < end; i++ {

			for j := i + 1; j < len(d); j++ {
				m.add(i, j)
			}
		}
		done += end - start
		fmt.Println(100*done/len(d), "%")
	})

	fmt.Println("writing raw results")

	vals := maps.Values(m.m)
	var bbb bytes.Buffer
	for _, r := range vals {
		if err := binary.Write(&bbb, binary.BigEndian, uint32(r.length)); err != nil {
			panic(err)
		}
		if err := binary.Write(&bbb, binary.BigEndian, uint32(len(r.starts))); err != nil {
			panic(err)
		}
		for _, s := range r.starts {
			if err := binary.Write(&bbb, binary.BigEndian, uint32(s)); err != nil {
				panic(err)
			}
		}
	}
	if err := os.WriteFile(TestCase+"data.zct.patterns.raw", bbb.Bytes(), 0644); err != nil {
		panic(err)
	}

	analyzePatterns(d, vals)
}

type byteReader struct {
	data []byte
	pos  int
}

func (b *byteReader) Read(p []byte) (n int, err error) {
	copy(p, b.data[b.pos:])
	if b.pos+len(p) >= len(b.data) {
		n = len(b.data) - b.pos
		b.pos = len(b.data)
		return n, errors.New("eof")
	}
	b.pos += len(p)
	return len(p), nil
}

func (b *byteReader) eof() bool {
	return b.pos >= len(b.data)
}

func TestAnalyzePatterns(t *testing.T) {
	// read raw results
	d, err := os.ReadFile(TestCase + "data.zct")
	require.NoError(t, err)
	raw, err := os.ReadFile(TestCase + "data.zct.patterns.raw")
	require.NoError(t, err)
	vals := make([]patternRecord, 0)
	bbb := &byteReader{raw, 0}
	var i uint32
	for n := 0; !bbb.eof(); n++ { // todo eof
		if n%3000000 == 0 {
			fmt.Println("reading record number", n)
			fmt.Println("consumed", 100*bbb.pos/len(raw), "% of raw data")
		}
		var r patternRecord
		err = binary.Read(bbb, binary.BigEndian, &i)
		require.NoError(t, err)
		r.length = int(i)

		require.NoError(t, binary.Read(bbb, binary.BigEndian, &i))
		r.starts = make([]int, i)
		for j := range r.starts {
			require.NoError(t, binary.Read(bbb, binary.BigEndian, &i))
			r.starts[j] = int(i)
		}
		vals = append(vals, r)
	}

	analyzePatterns(d, vals)
}

func isSubSeq(small, big []byte) bool {
	for i := 0; i < len(big)-len(small); i++ {
		if bytes.Equal(small, big[i:i+len(small)]) {
			return true
		}
	}
	return false
}

func analyzePatterns(d []byte, vals []patternRecord) {
	fmt.Println("scoring")
	n := 0
	utils.Parallelize(len(vals), func(start, end int) {
		taken := make([]bool, len(d))
		for i := start; i < end; i++ {
			/*v := &vals[i]
			if v.length == 334 {
				fmt.Println("ooooh wow")
			}*/
			for j := range vals[i].starts {
				for k := 0; k < vals[i].length; k++ {
					taken[vals[i].starts[j]+k] = true
				}
			}
			for j := range taken {
				if taken[j] {
					vals[i].score++
				}
				taken[j] = false
			}
			vals[i].score -= vals[i].length + 1 // overhead of describing it once
		}
		n += end - start
		fmt.Println("\tscored", 100*n/len(vals), "%")
	})

	fmt.Println("sorting")
	sort.Slice(vals, func(i, j int) bool {
		return vals[i].score > vals[j].score
	})

	fmt.Println("filtering and writing analyzed results")
	var included []int
	var bb strings.Builder
	for i, r := range vals {
		include := true
		for _, j := range included {
			if isSubSeq(d[r.starts[0]:r.starts[0]+r.length], d[vals[j].starts[0]:vals[j].starts[0]+vals[j].length]) {
				include = false
				break
			}
		}
		if include {
			included = append(included, i)

			s := fmt.Sprint(r.score, ":", r.count(), "\t", hex.EncodeToString(d[r.starts[0]:r.starts[0]+r.length]), "\n")
			bb.WriteString(s)
			s = fmt.Sprint("\tat", r.starts, "\n")
			bb.WriteString(s)
		}

	}
	if err := os.WriteFile(TestCase+"data.zct.patterns", []byte(bb.String()), 0644); err != nil {
		panic(err)
	}

}
