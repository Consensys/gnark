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

type substring struct {
	length int
	starts []int
	score  int
}

func (p substring) count() int {
	return len(p.starts)
}

type substringMap struct {
	m    map[uint64]substring
	data []byte
	mtx  sync.Mutex
}

func (m *substringMap) add(i, j int) {
	sha := sha256.Sum256(m.data[i:j])
	h := binary.BigEndian.Uint64(sha[:8])
	var starts []int
	m.mtx.Lock()
	if r, ok := m.m[h]; ok {
		//i = r.count + 1
		starts = r.starts
	}
	starts = append(starts, i)
	m.m[h] = substring{j - i, starts, 0}
	m.mtx.Unlock()
	if len(starts) > 1 && !bytes.Equal(m.data[i:j], m.data[starts[0]:starts[0]+j-i]) {
		panic("hash collision")
	}
}

func (m *substringMap) serialize() []byte {
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
	return bbb.Bytes()
}

// prune removes substrings that only occur as substrings of others
func (m *substringMap) prune() {
	fmt.Println("pruning useless substrings")
	k := maps.Keys(m.m)
	sort.Slice(k, func(i, j int) bool {
		return m.m[k[i]].length > m.m[k[j]].length
	})
	prevLengthAt := len(k) - 1
	for i := len(k) - 1; i >= 0; i-- {
		atI := m.m[k[i]]
		if i == prevLengthAt {
			for prevLengthAt >= 0 && m.m[k[prevLengthAt]].length == atI.length {
				prevLengthAt--
			}
			if prevLengthAt < 0 {
				break // substrings of max length
			}
		}

		for j := prevLengthAt; j >= 0 && m.m[k[j]].length == m.m[k[prevLengthAt]].length; j-- {
			atJ := m.m[k[j]]

			if len(atI.starts) <= len(atJ.starts) && (atI.starts[0] == atJ.starts[0] || atI.starts[0] == atJ.starts[0]+1) {
				delete(m.m, k[i])
				break
			}
		}
	}
	fmt.Println("pruned", len(k), "substrings into", len(m.m))
}

func TestFindPatterns(t *testing.T) {
	in, err := os.ReadFile(TestCase + "data.zct")
	require.NoError(t, err)
	findPatterns(in)
}

func newSubstringsMap(d []byte) *substringMap {
	fmt.Println("building map")
	m := substringMap{m: make(map[uint64]substring, len(d)*len(d)/2), data: d}
	fmt.Println("finding substrings")
	done := 0
	utils.Parallelize(len(d), func(start, end int) {
		for i := start; i < end; i++ {

			for j := i + 1; j <= len(d) && d[j-1] != 0 && j-i <= 256+substringReferenceSize; j++ { // don't touch substrings with zeros in them
				// TODO Are we losing opportunities by outlawing longer substrings?
				if j-i > substringReferenceSize {
					m.add(i, j)
				}
			}
		}
		done += end - start
		fmt.Println(100*done/len(d), "%")
	})

	fmt.Println("turning substring data into canonical")
	k := maps.Keys(m.m)
	utils.Parallelize(len(d), func(start, end int) {
		for i := start; i < end; i++ {
			sort.Ints(m.m[k[i]].starts)
		}
	})

	return &m
}

// very inefficient
func findPatterns(d []byte) {

	m := newSubstringsMap(d)

	fmt.Println("writing raw results")

	if err := os.WriteFile(TestCase+"data.zct.patterns.raw", m.data, 0644); err != nil {
		panic(err)
	}

	analyzePatterns(d, maps.Values(m.m))
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
	vals := make([]substring, 0)
	bbb := &byteReader{raw, 0}
	var i uint32
	for n := 0; !bbb.eof(); n++ { // todo eof
		if n%3000000 == 0 {
			fmt.Println("reading record number", n)
			fmt.Println("consumed", 100*bbb.pos/len(raw), "% of raw data")
		}
		var r substring
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

// score computes the score of each substring, removes the ones with nonpositive score, and returns a slice sorted by score
func (m *substringMap) score() []substring {
	keys := maps.Keys(m.m)
	fmt.Println("scoring")
	for _, k := range keys {
		val := m.m[k]

		j := 0
		nbOccurrences := 0
		for j < len(val.starts) {
			currentEnd := val.starts[j] + val.length
			for j < len(val.starts) && val.starts[j] < currentEnd {
				j++
			}
			nbOccurrences++
		}
		val.score = nbOccurrences*(val.length-3) - 1 - val.length
		if val.score <= 0 {
			delete(m.m, k)
		} else {
			m.m[k] = val
		}
	}

	fmt.Println("sorting")
	vals := maps.Values(m.m)
	sort.Slice(vals, func(i, j int) bool {
		return vals[i].score > vals[j].score
	})
	return vals
}

func analyzePatterns(d []byte, vals []substring) {

	fmt.Println("sorting")
	sort.Slice(vals, func(i, j int) bool {
		return vals[i].score > vals[j].score
	})

	fmt.Println("filtering and writing analyzed results")
	var included []int
	var bb strings.Builder
	for i := 0; i < len(vals) && len(included) < 256; i++ {
		r := &vals[i]
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

		if i%100000 == 0 {
			fmt.Println("filtered", 100*i/len(vals), "%")
		}
	}
	if err := os.WriteFile(TestCase+"data.zct.patterns", []byte(bb.String()), 0644); err != nil {
		panic(err)
	}

	uncompressed, err := os.ReadFile(TestCase + "data.bin")
	if err != nil {
		panic(err)
	}

	savings := 0
	for i := 0; i < len(included) && i < 256; i++ {
		savings += vals[included[i]].score
	}
	fmt.Println("final compression", (len(d)-savings)*100/len(uncompressed), "%")

}
