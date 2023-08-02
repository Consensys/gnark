package compress

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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
	in, err := os.ReadFile("data.zct")
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

	scored := maps.Values(m.m)
	var bbb bytes.Buffer
	for _, r := range scored {
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
	if err := os.WriteFile("data.zct.patterns.raw", bbb.Bytes(), 0644); err != nil {
		panic(err)
	}

	fmt.Println("scoring")
	utils.Parallelize(len(scored), func(start, end int) {
		taken := make([]bool, len(d))
		for i := start; i < end; i++ {
			for j := range scored[i].starts {
				taken[scored[i].starts[j]+scored[i].length] = true
			}
			for j := range taken {
				if taken[j] {
					scored[i].score++
				}
				taken[j] = false
			}
		}
	})

	fmt.Println("sorting")
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})

	fmt.Println("writing analyzed results")
	var bb strings.Builder
	for _, r := range scored {
		if r.count() > 1 {
			s := fmt.Sprint(r.score, ":", r.count(), "\t", hex.EncodeToString(d[r.starts[0]:r.starts[0]+r.length]), "\n")
			bb.WriteString(s)
			s = fmt.Sprint("\tat", r.starts, "\n")
			bb.WriteString(s)
		}
	}
	if err := os.WriteFile("data.zct.patterns", []byte(bb.String()), 0644); err != nil {
		panic(err)
	}
}
