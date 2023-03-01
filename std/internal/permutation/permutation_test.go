package permutation

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func TestRandomRouting(t *testing.T) {
	for N := 10; N < 100; N += 13 {
		t.Run(fmt.Sprintf("N=%d", N), func(t *testing.T) {
			s := rand.NewSource(time.Now().UnixMilli())
			p := rand.New(s).Perm(N) //nolint:gosec // strong randomness isn't required. We randomize using current time.
			v := make([]int, N)
			for i := range v {
				v[i] = i
			}
			pp := permutationFromMapping(v, p)
			permuted, nbSwitches, err := Route(pp, defaultRouting[int], v)
			if err != nil {
				t.Fatal(err)
			}
			if expSwitched := NbSwitches(N); nbSwitches != expSwitched {
				t.Errorf("switch count %d expected %d", nbSwitches, expSwitched)
			}
			if len(permuted) != len(p) {
				t.Fatal("permutation length mismatch")
			}
			for i := range p {
				if permuted[i] != p[i] {
					t.Fatalf("index %d mismatch %d %d", i, permuted[i], p[i])
				}
			}
		})
	}
}

func TestSwitchCount(t *testing.T) {
	for _, v := range []struct {
		n, count int
	}{
		{2, 1}, {3, 3}, {4, 5}, {5, 8}, {6, 11}, {7, 14}, {8, 17}, {9, 21}, {10, 25},
	} {
		if nn := NbSwitches(v.n); nn != v.count {
			t.Errorf("switch count %d expected %d got %d", v.n, v.count, nn)
		}
	}
}
