package gkrtypes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTopSortTrivial(t *testing.T) {
	c := make(Circuit, 2)
	c[0].Inputs = []int{1}
	sorted := c.TopologicalSort()
	assert.Equal(t, []*Wire{&c[1], &c[0]}, sorted)
}

func TestTopSortSingleGate(t *testing.T) {
	c := make(Circuit, 3)
	c[0].Inputs = []int{1, 2}
	sorted := c.TopologicalSort()
	expected := []*Wire{&c[1], &c[2], &c[0]}

	assert.Equal(t, expected, sorted)
	assert.Equal(t, c[0].NbUniqueOutputs, 0)
	assert.Equal(t, c[1].NbUniqueOutputs, 1)
	assert.Equal(t, c[2].NbUniqueOutputs, 1)
}

func TestTopSortDeep(t *testing.T) {
	c := make(Circuit, 4)
	c[0].Inputs = []int{2}
	c[1].Inputs = []int{3}
	c[2].Inputs = []int{}
	c[3].Inputs = []int{0}
	sorted := c.TopologicalSort()
	assert.Equal(t, []*Wire{&c[2], &c[0], &c[3], &c[1]}, sorted)
}

func TestTopSortWide(t *testing.T) {
	c := make(Circuit, 10)
	c[0].Inputs = []int{3, 8}
	c[1].Inputs = []int{6}
	c[2].Inputs = []int{4}
	c[3].Inputs = []int{}
	c[4].Inputs = []int{}
	c[5].Inputs = []int{9}
	c[6].Inputs = []int{9}
	c[7].Inputs = []int{9, 5, 2}
	c[8].Inputs = []int{4, 3}
	c[9].Inputs = []int{}

	sorted := c.TopologicalSort()
	sortedExpected := []*Wire{&c[3], &c[4], &c[2], &c[8], &c[0], &c[9], &c[5], &c[6], &c[1], &c[7]}

	assert.Equal(t, sortedExpected, sorted)
}

func assertPermutation(t *testing.T, original Circuit, permuted []*Wire, permutationInv []int) {
	for i := range permuted {
		if permuted[i] != &original[permutationInv[i]] {
			actualIndex := -1
			for j := range original {
				if &original[j] == permuted[i] {
					actualIndex = j
					break
				}
			}
			require.NotEqual(t, -1, actualIndex, "result is not a permutation. element #%d of \"permuted\" list not found in original", i)
			t.Errorf("expected ")
			t.Fail()
		}
	}
}
