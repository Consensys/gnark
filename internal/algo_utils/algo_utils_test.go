package algo_utils

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func SliceLen[T any](slice []T) int {
	return len(slice)
}

func testTopSort(t *testing.T, inputs [][]int, expectedSorted, expectedNbUniqueOuts []int) {
	sorted, uniqueOuts := TopologicalSort(inputs)
	nbUniqueOut := Map(uniqueOuts, SliceLen[int])
	assert.Equal(t, expectedSorted, sorted)
	assert.Equal(t, expectedNbUniqueOuts, nbUniqueOut)
}

func TestTopSortTrivial(t *testing.T) {
	testTopSort(t, [][]int{
		{1},
		{},
	}, []int{1, 0}, []int{0, 1})
}

func TestTopSortSingleGate(t *testing.T) {
	inputs := [][]int{{1, 2}, {}, {}}
	expectedSorted := []int{1, 2, 0}
	expectedNbUniqueOuts := []int{0, 1, 1}
	testTopSort(t, inputs, expectedSorted, expectedNbUniqueOuts)
}

func TestTopSortDeep(t *testing.T) {
	inputs := [][]int{{2}, {3}, {}, {0}}
	expectedSorted := []int{2, 0, 3, 1}
	expectedNbUniqueOuts := []int{1, 0, 1, 1}

	testTopSort(t, inputs, expectedSorted, expectedNbUniqueOuts)
}

func TestTopSortWide(t *testing.T) {
	inputs := [][]int{
		{3, 8},
		{6},
		{4},
		{},
		{},
		{9},
		{9},
		{9, 5, 2, 2},
		{4, 3},
		{},
	}
	expectedSorted := []int{3, 4, 2, 8, 0, 9, 5, 6, 1, 7}
	expectedNbUniqueOut := []int{0, 0, 1, 2, 2, 1, 1, 0, 1, 3}

	testTopSort(t, inputs, expectedSorted, expectedNbUniqueOut)
}

func TestPermute(t *testing.T) {
	list := []int{34, 65, 23, 2, 5}
	permutation := []int{2, 0, 1, 4, 3}
	permutationCopy := make([]int, len(permutation))
	copy(permutationCopy, permutation)

	Permute(list, permutation)
	assert.Equal(t, []int{65, 23, 34, 5, 2}, list)
	assert.Equal(t, permutationCopy, permutation)
}
