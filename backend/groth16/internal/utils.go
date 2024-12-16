package internal

import (
	"math"
	"slices"
)

func ConcatAll(slices ...[]int) []int { // copyright note: written by GitHub Copilot
	totalLen := 0
	for _, s := range slices {
		totalLen += len(s)
	}
	res := make([]int, totalLen)
	i := 0
	for _, s := range slices {
		i += copy(res[i:], s)
	}
	return res
}

func NbElements(slices [][]int) int { // copyright note: written by GitHub Copilot
	totalLen := 0
	for _, s := range slices {
		totalLen += len(s)
	}
	return totalLen
}

// NewMergeIterator assumes that all slices in s are sorted
func NewMergeIterator(s [][]int) *MergeIterator {
	res := &MergeIterator{slices: slices.Clone(s)}
	res.findLeast()
	return res
}

// MergeIterator iterates through a merging of multiple sorted slices
type MergeIterator struct {
	slices     [][]int
	leastIndex int
}

func (i *MergeIterator) findLeast() {
	value := math.MaxInt
	i.leastIndex = -1
	for j := range i.slices {
		if len(i.slices[j]) == 0 {
			continue
		}
		if v := i.slices[j][0]; v < value {
			value = v
			i.leastIndex = j
		}
	}
	return
}

// Peek returns the next smallest value and the index of the slice it came from
// If the iterator is empty, Peek returns (math.MaxInt, -1)
func (i *MergeIterator) Peek() (value, index int) {
	if i.leastIndex == -1 {
		return math.MaxInt, -1
	}
	return i.slices[i.leastIndex][0], i.leastIndex
}

// Next returns the next smallest value and the index of the slice it came from, and advances the iterator
// If the iterator is empty, Next returns (math.MaxInt, -1)
func (i *MergeIterator) Next() (value, index int) {
	value, index = i.Peek()
	i.slices[i.leastIndex] = i.slices[i.leastIndex][1:]
	i.findLeast()
	return
}

// IndexIfNext returns the index of the slice and advances the iterator if the next value is value, otherwise returns -1
// If the iterator is empty, IndexIfNext returns -1
func (i *MergeIterator) IndexIfNext(value int) int {
	if v, index := i.Peek(); v == value {
		i.Next()
		return index
	}
	return -1
}
