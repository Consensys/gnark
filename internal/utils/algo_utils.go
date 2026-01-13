package utils

import "github.com/bits-and-blooms/bitset"

// this package provides some generic (in both senses of the word) algorithmic conveniences.

// Permute operates in-place but is not thread-safe; it uses the permutation for scratching
// permutation[i] signifies which index slice[i] is going to
func Permute[T any](slice []T, permutation []int) {
	var cached T
	for next := 0; next < len(permutation); next++ {

		cached = slice[next]
		j := permutation[next]
		permutation[next] = ^j
		for j >= 0 {
			cached, slice[j] = slice[j], cached
			j, permutation[j] = permutation[j], ^permutation[j]
		}
		permutation[next] = ^permutation[next]
	}
	for i := range permutation {
		permutation[i] = ^permutation[i]
	}
}

// Map returns [f(in[0]), f(in[1]), ..., f(in[len(in)-1])]
func Map[T, S any](in []T, f func(T) S) []S {
	out := make([]S, len(in))
	for i, t := range in {
		out[i] = f(t)
	}
	return out
}

// TODO: Move this to gnark-crypto and use it for gkr there as well

// TopologicalSort takes a list of lists of dependencies and proposes a sorting of the lists in order of dependence. Such that for any wire, any one it depends on
// occurs before it. It tries to stick to the input order as much as possible. An already sorted list will remain unchanged.
// As a bonus, it returns for each list its "unique" outputs. That is, a list of its outputs with no duplicates.
// Worst-case inefficient O(n^2), but that probably won't matter since the circuits are small.
// Furthermore, it is efficient with already-close-to-sorted lists, which are the expected input.
// If performance was bad, consider using a heap for finding the value "leastReady".
// WARNING: Due to the current implementation of intSet, it is ALWAYS O(n^2).
func TopologicalSort(inputs [][]int) (sorted []int, uniqueOutputs [][]int) {
	data := newTopSortData(inputs)
	sorted = make([]int, len(inputs))

	for i := range inputs {
		sorted[i] = data.leastReady
		data.markDone(data.leastReady)
	}

	return sorted, data.uniqueOutputs
}

type topSortData struct {
	uniqueOutputs [][]int
	inputs        [][]int
	status        []int // status > 0 indicates number of unique inputs left to be ready. status = 0 means ready. status = -1 means done
	leastReady    int
}

func newTopSortData(inputs [][]int) topSortData {
	size := len(inputs)
	res := topSortData{
		uniqueOutputs: make([][]int, size),
		inputs:        inputs,
		status:        make([]int, size),
		leastReady:    0,
	}

	inputsISet := bitset.New(uint(size))
	for i := range res.uniqueOutputs {
		if i != 0 {
			inputsISet.ClearAll()
		}
		cpt := 0
		for _, in := range inputs[i] {
			if !inputsISet.Test(uint(in)) {
				inputsISet.Set(uint(in))
				cpt++
				res.uniqueOutputs[in] = append(res.uniqueOutputs[in], i)
			}
		}
		res.status[i] = cpt
	}

	for res.status[res.leastReady] != 0 {
		res.leastReady++
	}

	return res
}

func (d *topSortData) markDone(i int) {

	d.status[i] = -1

	for _, outI := range d.uniqueOutputs[i] {
		d.status[outI]--
		if d.status[outI] == 0 && outI < d.leastReady {
			d.leastReady = outI
		}
	}

	for d.leastReady < len(d.status) && d.status[d.leastReady] != 0 {
		d.leastReady++
	}
}

// SliceOfRefs returns [&slice[0], &slice[1], ..., &slice[len(slice)-1]]
func SliceOfRefs[T any](slice []T) []*T {
	res := make([]*T, len(slice))
	for i := range slice {
		res[i] = &slice[i]
	}
	return res
}
