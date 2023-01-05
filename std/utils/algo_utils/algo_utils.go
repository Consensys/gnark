package algo_utils

func Map[T, S any](in []T, f func(T) S) []S {
	out := make([]S, len(in))
	for i, t := range in {
		out[i] = f(t)
	}
	return out
}

// TODO: Move this to gnark-crypto and use it for gkr there as well

// TopologicalSort sorts the wires in order of dependence. Such that for any wire, any one it depends on
// occurs before it. It tries to stick to the input order as much as possible. An already sorted list will remain unchanged.
// It also sets the nbOutput flags, and a dummy IdentityGate for input wires.
// Worst-case inefficient O(n^2), but that probably won't matter since the circuits are small.
// Furthermore, it is efficient with already-close-to-sorted lists, which are the expected input
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
	for i := range res.uniqueOutputs {
		res.uniqueOutputs[i] = make([]int, 0)
	}
	inputsISet := newIntSet(size) //if size is large, a map to struct{} might serve better
	for i := range res.uniqueOutputs {
		if i != 0 {
			inputsISet.clear()
		}
		for _, in := range inputs[i] {
			if !inputsISet.put(in) {
				res.uniqueOutputs[in] = append(res.uniqueOutputs[in], i)
			}
		}
		res.status[i] = inputsISet.len()
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

type intSet struct {
	contains []bool
	length   int
}

func newIntSet(capacity int) intSet { //if capacity is large, a map to struct{} might serve better
	return intSet{contains: make([]bool, capacity)}
}

func (s *intSet) clear() {
	for i := range s.contains {
		s.contains[i] = false
	}
	s.length = 0
}

func (s *intSet) put(i int) (alreadyContains bool) {
	if alreadyContains = s.contains[i]; !alreadyContains {
		s.length++
	}
	s.contains[i] = true
	return
}

func (s *intSet) len() int {
	return s.length
}
