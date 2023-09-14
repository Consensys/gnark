package dfa_search

import "sort"

type transition struct {
	char byte
	dst  int
}

type dfa [][]transition

func findChar(ts []transition, char byte) int {
	for i, t := range ts {
		if char == t.char {
			return i
		}
		if char < t.char {
			return -1
		}
	}
	return -1
}

func createDfa(s []byte) dfa {
	dfa := make(dfa, len(s)+1)
	if len(s) == 0 {
		return dfa
	}

	backtrack := func(i int) {
		l := prefixLength(s, i)
		copy(dfa[i], dfa[l])
		if len(dfa[i]) < len(dfa[l]) {
			dfa[i] = append(dfa[i], dfa[l][len(dfa[i]):]...)
		}
		dfa[i] = dfa[i][:len(dfa[l])]
	}

	for i := range s {
		newTransition := transition{
			dst:  i + 1,
			char: s[i],
		}

		if j := findChar(dfa[i], s[i]); j == -1 {
			dfa[i] = append(dfa[i], newTransition)
		} else {
			dfa[i][j] = newTransition
		}

		sort.Slice(dfa[i], func(j, k int) bool {
			return dfa[i][j].char < dfa[i][k].char
		})
		backtrack(i + 1)
	}
	return dfa
}

func Search(s, d []byte) []int {
	res := make([]int, 0)
	dfa := createDfa(s)
	state := 0
	for i := range d {
		if j := findChar(dfa[state], d[i]); j == -1 {
			state = 0
		} else {
			state = dfa[state][j].dst
		}
		if state == len(s) {
			res = append(res, i-len(s)+1)
		}
	}
	return res
}

func prefixLength(s []byte, at int) int {
	goodL := 0
	for l := 0; l < at; l++ {
		if bytesEqual(s[:l], s[at-l:at]) {
			goodL = l
		}
	}
	return goodL
}

// bytes.Equal is acting erratically?
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
