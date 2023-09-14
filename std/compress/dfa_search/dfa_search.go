package dfa_search

func createDfa(s []byte) [][256]int {
	dfa := make([][256]int, len(s)+1)
	if len(s) == 0 {
		return dfa
	}

	backtrack := func(i int) {
		l := prefixLength(s, i)
		dfa[i] = dfa[l]
	}

	for i := range s {
		dfa[i][s[i]] = i + 1
		backtrack(i + 1)
	}
	return dfa
}

func Search(s, d []byte) []int {
	res := make([]int, 0)
	dfa := createDfa(s)
	state := 0
	for i := range d {
		state = dfa[state][d[i]]
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
