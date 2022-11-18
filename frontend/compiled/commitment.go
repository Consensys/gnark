package compiled

type CommitmentInfo struct {
	Committed       []int // sorted list of id's of committed variables
	CommitmentIndex int
}

func binarySearch(slice []int, v int) int { //different from the standard library binary search in that if v is not found, binarySearch returns where it would have been were it to be inserted
	j, k := 0, len(slice)
	for j < k {
		m := (j + k) / 2
		if sM := slice[m]; sM > v {
			k = m // if j < k then m < k so this advances the loop
		} else if sM < v {
			j = m + 1
		} else {
			return m
		}
	}
	return j
}

// NbPublicCommitted returns the number of public variables committed to, given the number of public variables
// IN THE WITNESS (i.e. not counting the commitment itself)
// nbPublic can also be considered as the index of the commitment itself
func (i *CommitmentInfo) NbPublicCommitted(nbPublic int) int {
	m := binarySearch(i.Committed, nbPublic)

	return m
}
