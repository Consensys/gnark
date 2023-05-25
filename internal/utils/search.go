package utils

// BinarySearch attempts to find the target in x. If not found, returns false and the index where the target would be inserted.
func BinarySearch(x []int, target int) (bool, int) {
	i := 0
	for j := len(x); i != j; {
		m := (i + j) / 2
		if x[m] < target {
			i = m + 1
		} else {
			j = m
		}
	}
	if i < len(x) && x[i] == target {
		return true, i
	}
	return false, i
}
