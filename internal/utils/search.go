package utils

import "sort"

// FindInSlice attempts to find the target in increasing slice x.
// If not found, returns false and the index where the target would be inserted.
func FindInSlice(x []int, target int) (int, bool) {
	return sort.Find(len(x), func(i int) int {
		return target - x[i]
	})
}
