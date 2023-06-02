package test_utils

import "math/rand"

func Random2DIntSlice(maxN, maxM int) [][]int {
	res := make([][]int, rand.Intn(maxN))
	for i := range res {
		res[i] = make([]int, rand.Intn(maxM))
		for j := range res[i] {
			res[i][j] = rand.Int()
		}
	}
	return res
}
