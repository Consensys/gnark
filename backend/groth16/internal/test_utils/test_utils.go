package test_utils

import "math/rand"

func Random2DIntSlice(maxN, maxM int) [][]int {
	res := make([][]int, rand.Intn(maxN)) //#nosec G404 weak rng OK for test
	for i := range res {
		res[i] = make([]int, rand.Intn(maxM)) //#nosec G404 weak rng OK for test
		for j := range res[i] {
			res[i][j] = rand.Int() //#nosec G404 weak rng OK for test
		}
	}
	return res
}
