package ecc

import (
	"math/big"
)

var (
	zero, one, two, three big.Int
)

func init() {
	one.SetUint64(1)
	two.SetUint64(2)
	three.SetUint64(3)
}

// NafDecomposition gets the naf decomposition of a big number
func NafDecomposition(a *big.Int, result []int8) int {

	length := 0

	// some buffers
	var buf, aCopy big.Int
	aCopy.Set(a)

	for aCopy.Cmp(&zero) != 0 {

		// if aCopy % 2 == 0
		buf.And(&aCopy, &one)

		// aCopy even
		if buf.Cmp(&zero) == 0 {
			result[length] = 0
		} else { // aCopy odd
			buf.And(&aCopy, &three)
			if buf.Cmp(&three) == 0 {
				result[length] = -1
				aCopy.Add(&aCopy, &one)
			} else {
				result[length] = 1
			}
		}
		aCopy.Rsh(&aCopy, 1)
		length++
	}
	return length
}
