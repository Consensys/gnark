package ecc

import (
	"math/big"
	"testing"
)

func TestNafDecomposition(t *testing.T) {
	exp := big.NewInt(13)
	var result [400]int8
	lExp := NafDecomposition(exp, result[:])
	dec := result[:lExp]

	res := [5]int8{1, 0, -1, 0, 1}
	for i, v := range dec {
		if v != res[i] {
			t.Error("Error in NafDecomposition")
		}
	}
}
