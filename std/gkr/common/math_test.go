package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLog2(t *testing.T) {
	x := []int{1, 2, 3, 4, 5, 6, 7, 8, 9}
	floor := []int{0, 1, 1, 2, 2, 2, 2, 3, 3}
	ceil := []int{0, 1, 2, 2, 3, 3, 3, 3, 4}

	for i := range x {
		assert.Equal(t, floor[i], Log2Floor(x[i]), "Error in log for x = %v", x[i])
		assert.Equal(t, ceil[i], Log2Ceil(x[i]), "Error in log for x = %v", x[i])
	}
}
