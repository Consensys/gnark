package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtendRepeatLast(t *testing.T) {
	// normal case
	s := []int{1, 2, 3}
	u := ExtendRepeatLast(s, 5)
	assert.Equal(t, []int{1, 2, 3, 3, 3}, u)

	// don't overwrite super-slice
	s = []int{1, 2, 3}
	u = ExtendRepeatLast(s[:1], 2)
	assert.Equal(t, []int{1, 1}, u)
	assert.Equal(t, []int{1, 2, 3}, s)

	// trim if n < len(s)
	s = []int{1, 2, 3}
	u = ExtendRepeatLast(s, 2)
	assert.Equal(t, []int{1, 2}, u)
}
