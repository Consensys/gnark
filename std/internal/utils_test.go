package internal

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNegFactorial(t *testing.T) {
	for n, expected := range []int{0, -1, 2, -6, 24} {
		assert.Equal(t, expected, NegFactorial(n))
	}
}
