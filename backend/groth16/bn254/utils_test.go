package groth16

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
)

func assertSliceEquals[T any](t *testing.T, expected []T, seen []T) {
	assert.Equal(t, len(expected), len(seen))
	for i := range expected {
		assert.Equal(t, expected[i], seen[i])
	}
}

func TestRemoveIndex(t *testing.T) {
	elems := []fr.Element{{0}, {1}, {2}, {3}}
	r := filter(elems, []int{1, 2})
	expected := []fr.Element{{0}, {3}}
	assertSliceEquals(t, expected, r)
}
