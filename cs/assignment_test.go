package cs_test

import (
	"testing"

	"github.com/consensys/gnark/cs"
	"github.com/stretchr/testify/require"
)

func TestDuplicateAssignment(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("duplicate assignment will panic.")
		}
	}()

	a := cs.NewAssignment()
	a.Assign(cs.Public, "x", 1)
	a.Assign(cs.Secret, "x", 1)
}

func TestVisibility(t *testing.T) {
	assert := require.New(t)
	a := cs.NewAssignment()
	a.Assign(cs.Public, "x", 1)
	a.Assign(cs.Secret, "y", 1)

	assert.True(a["x"].IsPublic)
	assert.False(a["y"].IsPublic)
}
