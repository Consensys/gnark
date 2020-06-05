package backend

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDuplicateAssignment(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("duplicate assignment will panic.")
		}
	}()

	a := NewAssignment()
	a.Assign(Public, "x", 1)
	a.Assign(Secret, "x", 1)
}

func TestVisibility(t *testing.T) {
	assert := require.New(t)
	a := NewAssignment()
	a.Assign(Public, "x", 1)
	a.Assign(Secret, "y", 1)

	assert.True(a["x"].IsPublic)
	assert.False(a["y"].IsPublic)
}
