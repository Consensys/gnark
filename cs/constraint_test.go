package cs

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConstraintTag(t *testing.T) {
	assert := require.New(t)

	circuit := New()

	a := circuit.ALLOCATE(12)
	assert.True(len(a.outputWire.Tags) == 0, "untagged constraint shouldn't have tags")
	a.Tag("a")
	assert.True(len(a.outputWire.Tags) == 1, "a should have 1 tag")
	a.Tag("b")
	assert.True(len(a.outputWire.Tags) == 2, "a should have 2 tag")
	a.Tag("b") // duplicate
	assert.True(len(a.outputWire.Tags) == 2, "a should have 2 tag")

	x := circuit.PUBLIC_INPUT("x")
	assert.True(len(x.outputWire.Tags) == 1, "a secret/public input should have 1 tag by default (it's name)")

}
