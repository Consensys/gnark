package frontend

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConstraintTag(t *testing.T) {
	assert := require.New(t)

	circuit := New()

	a := circuit.ALLOCATE(12)
	assert.True(len(a.getOutputWire().Tags) == 0, "untagged constraint shouldn't have tags")
	a.Tag("a")
	assert.True(len(a.getOutputWire().Tags) == 1, "a should have 1 tag")
	a.Tag("b")
	assert.True(len(a.getOutputWire().Tags) == 2, "a should have 2 tag")
	a.Tag("b") // duplicate
	assert.True(len(a.getOutputWire().Tags) == 2, "a should have 2 tag")

	x := circuit.PUBLIC_INPUT("x")
	assert.True(len(x.getOutputWire().Tags) == 0, "a secret/public is not tagged by default")

}
