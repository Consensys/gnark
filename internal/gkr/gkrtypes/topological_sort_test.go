package gkrtypes

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTopSortTrivial(t *testing.T) {
	c := make(ExecutableCircuit, 2)
	c[0].Inputs = []int{1}
	sorted := c.TopologicalSort()
	assert.Equal(t, ExecutableWires{&c[1], &c[0]}, sorted)
}

func TestTopSortSingleGate(t *testing.T) {
	c := make(ExecutableCircuit, 3)
	c[0].Inputs = []int{1, 2}
	sorted := c.TopologicalSort()
	expected := ExecutableWires{&c[1], &c[2], &c[0]}

	assert.Equal(t, expected, sorted)
	assert.Equal(t, c[0].NbUniqueOutputs, 0)
	assert.Equal(t, c[1].NbUniqueOutputs, 1)
	assert.Equal(t, c[2].NbUniqueOutputs, 1)
}

func TestTopSortDeep(t *testing.T) {
	c := make(ExecutableCircuit, 4)
	c[0].Inputs = []int{2}
	c[1].Inputs = []int{3}
	c[2].Inputs = []int{}
	c[3].Inputs = []int{0}
	sorted := c.TopologicalSort()
	assert.Equal(t, ExecutableWires{&c[2], &c[0], &c[3], &c[1]}, sorted)
}

func TestTopSortWide(t *testing.T) {
	c := make(ExecutableCircuit, 10)
	c[0].Inputs = []int{3, 8}
	c[1].Inputs = []int{6}
	c[2].Inputs = []int{4}
	c[3].Inputs = []int{}
	c[4].Inputs = []int{}
	c[5].Inputs = []int{9}
	c[6].Inputs = []int{9}
	c[7].Inputs = []int{9, 5, 2}
	c[8].Inputs = []int{4, 3}
	c[9].Inputs = []int{}

	sorted := c.TopologicalSort()
	sortedExpected := ExecutableWires{&c[3], &c[4], &c[2], &c[8], &c[0], &c[9], &c[5], &c[6], &c[1], &c[7]}

	assert.Equal(t, sortedExpected, sorted)
}
