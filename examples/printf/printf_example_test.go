package examples

import (
	"testing"

	"github.com/consensys/gnark/test"
)

func TestPrintfExample(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit PrintfCircuit
	assert.ProverSucceeded(&circuit, &PrintfCircuit{
		X: 2,
		Y: 3,
		Z: 4,
	})
}
