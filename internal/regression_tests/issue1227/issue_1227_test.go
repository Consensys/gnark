package issue1226

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type Circuit struct {
	constVal int
	X        frontend.Variable
}

func (circuit *Circuit) Define(api frontend.API) error {
	api.AssertIsLessOrEqual(circuit.constVal, circuit.X)
	return nil
}

func TestConstantPath(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&Circuit{constVal: 1},
		test.WithValidAssignment(&Circuit{X: 1}),   // 1 <= 1 --> true
		test.WithInvalidAssignment(&Circuit{X: 0})) // 1 <= 0 --> false
	// test edge case where constant is 0
	assert.CheckCircuit(&Circuit{constVal: 0},
		test.WithValidAssignment(&Circuit{X: 1}), // 0 <= 1 --> true
		test.WithValidAssignment(&Circuit{X: 0})) // 0 <= 0 --> true
}
