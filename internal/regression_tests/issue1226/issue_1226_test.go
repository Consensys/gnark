package issue1226

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type Circuit struct {
	X frontend.Variable
}

func (circuit *Circuit) Define(api frontend.API) error {
	api.AssertIsLessOrEqual(1, circuit.X)
	return nil
}

func TestConstantPath(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&Circuit{},
		test.WithValidAssignment(&Circuit{X: 1}),   // 1 <= 1 --> true
		test.WithInvalidAssignment(&Circuit{X: 0})) // 1 <= 0 --> false
}
