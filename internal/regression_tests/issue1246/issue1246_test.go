package issue1246_test

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// Circuit definition
// here we aim to catch the case where the API doesn't enforce the condition to be a boolean
type notBoolCond struct {
	Condition, Y1, Y2 frontend.Variable
}

func (circuit *notBoolCond) Define(api frontend.API) error {
	d := api.Select(circuit.Condition, circuit.Y1, circuit.Y2)

	// per api definition, d should hold either Y1 or Y2.
	// we have y1 = 2, y2 = 4, condition = 2 (non boolean)
	// r = condition(y1-y2) + y2
	api.AssertIsEqual(d, 0)

	return nil
}

func TestSelectConditionNonBool(t *testing.T) {
	assert := test.NewAssert(t)

	assert.CheckCircuit(&notBoolCond{},
		test.WithInvalidAssignment(&notBoolCond{
			Condition: 2,
			Y1:        2,
			Y2:        4,
		}),
	)
}
