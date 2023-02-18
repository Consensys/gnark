package gadgets_test

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/gadgets"
	"github.com/consensys/gnark/test"
)

type muxCircuit struct {
	SEL                frontend.Variable
	I0, I1, I2, I3, I4 frontend.Variable
	OUT                frontend.Variable
}

func (c *muxCircuit) Define(api frontend.API) error {

	out := gadgets.Mux(api, c.SEL, c.I0, c.I1, c.I2, c.I3, c.I4)

	api.AssertIsEqual(out, c.OUT)

	return nil
}

// The output of this circuit is ignored and the only way its proof can fail is by providing invalid inputs.
type ignoredOutputMuxCircuit struct {
	SEL        frontend.Variable
	I0, I1, I2 frontend.Variable
}

func (c *ignoredOutputMuxCircuit) Define(api frontend.API) error {
	// We ignore the output
	_ = gadgets.Mux(api, c.SEL, c.I0, c.I1, c.I2)

	return nil
}

func TestMux(t *testing.T) {
	assert := test.NewAssert(t)

	assert.ProverSucceeded(&muxCircuit{}, &muxCircuit{SEL: 2, I0: 10, I1: 11, I2: 12, I3: 13, I4: 14, OUT: 12})

	assert.ProverSucceeded(&muxCircuit{}, &muxCircuit{SEL: 0, I0: 10, I1: 11, I2: 12, I3: 13, I4: 14, OUT: 10})

	assert.ProverSucceeded(&muxCircuit{}, &muxCircuit{SEL: 4, I0: 20, I1: 21, I2: 22, I3: 23, I4: 24, OUT: 24})

	// Failures
	assert.ProverFailed(&muxCircuit{}, &muxCircuit{SEL: 5, I0: 20, I1: 21, I2: 22, I3: 23, I4: 24, OUT: 24})

	assert.ProverFailed(&muxCircuit{}, &muxCircuit{SEL: 0, I0: 20, I1: 21, I2: 22, I3: 23, I4: 24, OUT: 21})

	// Ignoring the circuit's output:
	assert.ProverSucceeded(&ignoredOutputMuxCircuit{}, &ignoredOutputMuxCircuit{SEL: 0, I0: 0, I1: 1, I2: 2})

	assert.ProverSucceeded(&ignoredOutputMuxCircuit{}, &ignoredOutputMuxCircuit{SEL: 2, I0: 0, I1: 1, I2: 2})

	// Failures
	assert.ProverFailed(&ignoredOutputMuxCircuit{}, &ignoredOutputMuxCircuit{SEL: 3, I0: 0, I1: 1, I2: 2})

	assert.ProverFailed(&ignoredOutputMuxCircuit{}, &ignoredOutputMuxCircuit{SEL: -1, I0: 0, I1: 1, I2: 2})
}
