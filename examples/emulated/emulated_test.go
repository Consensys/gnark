package emulated

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std"
	"github.com/consensys/gnark/test"
)

func TestEmulatedArithmetic(t *testing.T) {
	assert := test.NewAssert(t)
	std.RegisterHints()
	var c Circuit

	assert.ProverSucceeded(&c, &Circuit{
		X:   [8]frontend.Variable{1, 1, 1, 1, 1, 1, 1, 1},
		Y:   [8]frontend.Variable{2, 2, 2, 2, 2, 2, 2, 2},
		Res: [8]frontend.Variable{13680, 11742, 9788, 7834, 5880, 3926, 1972, 18},
	})
}
