package bits

import (
	"testing"

	"github.com/consensys/gnark/frontend"
)

type toBinaryCircuit struct {
}

func (c *toBinaryCircuit) Define(api frontend.API) error {
	return nil
}

func TestToBinary(t *testing.T) {
	// TODO
}
