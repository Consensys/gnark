package test

import (
	"fmt"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"math/big"
	"testing"
)

const id = solver.HintID(123454321)

func identityHint(_ *big.Int, in, out []*big.Int) error {
	if len(in) != len(out) {
		return fmt.Errorf("len(in) = %d ≠ %d = len(out)", len(in), len(out))
	}
	for i := range in {
		out[i].Set(in[i])
	}
	return nil
}

type customNamedHintCircuit struct {
	X []frontend.Variable
}

func (c *customNamedHintCircuit) Define(api frontend.API) error {
	y, err := api.Compiler().NewHintForId(id, len(c.X), c.X...)

	if err != nil {
		return err
	}
	for i := range y {
		api.AssertIsEqual(c.X[i], y[i])
	}

	return nil
}

var assignment customNamedHintCircuit

func init() {
	solver.RegisterNamedHint(identityHint, id)
	assignment = customNamedHintCircuit{X: []frontend.Variable{1, 2, 3, 4, 5}}
}

func TestHintWithCustomNamePlonk(t *testing.T) {
	testPlonk(t, &assignment)
}

func TestHintWithCustomNameGroth16(t *testing.T) {
	testGroth16(t, &assignment)
}

func TestHintWithCustomNameEngine(t *testing.T) {
	circuit := hollow(&assignment)
	NewAssert(t).SolvingSucceeded(circuit, &assignment)
}
