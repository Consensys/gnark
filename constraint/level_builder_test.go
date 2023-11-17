package constraint_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func idHint(_ *big.Int, in []*big.Int, out []*big.Int) error {
	if len(in) != len(out) {
		return fmt.Errorf("in/out length mismatch %d≠%d", len(in), len(out))
	}
	for i := range in {
		out[i].Set(in[i])
	}
	return nil
}

type idHintCircuit struct {
	X frontend.Variable
}

func (c *idHintCircuit) Define(api frontend.API) error {
	x, err := api.Compiler().NewHint(idHint, 1, api.Mul(c.X, c.X))
	if err != nil {
		return err
	}
	api.AssertIsEqual(x[0], api.Mul(c.X, c.X))
	return nil
}

func TestIdHint(t *testing.T) {
	solver.RegisterHint(idHint)
	assignment := idHintCircuit{0}

	test.NewAssert(t).CheckCircuit(&idHintCircuit{}, test.WithValidAssignment(&assignment))
}
