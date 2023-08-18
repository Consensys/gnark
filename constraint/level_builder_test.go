package constraint_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
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
	x, err := api.Compiler().NewHint(idHint, 1, c.X)
	if err != nil {
		return err
	}
	api.AssertIsEqual(x[0], c.X)
	return nil
}

func TestIdHint(t *testing.T) {
	solver.RegisterHint(idHint)
	assignment := idHintCircuit{0}
	test.NewAssert(t).SolvingSucceeded(&idHintCircuit{}, &assignment, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))
}
