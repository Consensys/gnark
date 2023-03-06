package std

import (
	"fmt"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

func ExampleRegisterHints() {
	// this constraint system correspond to a circuit using gnark/std components which rely on hints
	// like bits.ToNAF(...)
	var ccs constraint.ConstraintSystem

	// since package bits is not imported, the hint NNAF is not registered
	// --> solver.RegisterHint(bits.NNAF)
	// rather than to keep track on which hints are needed, a prover/solver service can register all
	// gnark/std hints with this call
	RegisterHints()

	// then -->
	_ = ccs.IsSolved(nil)
}

// Test the most basic hint possible

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
	test.NewAssert(t).SolvingSucceeded(&idHintCircuit{}, &assignment)
}
