package sha3

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
)

func GetHints() []solver.Hint {
	return []solver.Hint{
		remHint,
	}
}

func init() {
	solver.RegisterHint(GetHints()...)
}

func remHint(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return fmt.Errorf("expecting two inputs, got %d", len(inputs))
	}
	if len(outputs) != 1 {
		return fmt.Errorf("expecting one output, got %d", len(outputs))
	}
	y := inputs[0]
	x := inputs[1]
	rem := new(big.Int)
	new(big.Int).DivMod(x, y, rem)
	outputs[0].Set(rem)
	return nil
}
