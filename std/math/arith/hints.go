package arith

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

func GetHints() []solver.Hint {
	return []solver.Hint{
		divmodHint,
	}
}

func divmodHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return errors.New("expecting two inputs")
	}
	if len(outputs) != 2 {
		return errors.New("expecting two outputs")
	}
	outputs[0].DivMod(inputs[0], inputs[1], outputs[1])
	return nil
}
