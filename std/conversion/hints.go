package conversion

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

func GetHints() []solver.Hint {
	return []solver.Hint{
		nativeToBytesHint,
	}
}

func nativeToBytesHint(mod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return errors.New("expecting one input")
	}
	// we expect that we have exactly the number of outputs to represent the input.
	nbBytes := (mod.BitLen() + 7) / 8
	if len(outputs) != nbBytes {
		return fmt.Errorf("expecting %d outputs, got %d", nbBytes, len(outputs))
	}
	buf := make([]byte, nbBytes)
	inputs[0].FillBytes(buf)
	for i := range nbBytes {
		outputs[i].SetUint64(uint64(buf[i]))
	}
	return nil
}
