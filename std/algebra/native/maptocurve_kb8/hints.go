package maptocurve_kb8

import (
	"fmt"
	"math/big"

	multisethash "github.com/consensys/gnark-crypto/ecc/kb8/multiset-hash"
	"github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark/constraint/solver"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all hint functions used in the package.
func GetHints() []solver.Hint {
	return []solver.Hint{yIncrementHint}
}

func yIncrementHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return fmt.Errorf("yIncrementHint: expected 1 input, got %d", len(inputs))
	}
	if len(outputs) != 9 {
		return fmt.Errorf("yIncrementHint: expected 9 outputs, got %d", len(outputs))
	}
	if !inputs[0].IsUint64() {
		return fmt.Errorf("yIncrementHint: input does not fit in uint64")
	}
	msg := inputs[0].Uint64()
	if msg > (1<<16)-1 {
		return fmt.Errorf("yIncrementHint: input %d exceeds uint16 range", msg)
	}
	p, k, err := multisethash.Map(uint16(msg))
	if err != nil {
		return err
	}
	outputs[0].SetUint64(uint64(k))
	getNativeE8(&p.X, outputs[1:])
	return nil
}

func getNativeE8(src *extensions.E8, outputs []*big.Int) {
	src.C0.B0.A0.BigInt(outputs[0])
	src.C0.B0.A1.BigInt(outputs[1])
	src.C0.B1.A0.BigInt(outputs[2])
	src.C0.B1.A1.BigInt(outputs[3])
	src.C1.B0.A0.BigInt(outputs[4])
	src.C1.B0.A1.BigInt(outputs[5])
	src.C1.B1.A0.BigInt(outputs[6])
	src.C1.B1.A1.BigInt(outputs[7])
}
