package fields_octobear

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark/constraint/solver"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

func GetHints() []solver.Hint {
	return []solver.Hint{divE8Hint, inverseE8Hint}
}

func divE8Hint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 16 {
		return fmt.Errorf("divE8Hint: expected 16 inputs, got %d", len(inputs))
	}
	if len(outputs) != 8 {
		return fmt.Errorf("divE8Hint: expected 8 outputs, got %d", len(outputs))
	}
	var a, b, c extensions.E8
	SetNativeE8(&a, inputs[:8])
	SetNativeE8(&b, inputs[8:])
	c.Inverse(&b).Mul(&c, &a)
	GetNativeE8(&c, outputs)
	return nil
}

func inverseE8Hint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 8 {
		return fmt.Errorf("inverseE8Hint: expected 8 inputs, got %d", len(inputs))
	}
	if len(outputs) != 8 {
		return fmt.Errorf("inverseE8Hint: expected 8 outputs, got %d", len(outputs))
	}
	var a, c extensions.E8
	SetNativeE8(&a, inputs)
	c.Inverse(&a)
	GetNativeE8(&c, outputs)
	return nil
}

func SetNativeE8(dst *extensions.E8, inputs []*big.Int) {
	dst.C0.B0.A0.SetBigInt(inputs[0])
	dst.C0.B0.A1.SetBigInt(inputs[1])
	dst.C0.B1.A0.SetBigInt(inputs[2])
	dst.C0.B1.A1.SetBigInt(inputs[3])
	dst.C1.B0.A0.SetBigInt(inputs[4])
	dst.C1.B0.A1.SetBigInt(inputs[5])
	dst.C1.B1.A0.SetBigInt(inputs[6])
	dst.C1.B1.A1.SetBigInt(inputs[7])
}

func GetNativeE8(src *extensions.E8, outputs []*big.Int) {
	src.C0.B0.A0.BigInt(outputs[0])
	src.C0.B0.A1.BigInt(outputs[1])
	src.C0.B1.A0.BigInt(outputs[2])
	src.C0.B1.A1.BigInt(outputs[3])
	src.C1.B0.A0.BigInt(outputs[4])
	src.C1.B0.A1.BigInt(outputs[5])
	src.C1.B1.A0.BigInt(outputs[6])
	src.C1.B1.A1.BigInt(outputs[7])
}
