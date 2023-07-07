package fields_bw6761

import (
	"math/big"

	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/math/emulated"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all hint functions used in the package.
func GetHints() []solver.Hint {
	return []solver.Hint{
		// E3
		divE3Hint,
		inverseE3Hint,
	}
}

func inverseE3Hint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var a, c bw6761.E3

			a.A0.SetBigInt(inputs[0])
			a.A1.SetBigInt(inputs[1])
			a.A2.SetBigInt(inputs[2])

			c.Inverse(&a)

			c.A0.BigInt(outputs[0])
			c.A1.BigInt(outputs[1])
			c.A2.BigInt(outputs[2])

			return nil
		})
}

func divE3Hint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var a, b, c bw6761.E3

			a.A0.SetBigInt(inputs[0])
			a.A1.SetBigInt(inputs[1])
			a.A2.SetBigInt(inputs[2])
			b.A0.SetBigInt(inputs[3])
			b.A1.SetBigInt(inputs[4])
			b.A2.SetBigInt(inputs[5])

			c.Inverse(&b).Mul(&c, &a)

			c.A0.BigInt(outputs[0])
			c.A1.BigInt(outputs[1])
			c.A2.BigInt(outputs[2])

			return nil
		})
}
