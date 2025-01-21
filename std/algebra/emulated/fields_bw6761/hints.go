package fields_bw6761

import (
	"math/big"

	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/math/emulated"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all hint functions used in the package.
func GetHints() []solver.Hint {
	return []solver.Hint{
		divE6Hint,
		inverseE6Hint,
		divE6By362880Hint,
	}
}

func inverseE6Hint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var a, c bw6761.E6

			a.B0.A0.SetBigInt(inputs[0])
			a.B0.A1.SetBigInt(inputs[2])
			a.B0.A2.SetBigInt(inputs[4])
			a.B1.A0.SetBigInt(inputs[1])
			a.B1.A1.SetBigInt(inputs[3])
			a.B1.A2.SetBigInt(inputs[5])

			c.Inverse(&a)

			c.B0.A0.BigInt(outputs[0])
			c.B0.A1.BigInt(outputs[2])
			c.B0.A2.BigInt(outputs[4])
			c.B1.A0.BigInt(outputs[1])
			c.B1.A1.BigInt(outputs[3])
			c.B1.A2.BigInt(outputs[5])

			return nil
		})
}

func divE6Hint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var a, b, c bw6761.E6

			a.B0.A0.SetBigInt(inputs[0])
			a.B0.A1.SetBigInt(inputs[2])
			a.B0.A2.SetBigInt(inputs[4])
			a.B1.A0.SetBigInt(inputs[1])
			a.B1.A1.SetBigInt(inputs[3])
			a.B1.A2.SetBigInt(inputs[5])
			b.B0.A0.SetBigInt(inputs[6])
			b.B0.A1.SetBigInt(inputs[8])
			b.B0.A2.SetBigInt(inputs[10])
			b.B1.A0.SetBigInt(inputs[7])
			b.B1.A1.SetBigInt(inputs[9])
			b.B1.A2.SetBigInt(inputs[11])

			c.Inverse(&b).Mul(&c, &a)

			c.B0.A0.BigInt(outputs[0])
			c.B0.A1.BigInt(outputs[2])
			c.B0.A2.BigInt(outputs[4])
			c.B1.A0.BigInt(outputs[1])
			c.B1.A1.BigInt(outputs[3])
			c.B1.A2.BigInt(outputs[5])

			return nil
		})
}

func divE6By362880Hint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var a, c bw6761.E6

			a.B0.A0.SetBigInt(inputs[0])
			a.B0.A1.SetBigInt(inputs[2])
			a.B0.A2.SetBigInt(inputs[4])
			a.B1.A0.SetBigInt(inputs[1])
			a.B1.A1.SetBigInt(inputs[3])
			a.B1.A2.SetBigInt(inputs[5])

			var sixInv fp.Element
			sixInv.SetString("362880")
			sixInv.Inverse(&sixInv)
			c.B0.MulByElement(&a.B0, &sixInv)
			c.B1.MulByElement(&a.B1, &sixInv)

			c.B0.A0.BigInt(outputs[0])
			c.B0.A1.BigInt(outputs[2])
			c.B0.A2.BigInt(outputs[4])
			c.B1.A0.BigInt(outputs[1])
			c.B1.A1.BigInt(outputs[3])
			c.B1.A2.BigInt(outputs[5])

			return nil
		})
}
