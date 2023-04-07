package sw_bls12381

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/math/emulated"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all hint functions used in the package.
func GetHints() []solver.Hint {
	return []solver.Hint{
		subgroupG1Hint,
		subgroupG2Hint,
	}
}

func subgroupG1Hint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var a, c bls12381.G1Affine

			a.X.SetBigInt(inputs[0])
			a.Y.SetBigInt(inputs[1])

			// c = -[x²]ϕ(p)
			x0, _ := new(big.Int).SetString("15132376222941642752", 10) // negative
			var jac bls12381.G1Jac
			jac.FromAffine(&a)
			jac.Phi(&jac).ScalarMultiplication(&jac, x0).
				ScalarMultiplication(&jac, x0).
				Neg(&jac)
			c.FromJacobian(&jac)

			c.X.BigInt(outputs[0])
			c.Y.BigInt(outputs[1])

			return nil
		})
}

func subgroupG2Hint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var a, c bls12381.G2Affine

			a.X.A0.SetBigInt(inputs[0])
			a.X.A1.SetBigInt(inputs[1])
			a.Y.A0.SetBigInt(inputs[2])
			a.Y.A1.SetBigInt(inputs[3])

			// c = [x₀]a
			x0, _ := new(big.Int).SetString("15132376222941642752", 10) // negative
			c.ScalarMultiplication(&a, x0).Neg(&c)

			c.X.A0.BigInt(outputs[0])
			c.X.A1.BigInt(outputs[1])
			c.Y.A0.BigInt(outputs[2])
			c.Y.A1.BigInt(outputs[3])

			return nil
		})
}
