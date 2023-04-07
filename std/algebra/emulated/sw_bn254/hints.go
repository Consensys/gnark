package sw_bn254

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/math/emulated"
)

func init() {
	solver.RegisterHint(subgroupG2Hint)
}

func subgroupG2Hint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			var a, c bn254.G2Affine

			a.X.A0.SetBigInt(inputs[0])
			a.X.A1.SetBigInt(inputs[1])
			a.Y.A0.SetBigInt(inputs[2])
			a.Y.A1.SetBigInt(inputs[3])

			// c = ψ³([2x₀]a) - ψ²([x₀]a) - ψ([x₀]a) - [x₀]a
			x0, _ := new(big.Int).SetString("4965661367192848881", 10)
			var aJac, t1, t2, t3 bn254.G2Jac
			aJac.FromAffine(&a)
			aJac.ScalarMultiplication(&aJac, x0)
			t1.Psi(&aJac)
			t2.Psi(&t1)
			t3.Psi(&t2).Double(&t3).Neg(&t3)
			aJac.AddAssign(&t1).AddAssign(&t2).AddAssign(&t3).Neg(&aJac)
			c.FromJacobian(&aJac)

			c.X.A0.BigInt(outputs[0])
			c.X.A1.BigInt(outputs[1])
			c.Y.A0.BigInt(outputs[2])
			c.Y.A1.BigInt(outputs[3])

			return nil
		})
}
