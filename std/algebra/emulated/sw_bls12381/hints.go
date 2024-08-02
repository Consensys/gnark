package sw_bls12381

import (
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/math/emulated"
)

func GetHints() []solver.Hint {
	return []solver.Hint{
		sqrtRatioHint,
	}
}

func init() {
	solver.RegisterHint(GetHints()...)
}

func sqrtRatioHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	return emulated.UnwrapHint(inputs, outputs, func(field *big.Int, inputs, outputs []*big.Int) error {
		if len(inputs) != 4 {
			return fmt.Errorf("expecting 4 inputs")
		}
		if len(outputs) != 3 {
			return fmt.Errorf("expecting 3 outputs")
		}

		var z0, z1, u0, u1, v0, v1 fp.Element
		u0.SetBigInt(inputs[0])
		u1.SetBigInt(inputs[1])
		v0.SetBigInt(inputs[2])
		v1.SetBigInt(inputs[3])

		b := bls12381.G2SqrtRatio(&z0, &z1, &u0, &u1, &v0, &v1)
		outputs[0].SetUint64(b)
		z0.BigInt(outputs[1])
		z1.BigInt(outputs[2])
		return nil
	})
}
