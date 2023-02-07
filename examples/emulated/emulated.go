package emulated

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type Circuit struct {
	// Limbs of non-native elements X, Y and Res
	X, Y, Res emulated.Element[emulated.Secp256k1Fp]
}

func (circuit *Circuit) Define(api frontend.API) error {
	// wrap API to work in SECP256k1 scalar field
	secp256k1, err := emulated.NewField[emulated.Secp256k1Fp](api)
	if err != nil {
		return err
	}

	tmp := secp256k1.Mul(&circuit.X, &circuit.Y)
	secp256k1.AssertIsEqual(tmp, &circuit.Res)
	return nil
}
