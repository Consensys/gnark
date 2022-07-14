package emulated

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

const (
	limbSize = 32
	nbLimbs  = 256 / limbSize
)

type secp256k1Element [nbLimbs]frontend.Variable

var (
	qSecp256k1 *big.Int
)

func init() {
	qSecp256k1, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
}

type Circuit struct {
	// Limbs of non-native elements X, Y and Res
	X   emulated.Element
	Y   emulated.Element
	Res emulated.Element
}

func (circuit *Circuit) Define(api frontend.API) error {
	// initialize field emulation parameters. Limbs size 32 bits and given modulus.
	// This leads to 256/32=8 limbs per element.
	// wrap API to work in SECP256k1 scalar field
	secp256k1, err := emulated.NewField(api, qSecp256k1, limbSize)
	if err != nil {
		return err
	}

	tmp := secp256k1.Mul(circuit.X, circuit.Y)
	secp256k1.AssertIsEqual(tmp, circuit.Res)
	return nil
}
