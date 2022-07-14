package emulated

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/nonnative"
)

var secp256k1 = []byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
}
var secp256k1bi = new(big.Int).SetBytes(secp256k1)

type Circuit struct {
	// Limbs of non-native elements X, Y and Res
	X   [8]frontend.Variable
	Y   [8]frontend.Variable
	Res [8]frontend.Variable
}

func (circuit *Circuit) Define(api frontend.API) error {
	// initialize field emulation parameters. Limbs size 32 bits and given modulus.
	// This leads to 256/32=8 limbs per element.
	params, err := nonnative.NewParams(32, secp256k1bi)
	if err != nil {
		return fmt.Errorf("new params: %w", err)
	}
	// wrap API to work in SECP256k1 scalar field
	api = nonnative.NewAPI(api, params)
	// compose value 26959946673427741531515197488526605382048662297355296634326893985793 from limbs
	X1nn := params.ConstantFromLimbs(circuit.X[:])
	// compose value 53919893346855483063030394977053210764097324594710593268653787971586 from limbs
	X2nn := params.ConstantFromLimbs(circuit.Y[:])
	// compose expected value 485279052387156144224396168012515269674445015885648619762653195154800 from limbs
	Resnn := params.ConstantFromLimbs(circuit.Res[:])

	tmp := api.Mul(X1nn, X2nn)
	api.AssertIsEqual(tmp, Resnn)
	return nil
}
