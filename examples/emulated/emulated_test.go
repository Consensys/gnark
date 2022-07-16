package emulated

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

func TestEmulatedArithmetic(t *testing.T) {
	assert := test.NewAssert(t)
	std.RegisterHints()
	var c Circuit
	c.X = emulated.NewElement[emulated.Secp256k1](nil)
	c.Y = emulated.NewElement[emulated.Secp256k1](nil)
	c.Res = emulated.NewElement[emulated.Secp256k1](nil)

	assert.ProverSucceeded(&c, &Circuit{
		X:   emulated.NewElement[emulated.Secp256k1]("26959946673427741531515197488526605382048662297355296634326893985793"),
		Y:   emulated.NewElement[emulated.Secp256k1]("53919893346855483063030394977053210764097324594710593268653787971586"),
		Res: emulated.NewElement[emulated.Secp256k1]("485279052387156144224396168012515269674445015885648619762653195154800"),
	}, test.WithCurves(ecc.BN254))
}


TODO an element should know how to init itself / modify the parser with an interface that does that. 