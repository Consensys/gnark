package evmprecompiles

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

// Expmod implements [MODEXP] precompile contract at address 0x05.
//
// Internally, uses 4k elements for representing the base, exponent and modulus,
// upper bounding the sizes of the inputs. The runtime is constant regardless of
// the actual length of the inputs.
//
// [MODEXP]: https://ethereum.github.io/execution-specs/autoapi/ethereum/paris/vm/precompiled_contracts/expmod/index.html
func Expmod(api frontend.API, base, exp, modulus *emulated.Element[emparams.Mod1e4096]) *emulated.Element[emparams.Mod1e4096] {
	// x^0 = 1
	// x mod 0 = 0
	f, err := emulated.NewField[emparams.Mod1e4096](api)
	if err != nil {
		panic(fmt.Sprintf("new field: %v", err))
	}
	// in case modulus is zero, then need to compute with dummy values and return zero as a result
	isZeroMod := f.IsZero(modulus)
	modulus = f.Select(isZeroMod, f.One(), modulus)
	res := f.ModExp(base, exp, modulus)
	res = f.Select(isZeroMod, f.Zero(), res)
	return res
}
