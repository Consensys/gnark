package evmprecompiles

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

// Expmod implements [MODEXP] precompile contract at address 0x05.
//
// Internally, uses 4k elements for representing the base, exponent and modulus,
// upper bounding the sizes of the inputs. The runtime is constant regardless of
// the actual length of the inputs.
//
// [MODEXP]: https://ethereum.github.io/execution-specs/autoapi/ethereum/paris/vm/precompiled_contracts/expmod/index.html
func Expmod[P emulated.FieldParams](api frontend.API, base, exp, modulus *emulated.Element[P]) *emulated.Element[P] {
	// x^0 = 1
	// x mod 0 = 0
	f, err := emulated.NewField[P](api)
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
