package evmprecompiles

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
)

// ECPair implements [ALT_BN128_PAIRING_CHECK] precompile contract at address 0x08.
//
// [ALT_BN128_PAIRING_CHECK]: https://ethereum.github.io/execution-specs/autoapi/ethereum/paris/vm/precompiled_contracts/alt_bn128/index.html#alt-bn128-pairing-check
func ECPair(api frontend.API, P *sw_bn254.G1Affine, Q *sw_bn254.G2Affine) {
	pair, err := sw_bn254.NewPairing(api)
	if err != nil {
		panic(err)
	}
	if err := pair.PairingCheck([]*sw_bn254.G1Affine{P}, []*sw_bn254.G2Affine{Q}); err != nil {
		panic(err)
	}
}
