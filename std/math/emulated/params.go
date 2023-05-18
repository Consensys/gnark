package emulated

import (
	"math/big"

	"github.com/consensys/gnark/std/math/emulated/emparams"
)

// FieldParams describes the emulated field characteristics. For a list of
// included built-in emulation params refer to the [emparams] package.
// For backwards compatibility, the current package contains the following
// parameters:
//   - [Goldilocks]
//   - [Secp256k1Fp] and [Secp256k1Fr]
//   - [BN254Fp] and [BN254Fr]
//   - [BLS12377Fp]
//   - [BLS12381Fp] and [BLS12381Fr]
//
// Any new parameters will be included in [emparams] package, not here.
type FieldParams interface {
	NbLimbs() uint     // number of limbs to represent field element
	BitsPerLimb() uint // number of bits per limb. Top limb may contain less than limbSize bits.
	IsPrime() bool     // indicates if the modulus is prime
	Modulus() *big.Int // returns modulus. Do not modify.
}

type Goldilocks = emparams.Goldilocks
type Secp256k1Fp = emparams.Secp256k1Fp
type Secp256k1Fr = emparams.Secp256k1Fr
type BN254Fp = emparams.BN254Fp
type BN254Fr = emparams.BN254Fr
type BLS12377Fp = emparams.BLS12377Fp
type BLS12381Fp = emparams.BLS12381Fp
type BLS12381Fr = emparams.BLS12381Fr
