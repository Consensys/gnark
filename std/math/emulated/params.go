package emulated

import (
	"math/big"

	"github.com/consensys/gnark/std/math/emulated/emulationparams"
)

// FieldParams describes the emulated field characteristics
type FieldParams interface {
	NbLimbs() uint     // number of limbs to represent field element
	BitsPerLimb() uint // number of bits per limb. Top limb may contain less than limbSize bits.
	IsPrime() bool     // indicates if the modulus is prime
	Modulus() *big.Int // returns modulus. Do not modify.
}

type Goldilocks = emulationparams.Goldilocks
type Secp256k1Fp = emulationparams.Secp256k1Fp
type Secp256k1Fr = emulationparams.Secp256k1Fr
type BN254Fp = emulationparams.BN254Fp
type BN254Fr = emulationparams.BN254Fr
type BLS12377Fp = emulationparams.BLS12377Fp
type BLS12381Fp = emulationparams.BLS12381Fp
type BLS12381Fr = emulationparams.BLS12381Fr
