package emulationparams

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/goldilocks"
)

// Goldilocks provide type parametrization for emulated field on 1 limb of width 64bits
// for modulus 0xffffffff00000001
type Goldilocks struct{}

func (fp Goldilocks) NbLimbs() uint     { return 1 }
func (fp Goldilocks) BitsPerLimb() uint { return 64 }
func (fp Goldilocks) IsPrime() bool     { return true }
func (fp Goldilocks) Modulus() *big.Int { return goldilocks.Modulus() }

// Secp256k1Fp provide type parametrization for emulated field on 4 limb of width 64bits
// for modulus 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f.
// This is the base field of secp256k1 curve
type Secp256k1Fp struct{}

func (fp Secp256k1Fp) NbLimbs() uint     { return 4 }
func (fp Secp256k1Fp) BitsPerLimb() uint { return 64 }
func (fp Secp256k1Fp) IsPrime() bool     { return true }
func (fp Secp256k1Fp) Modulus() *big.Int { return ecc.SECP256K1.BaseField() }

// Secp256k1Fr provides type parametrization for emulated field on 4 limbs of width 64bits
// for modulus 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141.
// This is the scalar field of secp256k1 curve.
type Secp256k1Fr struct{}

func (fp Secp256k1Fr) NbLimbs() uint     { return 4 }
func (fp Secp256k1Fr) BitsPerLimb() uint { return 64 }
func (fp Secp256k1Fr) IsPrime() bool     { return true }
func (fp Secp256k1Fr) Modulus() *big.Int { return ecc.SECP256K1.ScalarField() }

// BN254Fp provide type parametrization for emulated field on 4 limb of width
// 64bits for modulus
// 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47. This is
// the base field of the BN254 curve.
type BN254Fp struct{}

func (fp BN254Fp) NbLimbs() uint     { return 4 }
func (fp BN254Fp) BitsPerLimb() uint { return 64 }
func (fp BN254Fp) IsPrime() bool     { return true }
func (fp BN254Fp) Modulus() *big.Int { return ecc.BN254.BaseField() }

// BN254Fr provides type parametrisation for emulated field on 4 limbs of width
// 64bits for modulus
// 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001. This is
// the scalar field of the BN254 curve.
type BN254Fr struct{}

func (fp BN254Fr) NbLimbs() uint     { return 4 }
func (fp BN254Fr) BitsPerLimb() uint { return 64 }
func (fp BN254Fr) IsPrime() bool     { return true }
func (fp BN254Fr) Modulus() *big.Int { return ecc.BN254.ScalarField() }

// BLS12377Fp provide type parametrization for emulated field on 6 limb of width
// 64bits for modulus
// 0x1ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c00000000001.
// This is the base field of the BLS12-377 curve.
type BLS12377Fp struct{}

func (fp BLS12377Fp) NbLimbs() uint     { return 6 }
func (fp BLS12377Fp) BitsPerLimb() uint { return 64 }
func (fp BLS12377Fp) IsPrime() bool     { return true }
func (fp BLS12377Fp) Modulus() *big.Int { return ecc.BLS12_377.BaseField() }

// BLS12381Fp provide type parametrization for emulated field on 6 limb of width
// 64bits for modulus
// 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab.
// This is the base field of the BLS12-381 curve.
type BLS12381Fp struct{}

func (fp BLS12381Fp) NbLimbs() uint     { return 6 }
func (fp BLS12381Fp) BitsPerLimb() uint { return 64 }
func (fp BLS12381Fp) IsPrime() bool     { return true }
func (fp BLS12381Fp) Modulus() *big.Int { return ecc.BLS12_381.BaseField() }

// BLS12381Fr provide type parametrization for emulated field on 4 limb of width
// 64bits for modulus
// 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001.
// This is the scalar field of the BLS12-381 curve.
type BLS12381Fr struct{}

func (fp BLS12381Fr) NbLimbs() uint     { return 4 }
func (fp BLS12381Fr) BitsPerLimb() uint { return 64 }
func (fp BLS12381Fr) IsPrime() bool     { return true }
func (fp BLS12381Fr) Modulus() *big.Int { return ecc.BLS12_381.ScalarField() }
