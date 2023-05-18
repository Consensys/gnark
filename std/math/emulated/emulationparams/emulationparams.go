// Package emulationparams contains emulation parameters for well known fields.
//
// We define some well-known parameters in this package for compatibility and
// ease of use. When needing to use parameters not defined in this package it is
// sufficient to define a new type implementing [FieldParams]. For example, as:
//
//	type SmallField struct {}
//	func (SmallField) NbLimbs() uint { return 1 }
//	func (SmallField) BitsPerLimb() uint { return 11 }
//	func (SmallField) IsPrime() bool { return true }
//	func (SmallField) Modulus() *big.Int { return big.NewInt(1032) }
package emulationparams

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/goldilocks"
)

// Goldilocks provides type parametrization for field emulation:
//   - limbs: 1
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0xffffffff00000001 (base 16)
//	18446744069414584321 (base 10)
type Goldilocks struct{}

func (fp Goldilocks) NbLimbs() uint     { return 1 }
func (fp Goldilocks) BitsPerLimb() uint { return 64 }
func (fp Goldilocks) IsPrime() bool     { return true }
func (fp Goldilocks) Modulus() *big.Int { return goldilocks.Modulus() }

// Secp256k1Fp provides type parametrization for field emulation:
//   - limbs: 4
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f (base 16)
//	115792089237316195423570985008687907853269984665640564039457584007908834671663 (base 10)
//
// This is the base field of the SECP256k1 curve.
type Secp256k1Fp struct{}

func (fp Secp256k1Fp) NbLimbs() uint     { return 4 }
func (fp Secp256k1Fp) BitsPerLimb() uint { return 64 }
func (fp Secp256k1Fp) IsPrime() bool     { return true }
func (fp Secp256k1Fp) Modulus() *big.Int { return ecc.SECP256K1.BaseField() }

// Secp256k1Fr provides type parametrization for field emulation:
//   - limbs: 4
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 (base 16)
//	115792089237316195423570985008687907852837564279074904382605163141518161494337 (base 10)
//
// This is the scalar field of the SECP256k1 curve.
type Secp256k1Fr struct{}

func (fp Secp256k1Fr) NbLimbs() uint     { return 4 }
func (fp Secp256k1Fr) BitsPerLimb() uint { return 64 }
func (fp Secp256k1Fr) IsPrime() bool     { return true }
func (fp Secp256k1Fr) Modulus() *big.Int { return ecc.SECP256K1.ScalarField() }

// BN254Fp provides type parametrization for field emulation:
//   - limbs: 4
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47 (base 16)
//	21888242871839275222246405745257275088696311157297823662689037894645226208583 (base 10)
//
// This is the base field of the BN254 curve.
type BN254Fp struct{}

func (fp BN254Fp) NbLimbs() uint     { return 4 }
func (fp BN254Fp) BitsPerLimb() uint { return 64 }
func (fp BN254Fp) IsPrime() bool     { return true }
func (fp BN254Fp) Modulus() *big.Int { return ecc.BN254.BaseField() }

// BN254Fr provides type parametrization for field emulation:
//   - limbs: 4
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001 (base 16)
//	21888242871839275222246405745257275088548364400416034343698204186575808495617 (base 10)
//
// This is the scalar field of the BN254 curve.
type BN254Fr struct{}

func (fp BN254Fr) NbLimbs() uint     { return 4 }
func (fp BN254Fr) BitsPerLimb() uint { return 64 }
func (fp BN254Fr) IsPrime() bool     { return true }
func (fp BN254Fr) Modulus() *big.Int { return ecc.BN254.ScalarField() }

// BLS12377Fp provides type parametrization for field emulation:
//   - limbs: 6
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0x1ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c00000000001 (base 16)
//	258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177 (base 10)
//
// This is the base field of the BLS12-377 curve.
type BLS12377Fp struct{}

func (fp BLS12377Fp) NbLimbs() uint     { return 6 }
func (fp BLS12377Fp) BitsPerLimb() uint { return 64 }
func (fp BLS12377Fp) IsPrime() bool     { return true }
func (fp BLS12377Fp) Modulus() *big.Int { return ecc.BLS12_377.BaseField() }

// BLS12381Fp provides type parametrization for field emulation:
//   - limbs: 6
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab (base 16)
//	4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787 (base 10)
//
// This is the base field of the BLS12-381 curve.
type BLS12381Fp struct{}

func (fp BLS12381Fp) NbLimbs() uint     { return 6 }
func (fp BLS12381Fp) BitsPerLimb() uint { return 64 }
func (fp BLS12381Fp) IsPrime() bool     { return true }
func (fp BLS12381Fp) Modulus() *big.Int { return ecc.BLS12_381.BaseField() }

// BLS12381Fr provides type parametrization for field emulation:
//   - limbs: 4
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001 (base 16)
//	52435875175126190479447740508185965837690552500527637822603658699938581184513 (base 10)
//
// This is the scalar field of the BLS12-381 curve.
type BLS12381Fr struct{}

func (fp BLS12381Fr) NbLimbs() uint     { return 4 }
func (fp BLS12381Fr) BitsPerLimb() uint { return 64 }
func (fp BLS12381Fr) IsPrime() bool     { return true }
func (fp BLS12381Fr) Modulus() *big.Int { return ecc.BLS12_381.ScalarField() }
