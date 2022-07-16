package emulated

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
)

// FieldParams describe the emulated field characteristics
type FieldParams interface {
	NbLimbs() uint
	BitsPerLimb() uint // limbSize is number of bits per limb. Top limb may contain less than limbSize bits.
	IsPrime() bool
	Modulus() *big.Int // TODO @gbotrel built-in don't copy value, we probably should.
}

var (
	qSecp256k1  *big.Int
	qGoldilocks *big.Int
)

func init() {
	qSecp256k1, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
	qGoldilocks, _ = new(big.Int).SetString("ffffffff00000001", 16)
}

// Goldilocks provide type parametrization for emulated field on 1 limb of width 64bits
// for modulus 0xffffffff00000001
type Goldilocks struct{}

func (fp Goldilocks) NbLimbs() uint     { return 1 }
func (fp Goldilocks) BitsPerLimb() uint { return 64 }
func (fp Goldilocks) IsPrime() bool     { return true }
func (fp Goldilocks) Modulus() *big.Int { return qGoldilocks }

// Secp256k1 provide type parametrization for emulated field on 8 limb of width 32bits
// for modulus 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
type Secp256k1 struct{}

func (fp Secp256k1) NbLimbs() uint     { return 8 }
func (fp Secp256k1) BitsPerLimb() uint { return 32 }
func (fp Secp256k1) IsPrime() bool     { return true }
func (fp Secp256k1) Modulus() *big.Int { return qSecp256k1 }

// BN254Fp provide type parametrization for emulated field on 8 limb of width 32bits
// for modulus 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
type BN254Fp struct{}

func (fp BN254Fp) NbLimbs() uint     { return 8 }
func (fp BN254Fp) BitsPerLimb() uint { return 32 }
func (fp BN254Fp) IsPrime() bool     { return true }
func (fp BN254Fp) Modulus() *big.Int { return ecc.BN254.BaseField() }

// BLS12377Fp provide type parametrization for emulated field on 8 limb of width 32bits
// for modulus 0x1ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c00000000001
type BLS12377Fp struct{}

func (fp BLS12377Fp) NbLimbs() uint     { return 12 }
func (fp BLS12377Fp) BitsPerLimb() uint { return 32 }
func (fp BLS12377Fp) IsPrime() bool     { return true }
func (fp BLS12377Fp) Modulus() *big.Int { return ecc.BLS12_377.BaseField() }
