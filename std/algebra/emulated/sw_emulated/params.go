package sw_emulated

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark/std/math/emulated"
)

// CurveParams defines parameters of an elliptic curve in short Weierstrass form
// given by the equation
//
//	Y² = X³ + aX + b
//
// The base point is defined by (Gx, Gy).
type CurveParams struct {
	A  *big.Int      // a in curve equation
	B  *big.Int      // b in curve equation
	Gx *big.Int      // base point x
	Gy *big.Int      // base point y
	Gm [][2]*big.Int // m*base point coords
}

// GetSecp256k1Params returns curve parameters for the curve secp256k1. When
// initialising new curve, use the base field [emulated.Secp256k1Fp] and scalar
// field [emulated.Secp256k1Fr].
func GetSecp256k1Params() CurveParams {
	_, g1aff := secp256k1.Generators()
	return CurveParams{
		A:  big.NewInt(0),
		B:  big.NewInt(7),
		Gx: g1aff.X.BigInt(new(big.Int)),
		Gy: g1aff.Y.BigInt(new(big.Int)),
		Gm: computeSecp256k1Table(),
	}
}

// GetBN254Params returns the curve parameters for the curve BN254 (alt_bn128).
// When initialising new curve, use the base field [emulated.BN254Fp] and scalar
// field [emulated.BN254Fr].
func GetBN254Params() CurveParams {
	_, _, g1aff, _ := bn254.Generators()
	return CurveParams{
		A:  big.NewInt(0),
		B:  big.NewInt(3),
		Gx: g1aff.X.BigInt(new(big.Int)),
		Gy: g1aff.Y.BigInt(new(big.Int)),
		Gm: computeBN254Table(),
	}
}

// GetBLS12381Params returns the curve parameters for the curve BLS12-381.
// When initialising new curve, use the base field [emulated.BLS12381Fp] and scalar
// field [emulated.BLS12381Fr].
func GetBLS12381Params() CurveParams {
	_, _, g1aff, _ := bls12381.Generators()
	return CurveParams{
		A:  big.NewInt(0),
		B:  big.NewInt(4),
		Gx: g1aff.X.BigInt(new(big.Int)),
		Gy: g1aff.Y.BigInt(new(big.Int)),
		Gm: computeBLS12381Table(),
	}
}

// GetCurveParams returns suitable curve parameters given the parametric type Base as base field.
func GetCurveParams[Base emulated.FieldParams]() CurveParams {
	var t Base
	switch t.Modulus().Text(16) {
	case "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f":
		return secp256k1Params
	case "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47":
		return bn254Params
	case "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab":
		return bls12381Params
	default:
		panic("no stored parameters")
	}
}

var (
	secp256k1Params CurveParams
	bn254Params     CurveParams
	bls12381Params  CurveParams
)

func init() {
	secp256k1Params = GetSecp256k1Params()
	bn254Params = GetBN254Params()
	bls12381Params = GetBLS12381Params()
}
