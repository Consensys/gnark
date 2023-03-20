package weierstrass

import (
	"math/big"

	"github.com/consensys/gnark/std/math/emulated"
)

// CurveParams defines parameters of an elliptic curve in short Weierstrass form
// given by the equation
//
//	Y² = X³ + aX + b
//
// The base point is defined by (Gx, Gy).
type CurveParams struct {
	A  *big.Int // a in curve equation
	B  *big.Int // b in curve equation
	Gx *big.Int // base point x
	Gy *big.Int // base point y
}

// GetSecp256k1Params returns curve parameters for the curve secp256k1. When
// initialising new curve, use the base field [emulated.Secp256k1Fp] and scalar
// field [emulated.Secp256k1Fr].
func GetSecp256k1Params() CurveParams {
	gx, _ := new(big.Int).SetString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16)
	gy, _ := new(big.Int).SetString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16)
	return CurveParams{
		A:  big.NewInt(0),
		B:  big.NewInt(7),
		Gx: gx,
		Gy: gy,
	}
}

// GetBN254Params returns the curve parameters for the curve BN254 (alt_bn128).
// When initialising new curve, use the base field [emulated.BN254Fp] and scalar
// field [emulated.BN254Fr].
func GetBN254Params() CurveParams {
	gx := big.NewInt(1)
	gy := big.NewInt(2)
	return CurveParams{
		A:  big.NewInt(0),
		B:  big.NewInt(3),
		Gx: gx,
		Gy: gy,
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
	default:
		panic("no stored parameters")
	}
}

var (
	secp256k1Params CurveParams
	bn254Params     CurveParams
)

func init() {
	secp256k1Params = GetSecp256k1Params()
	bn254Params = GetBN254Params()
}
