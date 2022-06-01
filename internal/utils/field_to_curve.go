package utils

import (
	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field"
)

var curves map[string]ecc.ID

func init() {
	curves = make(map[string]ecc.ID)
	for _, c := range gnark.Curves() {
		fHex := c.ScalarField().Modulus().Text(16)
		curves[fHex] = c
	}
}

func FieldToCurve(f field.Field) ecc.ID {
	fHex := f.Modulus().Text(16)
	curve, ok := curves[fHex]
	if !ok {
		return ecc.UNKNOWN
	}
	return curve
}
