package utils

import (
	"math/big"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
)

var curves map[string]ecc.ID

func init() {
	curves = make(map[string]ecc.ID)
	for _, c := range gnark.Curves() {
		fHex := c.ScalarField().Text(16)
		curves[fHex] = c
	}
}

func FieldToCurve(q *big.Int) ecc.ID {
	fHex := q.Text(16)
	curve, ok := curves[fHex]
	if !ok {
		return ecc.UNKNOWN
	}
	return curve
}
