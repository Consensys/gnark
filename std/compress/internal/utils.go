package internal

import (
	"github.com/consensys/gnark/frontend"
)

func EvaluatePlonkExpression(api frontend.API, a, b frontend.Variable, aCoeff, bCoeff, mCoeff, constant int) frontend.Variable {
	if plonkAPI, ok := api.(frontend.PlonkAPI); ok {
		return plonkAPI.EvaluatePlonkExpression(a, b, aCoeff, bCoeff, mCoeff, constant)
	}
	return api.Add(api.Mul(a, aCoeff), api.Mul(b, bCoeff), api.Mul(mCoeff, a, b), constant)
}
