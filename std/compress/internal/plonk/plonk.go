package plonk

import "github.com/consensys/gnark/frontend"

func EvaluateExpression(api frontend.API, a, b frontend.Variable, aCoeff, bCoeff, mCoeff, constant int) frontend.Variable {
	if plonkAPI, ok := api.(frontend.PlonkAPI); ok {
		return plonkAPI.EvaluatePlonkExpression(a, b, aCoeff, bCoeff, mCoeff, constant)
	}
	return api.Add(api.Mul(a, aCoeff), api.Mul(b, bCoeff), api.Mul(mCoeff, a, b), constant)
}

func AddConstraint(api frontend.API, a, b, o frontend.Variable, qL, qR, qO, qM, qC int) {
	if papi, ok := api.(frontend.PlonkAPI); ok {
		papi.AddPlonkConstraint(a, b, o, qL, qR, qO, qM, qC)
	} else {
		api.AssertIsEqual(
			api.Add(
				api.Mul(a, qL),
				api.Mul(b, qR),
				api.Mul(a, b, qM),
				api.Mul(o, qO),
				qC,
			),
			0,
		)
	}
}
