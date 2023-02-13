package gkr

import "github.com/consensys/gnark/frontend"

var RegisteredGates = map[string]Gate{
	"identity": IdentityGate{},
	"add":      AddGate{},
	"mul":      MulGate{},
	"mimc":     MiMCCipherGate{Ark: 0}, //TODO: Add ark
}

type MiMCCipherGate struct {
	Ark frontend.Variable
}

func (m MiMCCipherGate) Evaluate(api frontend.API, input ...frontend.Variable) frontend.Variable {

	if len(input) != 2 {
		panic("mimc has fan-in 2")
	}
	sum := api.Add(input[0], input[1], m.Ark)

	sumCubed := api.Mul(sum, sum, sum) // sum^3
	return api.Mul(sumCubed, sumCubed, sum)
}

func (m MiMCCipherGate) Degree() int {
	return 7
}
