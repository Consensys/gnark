package mimc_gkr

import (
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
)

func NewMimcWithGKR(api frontend.API, il, ir frontend.Variable) frontend.Variable {
	// ensure they are linear expressions
	il = api.Add(il, ir)              // il + ir
	ir = api.Sub(api.Add(ir, ir), ir) // ir
	results, err := api.Compiler().NewHint(hint.MIMC2Elements, 1, il, ir)
	if err != nil {
		panic(err)
	}

	return results[0]
}

func NewMimcWithGKRPure(api frontend.API, il, ir frontend.Variable) frontend.Variable {
	// ensure they are linear expressions
	il = api.Add(il, ir)              // il + ir
	ir = api.Sub(api.Add(ir, ir), ir) // ir
	results, err := api.Compiler().NewHint(hint.MIMC2ElementsPure, 1, il, ir)
	if err != nil {
		panic(err)
	}

	return results[0]
}
