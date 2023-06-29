package gkr

import (
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/std/utils/algo_utils"
)

func frontendVarToInt(a constraint.GkrVariable) int {
	return int(a)
}

func (api *API) NamedGate(gate string, in ...constraint.GkrVariable) constraint.GkrVariable {
	api.toStore.Circuit = append(api.toStore.Circuit, constraint.GkrWire{
		Gate:   gate,
		Inputs: algo_utils.Map(in, frontendVarToInt),
	})
	api.assignments = append(api.assignments, nil)
	return constraint.GkrVariable(len(api.toStore.Circuit) - 1)
}

func (api *API) namedGate2PlusIn(gate string, in1, in2 constraint.GkrVariable, in ...constraint.GkrVariable) constraint.GkrVariable {
	inCombined := make([]constraint.GkrVariable, 2+len(in))
	inCombined[0] = in1
	inCombined[1] = in2
	for i := range in {
		inCombined[i+2] = in[i]
	}
	return api.NamedGate(gate, inCombined...)
}

func (api *API) Add(i1, i2 constraint.GkrVariable, in ...constraint.GkrVariable) constraint.GkrVariable {
	return api.namedGate2PlusIn("add", i1, i2, in...)
}

func (api *API) Neg(i1 constraint.GkrVariable) constraint.GkrVariable {
	return api.NamedGate("neg", i1)
}

func (api *API) Sub(i1, i2 constraint.GkrVariable, in ...constraint.GkrVariable) constraint.GkrVariable {
	return api.namedGate2PlusIn("sub", i1, i2, in...)
}

func (api *API) Mul(i1, i2 constraint.GkrVariable, in ...constraint.GkrVariable) constraint.GkrVariable {
	return api.namedGate2PlusIn("mul", i1, i2, in...)
}

// TODO @Tabaie This can be useful
func (api *API) Println(a ...constraint.GkrVariable) {
	panic("not implemented")
}
