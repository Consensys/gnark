package gkrapi

import (
	"github.com/consensys/gnark/constraint/solver/gkrgates"
	"github.com/consensys/gnark/internal/gkr/gkrinfo"
	"github.com/consensys/gnark/internal/gkr/gkrtypes"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/gkrapi/v2/gkr"
)

type API struct {
	toStore     gkrinfo.StoringInfo
	assignments gkrtypes.WireAssignment
}

func frontendVarToInt(a gkr.Variable) int {
	return int(a)
}

func (api *API) NamedGate(gate gkr.GateName, in ...gkr.Variable) gkr.Variable {
	api.toStore.Circuit = append(api.toStore.Circuit, gkrinfo.Wire{
		Gate:   string(gate),
		Inputs: utils.Map(in, frontendVarToInt),
	})
	api.assignments = append(api.assignments, nil)
	return gkr.Variable(len(api.toStore.Circuit) - 1)
}

func (api *API) Gate(gate gkr.GateFunction, in ...gkr.Variable) gkr.Variable {
	if _, err := gkrgates.Register(gate, len(in)); err != nil {
		panic(err)
	}
	return api.NamedGate(gkrgates.GetDefaultGateName(gate), in...)
}

func (api *API) namedGate2PlusIn(gate gkr.GateName, in1, in2 gkr.Variable, in ...gkr.Variable) gkr.Variable {
	inCombined := make([]gkr.Variable, 2+len(in))
	inCombined[0] = in1
	inCombined[1] = in2
	for i := range in {
		inCombined[i+2] = in[i]
	}
	return api.NamedGate(gate, inCombined...)
}

func (api *API) Add(i1, i2 gkr.Variable) gkr.Variable {
	return api.namedGate2PlusIn(gkr.Add2, i1, i2)
}

func (api *API) Neg(i1 gkr.Variable) gkr.Variable {
	return api.NamedGate("neg", i1)
}

func (api *API) Sub(i1, i2 gkr.Variable) gkr.Variable {
	return api.namedGate2PlusIn(gkr.Sub2, i1, i2)
}

func (api *API) Mul(i1, i2 gkr.Variable) gkr.Variable {
	return api.namedGate2PlusIn(gkr.Mul2, i1, i2)
}
