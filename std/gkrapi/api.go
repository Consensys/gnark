package gkrapi

import (
	"github.com/consensys/gnark/constraint/solver/gkrgates"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/gkr/gkrtypes"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/gkrapi/gkr"
)

type API struct {
	circuit     gkrtypes.RegisteredCircuit
	parentApi   frontend.API
}

func frontendVarToInt(a gkr.Variable) int {
	return int(a)
}

func (api *API) NamedGate(gateName gkr.GateName, in ...gkr.Variable) gkr.Variable {
	// Get the registered gate (with both executables)
	registeredGate := gkrgates.Get(gateName)
	if registeredGate == nil {
		panic("gate not found: " + gateName)
	}

	api.circuit = append(api.circuit, gkrtypes.RegisteredWire{
		Gate:   registeredGate,
		Inputs: utils.Map(in, frontendVarToInt),
	})
	return gkr.Variable(len(api.circuit) - 1)
}

func (api *API) Gate(gate gkr.GateFunction, in ...gkr.Variable) gkr.Variable {
	if err := gkrgates.Register(gate, len(in)); err != nil {
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
