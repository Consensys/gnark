package gkrapi

import (
	"github.com/consensys/gnark/frontend"
	gadget "github.com/consensys/gnark/internal/gkr"
	"github.com/consensys/gnark/internal/gkr/gkrtypes"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/gkrapi/gkr"
)

type API struct {
	circuit      gkrtypes.SerializableCircuit
	assignments  gadget.WireAssignment
	parentApi    frontend.API
	gateRegistry gateRegistry
}

func frontendVarToInt(a gkr.Variable) int {
	return int(a)
}

func (api *API) gate(id gkrtypes.GateID, inputs ...gkr.Variable) gkr.Variable {
	api.circuit = append(api.circuit, gkrtypes.SerializableWire{
		Gate:   id,
		Inputs: utils.Map(inputs, frontendVarToInt),
	})
	api.assignments = append(api.assignments, nil)
	return gkr.Variable(len(api.circuit) - 1)
}

// Gate adds the given gate with the given inputs and returns its output wire.
func (api *API) Gate(gate gkr.GateFunction, inputs ...gkr.Variable) gkr.Variable {
	return api.gate(api.gateRegistry.getID(gate, len(inputs)), inputs...)
}

func (api *API) gate2PlusIn(gate gkrtypes.GateID, in1, in2 gkr.Variable, in ...gkr.Variable) gkr.Variable {
	inCombined := make([]gkr.Variable, 2+len(in))
	inCombined[0] = in1
	inCombined[1] = in2
	for i := range in {
		inCombined[i+2] = in[i]
	}
	return api.gate(gate, inCombined...)
}

func (api *API) Add(i1, i2 gkr.Variable) gkr.Variable {
	return api.gate2PlusIn(idAdd2, i1, i2)
}

func (api *API) Neg(i1 gkr.Variable) gkr.Variable {
	return api.gate(idNeg, i1)
}

func (api *API) Sub(i1, i2 gkr.Variable) gkr.Variable {
	return api.gate2PlusIn(idSub2, i1, i2)
}

func (api *API) Mul(i1, i2 gkr.Variable) gkr.Variable {
	return api.gate2PlusIn(idMul2, i1, i2)
}
