package gkr

import (
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/utils/algo_utils"
	"math/big"
)

func frontendVarToInt(a frontend.Variable) int {
	return int(a.(constraint.GkrVariable))
}

func (api *API) newNonInputVariable(gate string, in []frontend.Variable) constraint.GkrVariable {
	api.toStore.Circuit = append(api.toStore.Circuit, constraint.GkrWire{
		Gate:   gate,
		Inputs: algo_utils.Map(in, frontendVarToInt),
	})
	return constraint.GkrVariable(len(api.toStore.Circuit) - 1)
}

func (api *API) newVar2PlusIn(gate string, in1, in2 frontend.Variable, in ...frontend.Variable) constraint.GkrVariable {
	inCombined := make([]frontend.Variable, 2+len(in))
	inCombined[0] = in1
	inCombined[1] = in2
	for i := range in {
		inCombined[i+2] = in[i]
	}
	return api.newNonInputVariable(gate, inCombined)
}

func (api *API) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return api.newVar2PlusIn("add", i1, i2, in...)
}

func (api *API) Neg(i1 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (api *API) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (api *API) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return api.newVar2PlusIn("mul", i1, i2, in...)
}

func (api *API) DivUnchecked(i1, i2 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (api *API) Div(i1, i2 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (api *API) Inverse(i1 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (api *API) ToBinary(i1 frontend.Variable, n ...int) []frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (api *API) FromBinary(b ...frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (api *API) Xor(a, b frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (api *API) Or(a, b frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (api *API) And(a, b frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (api *API) Select(b frontend.Variable, i1, i2 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (api *API) Lookup2(b0, b1 frontend.Variable, i0, i1, i2, i3 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (api *API) IsZero(i1 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (api *API) Cmp(i1, i2 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (api *API) AssertIsEqual(i1, i2 frontend.Variable) {
	//TODO implement me
	panic("implement me")
}

func (api *API) AssertIsDifferent(i1, i2 frontend.Variable) {
	//TODO implement me
	panic("implement me")
}

func (api *API) AssertIsBoolean(i1 frontend.Variable) {
	//TODO implement me
	panic("implement me")
}

func (api *API) AssertIsLessOrEqual(v frontend.Variable, bound frontend.Variable) {
	//TODO implement me
	panic("implement me")
}

func (api *API) Println(a ...frontend.Variable) {
	//TODO implement me
	panic("implement me")
}

func (api *API) Compiler() frontend.Compiler {
	//TODO implement me
	panic("implement me")
}

func (api *API) NewHint(f hint.Function, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {
	//TODO implement me
	panic("implement me")
}

func (api *API) ConstantValue(v frontend.Variable) (*big.Int, bool) {
	//TODO implement me
	panic("implement me")
}
