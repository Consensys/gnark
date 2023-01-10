package gkr

import (
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/utils/algo_utils"
	"math/big"
)

func frontendVarToInt(a frontend.Variable) int {
	return int(a.(Variable))
}

func (i *API) newNonInputVariable(gate Gate, in []frontend.Variable) Variable {
	i.noPtr.circuit = append(i.noPtr.circuit, wireNoPtr{
		gate:   gate,
		inputs: algo_utils.Map(in, frontendVarToInt),
	})
	return Variable(len(i.noPtr.circuit) - 1)
}

func (i *API) newVar2PlusIn(gate Gate, in1, in2 frontend.Variable, in ...frontend.Variable) Variable {
	inCombined := make([]frontend.Variable, 2+len(in))
	inCombined[0] = in1
	inCombined[1] = in2
	for i := range in {
		inCombined[i+2] = in[i]
	}
	return i.newNonInputVariable(gate, inCombined)
}

func (i *API) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (i *API) Neg(i1 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (i *API) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (i *API) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return i.newVar2PlusIn(MulGate{}, i1, i2, in...)
}

func (i *API) DivUnchecked(i1, i2 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (i *API) Div(i1, i2 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (i *API) Inverse(i1 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (i *API) ToBinary(i1 frontend.Variable, n ...int) []frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (i *API) FromBinary(b ...frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (i *API) Xor(a, b frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (i *API) Or(a, b frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (i *API) And(a, b frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (i *API) Select(b frontend.Variable, i1, i2 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (i *API) Lookup2(b0, b1 frontend.Variable, i0, i1, i2, i3 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (i *API) IsZero(i1 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (i *API) Cmp(i1, i2 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (i *API) AssertIsEqual(i1, i2 frontend.Variable) {
	//TODO implement me
	panic("implement me")
}

func (i *API) AssertIsDifferent(i1, i2 frontend.Variable) {
	//TODO implement me
	panic("implement me")
}

func (i *API) AssertIsBoolean(i1 frontend.Variable) {
	//TODO implement me
	panic("implement me")
}

func (i *API) AssertIsLessOrEqual(v frontend.Variable, bound frontend.Variable) {
	//TODO implement me
	panic("implement me")
}

func (i *API) Println(a ...frontend.Variable) {
	//TODO implement me
	panic("implement me")
}

func (i *API) Compiler() frontend.Compiler {
	//TODO implement me
	panic("implement me")
}

func (i *API) NewHint(f hint.Function, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {
	//TODO implement me
	panic("implement me")
}

func (i *API) ConstantValue(v frontend.Variable) (*big.Int, bool) {
	//TODO implement me
	panic("implement me")
}
