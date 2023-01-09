package gkr

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/gkr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/utils/algo_utils"
	"math/big"
)

type bn254CircuitData struct {
	assignments gkr.WireAssignment
	circuit     gkr.Circuit
	memoryPool  polynomial.Pool
}

func convertGate(gate Gate) gkr.Gate {
	return gateConverter{gate: gate}
}

func convertCircuit(noPtr circuitNoPtr) gkr.Circuit {
	resCircuit := make(gkr.Circuit, len(noPtr))
	for i := range noPtr {
		resCircuit[i].Gate = convertGate(noPtr[i].gate)
		resCircuit[i].Inputs = algo_utils.Map(noPtr[i].inputs, slicePtrAt(resCircuit))
	}
	return resCircuit
}

type gateConverter struct {
	gate Gate
	api  gateConversionApi
}

func (c gateConverter) Degree() int {
	return c.gate.Degree()
}

func newGateConverter(gate Gate) gateConverter {
	return gateConverter{
		gate: gate,
		api:  gateConversionApi{},
	}
}

func elementSliceToVariableSlice(e []fr.Element) []frontend.Variable {
	res := make([]frontend.Variable, len(e))
	for i := range res {
		res[i] = e[i]
	}
	return res
}

func (c gateConverter) Evaluate(ins ...fr.Element) fr.Element {
	return c.gate.Evaluate(&c.api, elementSliceToVariableSlice(ins)...).(fr.Element)
}

type gateConversionApi struct{}

/*func forceElemPtr(elems []fr.Element, i1, i2 frontend.Variable, in ...frontend.Variable) []*fr.Element {
	res := make([]*fr.Element, 2+len(in))
	res[0] = &elems[i1.(int)]
	res[1] = &elems[i2.(int)]
	for i := range in {
		res[2+i] = &elems[in[i].(int)]
	}
}*/

func varsToElems(i1, i2 frontend.Variable, in ...frontend.Variable) []fr.Element {
	res := make([]fr.Element, 2+len(in))
	res[0] = i1.(fr.Element)
	res[1] = i2.(fr.Element)
	for i := range in {
		res[2+i] = in[i].(fr.Element)
	}
	return res
}

func (c *gateConversionApi) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (c *gateConversionApi) Neg(i1 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (c *gateConversionApi) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (c *gateConversionApi) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	elems := varsToElems(i1, i2, in...)
	var res fr.Element
	res.Mul(&elems[0], &elems[1])
	for i := range in {
		res.Mul(&res, &elems[i+2])
	}
	return res
}

func (c *gateConversionApi) DivUnchecked(i1, i2 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (c *gateConversionApi) Div(i1, i2 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (c *gateConversionApi) Inverse(i1 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (c *gateConversionApi) ToBinary(i1 frontend.Variable, n ...int) []frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (c *gateConversionApi) FromBinary(b ...frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (c *gateConversionApi) Xor(a, b frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (c *gateConversionApi) Or(a, b frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (c *gateConversionApi) And(a, b frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (c *gateConversionApi) Select(b frontend.Variable, i1, i2 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (c *gateConversionApi) Lookup2(b0, b1 frontend.Variable, i0, i1, i2, i3 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (c *gateConversionApi) IsZero(i1 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (c *gateConversionApi) Cmp(i1, i2 frontend.Variable) frontend.Variable {
	//TODO implement me
	panic("implement me")
}

func (c *gateConversionApi) AssertIsEqual(i1, i2 frontend.Variable) {
	//TODO implement me
	panic("implement me")
}

func (c *gateConversionApi) AssertIsDifferent(i1, i2 frontend.Variable) {
	//TODO implement me
	panic("implement me")
}

func (c *gateConversionApi) AssertIsBoolean(i1 frontend.Variable) {
	//TODO implement me
	panic("implement me")
}

func (c *gateConversionApi) AssertIsLessOrEqual(v frontend.Variable, bound frontend.Variable) {
	//TODO implement me
	panic("implement me")
}

func (c *gateConversionApi) Println(a ...frontend.Variable) {
	//TODO implement me
	panic("implement me")
}

func (c *gateConversionApi) Compiler() frontend.Compiler {
	//TODO implement me
	panic("implement me")
}

func (c *gateConversionApi) NewHint(f hint.Function, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {
	//TODO implement me
	panic("implement me")
}

func (c *gateConversionApi) ConstantValue(v frontend.Variable) (*big.Int, bool) {
	//TODO implement me
	panic("implement me")
}
