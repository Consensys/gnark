package gkr_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	crypto_gkr "github.com/consensys/gnark-crypto/ecc/bn254/fr/gkr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/gkr"
	"github.com/consensys/gnark/test"
)

type PolyEvalGateNative struct {
	VarPowers []fr.Element
}

func (g PolyEvalGateNative) Evaluate(in ...fr.Element) fr.Element {
	if len(in) != len(g.VarPowers)+1 {
		panic("mismatching powers")
	}
	tmp := new(fr.Element)
	res := new(fr.Element)
	res = res.Set(&in[0])
	for i := 1; i < len(in); i++ {
		tmp.Mul(&in[i], (&g.VarPowers[i-1]))
		res = res.Add(res, tmp)
	}
	return *res
}

func (g PolyEvalGateNative) Degree() int {
	return len(g.VarPowers) + 1
}

type PolyEvalGate struct {
	VarPowers []frontend.Variable
}

func (g PolyEvalGate) Evaluate(api frontend.API, in ...frontend.Variable) frontend.Variable {
	if len(in) != len(g.VarPowers)+1 {
		panic("mismatching powers")
	}
	res := in[0]
	for i := 1; i < len(in); i++ {
		res = api.Add(res, api.Mul(in[i], g.VarPowers[i-1]))
	}
	return res
}

func (g PolyEvalGate) Degree() int {
	return len(g.VarPowers) + 1
}

type PolyEvalGateCircuitGKR struct {
	T   frontend.Variable
	X   []frontend.Variable
	Y   []frontend.Variable
	Z   []frontend.Variable
	W   []frontend.Variable
	Res []frontend.Variable
}

func (c *PolyEvalGateCircuitGKR) Define(api frontend.API) error {
	f := gkr.NewApi()
	t := make([]frontend.Variable, 3)
	t[0] = c.T
	t[1] = api.Mul(c.T, c.T)
	t[2] = api.Mul(t[1], c.T)
	gkr.Gates["polyeval"] = PolyEvalGate{
		VarPowers: t,
	}
	crypto_gkr.Gates["polyeval"] = PolyEvalGateNative{VarPowers: []fr.Element{
		fr.NewElement(2),
		fr.NewElement(4),
		fr.NewElement(8),
	}}
	x, err := f.Import(c.X)
	if err != nil {
		return err
	}
	y, err := f.Import(c.Y)
	if err != nil {
		return err
	}
	z, err := f.Import(c.Z)
	if err != nil {
		return err
	}
	w, err := f.Import(c.Z)
	if err != nil {
		return err
	}
	res := f.NamedGate("polyeval", x, y, z, w)
	solution, err := f.Solve(api)
	if err != nil {
		return err
	}
	nres := solution.Export(res)
	if len(nres) != len(c.Res) {
		return fmt.Errorf("mismatch")
	}
	// for i := range nres {
	// 	api.AssertIsEqual(nres[i], c.Res[i])
	// }
	return solution.Verify("mimc")
}

type PolyEvalGateCircuit struct {
	T   frontend.Variable
	X   []frontend.Variable
	Y   []frontend.Variable
	Z   []frontend.Variable
	W   []frontend.Variable
	Res []frontend.Variable
}

func (c *PolyEvalGateCircuit) Define(api frontend.API) error {
	t := make([]frontend.Variable, 3)
	t[0] = c.T
	t[1] = api.Mul(c.T, c.T)
	t[2] = api.Mul(t[1], c.T)
	for i := range c.X {
		res := c.X[i]
		res = api.Add(res, api.Mul(t[0], c.Y[i]))
		res = api.Add(res, api.Mul(t[1], c.Z[i]))
		res = api.Add(res, api.Mul(t[2], c.W[i]))
		_ = res
		// api.AssertIsEqual(res, c.Res[i])
	}
	return nil
}

func TestPolyEvalGate(t *testing.T) {
	tau := big.NewInt(2)
	nbInstances := 1 << 18
	assert := test.NewAssert(t)
	circuitGKR := PolyEvalGateCircuitGKR{
		T:   tau,
		X:   make([]frontend.Variable, nbInstances),
		Y:   make([]frontend.Variable, nbInstances),
		Z:   make([]frontend.Variable, nbInstances),
		W:   make([]frontend.Variable, nbInstances),
		Res: make([]frontend.Variable, nbInstances),
	}
	circuitNative := PolyEvalGateCircuit{
		T:   tau,
		X:   make([]frontend.Variable, nbInstances),
		Y:   make([]frontend.Variable, nbInstances),
		Z:   make([]frontend.Variable, nbInstances),
		W:   make([]frontend.Variable, nbInstances),
		Res: make([]frontend.Variable, nbInstances),
	}
	ccs1, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuitGKR)
	assert.NoError(err)
	ccs2, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuitGKR)
	assert.NoError(err)
	ccs3, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuitNative)
	assert.NoError(err)
	ccs4, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuitNative)
	assert.NoError(err)

	_ = ccs1
	_ = ccs2
	_ = ccs3
	_ = ccs4
}

type HighDegreeGate struct {
}

func (g HighDegreeGate) Evaluate(api frontend.API, in ...frontend.Variable) frontend.Variable {
	if len(in) != 2 {
		panic("aaa")
	}
	res := api.Add(in[0], in[1])
	res = api.Mul(res, res, res)
	res = api.Mul(res, res, res)
	res = api.Mul(res, res, res)
	return res
}

func (g HighDegreeGate) Degree() int {
	return 27
}

type HighDegreeGateCircuitGKR struct {
	X []frontend.Variable
	Y []frontend.Variable
}

func (c *HighDegreeGateCircuitGKR) Define(api frontend.API) error {
	f := gkr.NewApi()
	gkr.Gates["highdegree"] = HighDegreeGate{}
	x, err := f.Import(c.X)
	if err != nil {
		return err
	}
	y, err := f.Import(c.Y)
	if err != nil {
		return err
	}
	res := f.NamedGate("highdegree", x, y)
	res = f.NamedGate("highdegree", res, y)
	res = f.NamedGate("highdegree", res, y)
	res = f.NamedGate("highdegree", res, y)
	solution, err := f.Solve(api)
	if err != nil {
		return err
	}
	nres := solution.Export(res)
	if len(nres) != len(c.X) {
		return fmt.Errorf("mismatch")
	}
	return solution.Verify("mimc")
}

func TestHighDegreeCircuit(t *testing.T) {
	// tau := big.NewInt(2)
	nbInstances := 1 << 16
	assert := test.NewAssert(t)
	circuitGKR := HighDegreeGateCircuitGKR{
		X: make([]frontend.Variable, nbInstances),
		Y: make([]frontend.Variable, nbInstances),
	}
	circuitNative := HighDegreeGateCircuit{
		X: make([]frontend.Variable, nbInstances),
		Y: make([]frontend.Variable, nbInstances),
	}
	ccs1, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuitGKR)
	assert.NoError(err)
	ccs2, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuitGKR)
	assert.NoError(err)
	ccs3, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuitNative)
	assert.NoError(err)
	ccs4, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuitNative)
	assert.NoError(err)

	_ = ccs1
	_ = ccs2
	_ = ccs3
	_ = ccs4
}

type HighDegreeGateCircuit struct {
	X []frontend.Variable
	Y []frontend.Variable
}

func (c *HighDegreeGateCircuit) Define(api frontend.API) error {
	res := make([]frontend.Variable, len(c.X))
	for i := range c.X {
		mul := api.Add(c.X[i], c.Y[i])
		res[i] = api.Mul(mul, mul, mul)
		res[i] = api.Mul(res[i], res[i], res[i])
		res[i] = api.Mul(res[i], res[i], res[i])
	}
	for i := range res {
		mul := api.Add(c.X[i], c.Y[i])
		res[i] = api.Mul(mul, mul, mul)
		res[i] = api.Mul(res[i], res[i], res[i])
		res[i] = api.Mul(res[i], res[i], res[i])
	}
	for i := range res {
		mul := api.Add(res[i], c.Y[i])
		res[i] = api.Mul(mul, mul, mul)
		res[i] = api.Mul(res[i], res[i], res[i])
		res[i] = api.Mul(res[i], res[i], res[i])
	}
	for i := range res {
		mul := api.Add(res[i], c.Y[i])
		res[i] = api.Mul(mul, mul, mul)
		res[i] = api.Mul(res[i], res[i], res[i])
		res[i] = api.Mul(res[i], res[i], res[i])
	}
	return nil
}
