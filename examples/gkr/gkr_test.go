package gkr_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bn254MiMC "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/constraint"
	bn254r1cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/gkr"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

func init() {
	bn254r1cs.HashBuilderRegistry["mimc"] = bn254MiMC.NewMiMC
	hash.BuilderRegistry["mimc"] = func(api frontend.API) (hash.FieldHasher, error) {
		m, err := mimc.NewMiMC(api)
		return &m, err
	}
}

// variable types we are interested in are:
//   * frontend.Variable
//   * constraint.GkrVariable
//   * *big.Int for testing
//   * long term emulated.Element

type Arithmetization[T any] interface {
	Add(T, T, ...T) T
	Mul(T, T, ...T) T
	// Sub TODO
	// Neg TODO
	// Div TODO
	// Inverse TODO
}

type NativeArithmetization struct {
	mod *big.Int
}

func (na NativeArithmetization) Add(in1, in2 *big.Int, other ...*big.Int) *big.Int {
	res := new(big.Int)
	res.Add(in1, in2)
	for i := range other {
		res.Mod(res, na.mod)
		res.Add(res, other[i])
	}
	return res.Mod(res, na.mod)
}

func (na NativeArithmetization) Mul(in1, in2 *big.Int, other ...*big.Int) *big.Int {
	res := new(big.Int)
	res.Mul(in1, in2)
	for i := range other {
		res.Mod(res, na.mod)
		res.Mul(res, other[i])
	}
	return res.Mod(res, na.mod)
}

type ArithmFn[API Arithmetization[VAR], VAR any] func(api API, in1, in2 VAR, other ...VAR) VAR

func SimpleMul[API Arithmetization[VAR], VAR any](api API, in1, in2 VAR, other ...VAR) VAR {
	return api.Mul(in1, in2, other...)
}

func DeepMul[API Arithmetization[VAR], VAR any](api API, in1, in2 VAR, other ...VAR) VAR {
	b := api.Mul(in1, in2)
	c := api.Mul(b, b)
	d := api.Mul(c, c)
	e := api.Mul(d, d)
	f := api.Add(e, e)
	return f
}

func PolynomialEval[API Arithmetization[VAR], VAR any](api API, in1, in2 VAR, other ...VAR) VAR {
	// inputs are cm1, cm2, cm3, cm4, cm5, cm6, cm7, a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, c4, c5, c6, c7
	cm1 := in1
	cm2 := in2
	cm3 := other[0]
	cm4 := other[1]
	cm5 := other[2]
	cm6 := other[3]
	cm7 := other[4]
	a0 := other[5]
	a1 := other[6]
	a2 := other[7]
	a3 := other[8]
	b0 := other[9]
	b1 := other[10]
	b2 := other[11]
	b3 := other[12]
	c0 := other[13]
	c1 := other[14]
	c2 := other[15]
	c3 := other[16]
	c4 := other[17]
	c5 := other[18]
	c6 := other[19]
	c7 := other[20]
	a := api.Add(a0, api.Mul(a1, cm1))
	a = api.Add(a, api.Mul(a2, cm2))
	a = api.Add(a, api.Mul(a3, cm3))
	b := api.Add(b0, api.Mul(b1, cm1))
	b = api.Add(b, api.Mul(b2, cm2))
	b = api.Add(b, api.Mul(b3, cm3))
	c := api.Add(c0, api.Mul(c1, cm1))
	c = api.Add(c, api.Mul(c2, cm2))
	c = api.Add(c, api.Mul(c3, cm3))
	c = api.Add(c, api.Mul(c4, cm4))
	c = api.Add(c, api.Mul(c5, cm5))
	c = api.Add(c, api.Mul(c6, cm6))
	c = api.Add(c, api.Mul(c7, cm7))
	k := api.Add(a, b)
	k = api.Add(k, c)
	return k
}

func WithGKR(api frontend.API, fn ArithmFn[*gkr.API, constraint.GkrVariable], inputs1 []frontend.Variable, inputs2 []frontend.Variable, other ...[]frontend.Variable) (res []frontend.Variable, commit func() error, err error) {
	f := gkr.NewApi()
	in1, err := f.Import(inputs1)
	if err != nil {
		return nil, nil, fmt.Errorf("import %w", err)
	}
	in2, err := f.Import(inputs2)
	if err != nil {
		return nil, nil, fmt.Errorf("import2: %w", err)
	}
	gkrOther := make([]constraint.GkrVariable, len(other))
	for i := range other {
		gkrOther[i], err = f.Import(other[i])
		if err != nil {
			return nil, nil, fmt.Errorf("import other: %w", err)
		}
	}
	gkrres := fn(f, in1, in2, gkrOther...)
	solution, err := f.Solve(api)
	if err != nil {
		return nil, nil, fmt.Errorf("solution: %w", err)
	}
	nres := solution.Export(gkrres)
	return nres, func() error {
		return solution.Verify("mimc")
	}, nil
}

func WithAPI(api frontend.API, fn ArithmFn[frontend.API, frontend.Variable], inputs1 []frontend.Variable, inputs2 []frontend.Variable, other ...[]frontend.Variable) (res []frontend.Variable, err error) {
	if len(inputs1) != len(inputs2) {
		return nil, fmt.Errorf("mismatching nb of inputs")
	}
	nbInputs := len(inputs1)
	for i := range other {
		if len(other[i]) != nbInputs {
			return nil, fmt.Errorf("mismatching nb of inputs")
		}
	}
	outputs := make([]frontend.Variable, nbInputs)
	for i := 0; i < nbInputs; i++ {
		otherInputs := make([]frontend.Variable, len(other))
		for j := range otherInputs {
			otherInputs[j] = other[j][i]
		}
		outputs[i] = fn(api, inputs1[i], inputs2[i], otherInputs...)
	}
	return outputs, nil
}

type TestCircuit struct {
	withGKR bool
	Inputs1 []frontend.Variable
	Inputs2 []frontend.Variable
	Other   [][]frontend.Variable
	Outputs []frontend.Variable
}

func (c *TestCircuit) Define(api frontend.API) error {
	var res []frontend.Variable
	var verify func() error
	var err error
	if c.withGKR {
		res, verify, err = WithGKR(api, PolynomialEval[*gkr.API, constraint.GkrVariable], c.Inputs1, c.Inputs2, c.Other...)
		if err != nil {
			return err
		}
	} else {
		res, err = WithAPI(api, PolynomialEval[frontend.API, frontend.Variable], c.Inputs1, c.Inputs2, c.Other...)
		if err != nil {
			return err
		}
		verify = func() error { return nil }
	}
	for i := range res {
		api.AssertIsEqual(res[i], c.Outputs[i])
	}
	return verify()
}

func TestGKR(t *testing.T) {
	nbInstances := 1 << 20
	assert := test.NewAssert(t)
	circuitNative := TestCircuit{
		withGKR: false,
		Inputs1: make([]frontend.Variable, nbInstances),
		Inputs2: make([]frontend.Variable, nbInstances),
		Other:   make([][]frontend.Variable, 21),
		Outputs: make([]frontend.Variable, nbInstances),
	}
	circuitGKR := TestCircuit{
		withGKR: true,
		Inputs1: make([]frontend.Variable, nbInstances),
		Inputs2: make([]frontend.Variable, nbInstances),
		Other:   make([][]frontend.Variable, 21),
		Outputs: make([]frontend.Variable, nbInstances),
	}
	for i := range circuitNative.Other {
		circuitNative.Other[i] = make([]frontend.Variable, nbInstances)
		circuitGKR.Other[i] = make([]frontend.Variable, nbInstances)
	}
	ccs1, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuitNative)
	assert.NoError(err)
	ccs2, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuitNative)
	assert.NoError(err)
	ccs3, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuitGKR)
	assert.NoError(err)
	ccs4, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuitGKR)
	assert.NoError(err)
	// bound := ecc.BN254.ScalarField()
	// witness := TestCircuit{
	// 	withGKR: withGKR,
	// 	Inputs1: make([]frontend.Variable, nbInstances),
	// 	Inputs2: make([]frontend.Variable, nbInstances),
	// 	Outputs: make([]frontend.Variable, nbInstances),
	// }
	// for i := 0; i < nbInstances; i++ {
	// 	input1, err := rand.Int(rand.Reader, bound)
	// 	assert.NoError(err)
	// 	input2, err := rand.Int(rand.Reader, bound)
	// 	assert.NoError(err)
	// 	witness.Inputs1[i] = input1
	// 	witness.Inputs2[i] = input2
	// 	witness.Outputs[i] = DeepMul(NativeArithmetization{bound}, input1, input2)
	// }

	// fullWitness, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	// assert.NoError(err)
	// publicWitness, err := fullWitness.Public()
	// assert.NoError(err)
	// pk, vk, err := groth16.Setup(ccs)
	// assert.NoError(err)
	// proof, err := groth16.Prove(ccs, pk, fullWitness)
	// assert.NoError(err)
	// err = groth16.Verify(proof, vk, publicWitness)
	// assert.NoError(err)
	_ = ccs1
	_ = ccs2
	_ = ccs3
	_ = ccs4
}
