package gkr_test

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bn254MiMC "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/constraint"
	bn254r1cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
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
	f := api.Mul(e, e)
	return f

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
	Outputs []frontend.Variable
}

func (c *TestCircuit) Define(api frontend.API) error {
	var res []frontend.Variable
	var verify func() error
	var err error
	if c.withGKR {
		res, verify, err = WithGKR(api, DeepMul[*gkr.API, constraint.GkrVariable], c.Inputs1, c.Inputs2)
		if err != nil {
			return err
		}
	} else {
		res, err = WithAPI(api, DeepMul[frontend.API, frontend.Variable], c.Inputs1, c.Inputs2)
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
	withGKR := false
	assert := test.NewAssert(t)
	bound := ecc.BN254.ScalarField()
	circuit := TestCircuit{
		withGKR: withGKR,
		Inputs1: make([]frontend.Variable, nbInstances),
		Inputs2: make([]frontend.Variable, nbInstances),
		Outputs: make([]frontend.Variable, nbInstances),
	}
	witness := TestCircuit{
		withGKR: withGKR,
		Inputs1: make([]frontend.Variable, nbInstances),
		Inputs2: make([]frontend.Variable, nbInstances),
		Outputs: make([]frontend.Variable, nbInstances),
	}
	for i := 0; i < nbInstances; i++ {
		input1, err := rand.Int(rand.Reader, bound)
		assert.NoError(err)
		input2, err := rand.Int(rand.Reader, bound)
		assert.NoError(err)
		witness.Inputs1[i] = input1
		witness.Inputs2[i] = input2
		witness.Outputs[i] = DeepMul(NativeArithmetization{bound}, input1, input2)
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(err)
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
	_, _ = ccs, witness
}
