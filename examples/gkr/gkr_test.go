package gkr_test

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bn254MiMC "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
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

type Arithmetization[T any] interface {
	Add(T, T, ...T) T
	Mul(T, T, ...T) T
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

type APIArithmetization struct {
	api frontend.API
}

func (aa APIArithmetization) Add(in1, in2 frontend.Variable, other ...frontend.Variable) frontend.Variable {
	return aa.api.Add(in1, in2, other...)
}

func (aa APIArithmetization) Mul(in1, in2 frontend.Variable, other ...frontend.Variable) frontend.Variable {
	return aa.api.Mul(in1, in2, other...)
}

type ArithmFn[A Arithmetization[V], V any] func(a A, in1, in2 V) V

func SimpleMul[A Arithmetization[V], V any](a A, in1, in2 V) V {
	return a.Mul(in1, in2)
}

func WithGKR(api frontend.API, fn ArithmFn[*gkr.API, constraint.GkrVariable], inputs1 []frontend.Variable, inputs2 []frontend.Variable) (res []frontend.Variable, commit func() error, err error) {
	f := gkr.NewApi()
	in1, err := f.Import(inputs1)
	if err != nil {
		return nil, nil, fmt.Errorf("import %w", err)
	}
	in2, err := f.Import(inputs2)
	if err != nil {
		return nil, nil, fmt.Errorf("import2: %w", err)
	}
	gkrres := fn(f, in1, in2)
	solution, err := f.Solve(api)
	if err != nil {
		return nil, nil, fmt.Errorf("solution: %w", err)
	}
	nres := solution.Export(gkrres)
	return nres, func() error {
		return solution.Verify("mimc")
	}, nil
}

type TestCircuit struct {
	Inputs1 []frontend.Variable
	Inputs2 []frontend.Variable
	Outputs []frontend.Variable
	fn      ArithmFn[*gkr.API, constraint.GkrVariable]
}

func (c *TestCircuit) Define(api frontend.API) error {
	res, verify, err := WithGKR(api, c.fn, c.Inputs1, c.Inputs2)
	if err != nil {
		return err
	}
	for i := range res {
		api.AssertIsEqual(res[i], c.Outputs[i])
	}
	return verify()
}

func TestGKR(t *testing.T) {
	nbVars := 1 << 16
	assert := test.NewAssert(t)
	bound := ecc.BN254.ScalarField()
	circuit := TestCircuit{
		Inputs1: make([]frontend.Variable, nbVars),
		Inputs2: make([]frontend.Variable, nbVars),
		Outputs: make([]frontend.Variable, nbVars),
		fn:      SimpleMul[*gkr.API, constraint.GkrVariable],
	}
	witness := TestCircuit{
		Inputs1: make([]frontend.Variable, nbVars),
		Inputs2: make([]frontend.Variable, nbVars),
		Outputs: make([]frontend.Variable, nbVars),
		fn:      SimpleMul[*gkr.API, constraint.GkrVariable],
	}
	for i := 0; i < nbVars; i++ {
		input1, err := rand.Int(rand.Reader, bound)
		assert.NoError(err)
		input2, err := rand.Int(rand.Reader, bound)
		assert.NoError(err)
		witness.Inputs1[i] = input1
		witness.Inputs2[i] = input2
		witness.Outputs[i] = SimpleMul(NativeArithmetization{bound}, input1, input2)
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(err)
	fullWitness, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	assert.NoError(err)
	publicWitness, err := fullWitness.Public()
	assert.NoError(err)
	pk, vk, err := groth16.Setup(ccs)
	assert.NoError(err)
	proof, err := groth16.Prove(ccs, pk, fullWitness)
	assert.NoError(err)
	err = groth16.Verify(proof, vk, publicWitness)
	assert.NoError(err)
}
