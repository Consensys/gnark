package smallfields_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/consensys/gnark-crypto/field/goldilocks"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/smallfields/tinyfield"
	"github.com/consensys/gnark/test"
)

type NativeCircuit struct {
	A frontend.Variable `gnark:",public"`
	B frontend.Variable `gnark:",secret"`
}

func (circuit *NativeCircuit) Define(api frontend.API) error {
	res := api.Mul(circuit.A, circuit.A)
	api.AssertIsEqual(res, circuit.B)
	return nil
}

var testCases = []struct {
	name            string
	modulus         *big.Int
	supportsCompile bool
}{
	{"goldilocks", goldilocks.Modulus(), false},
	{"tinyfield", tinyfield.Modulus(), false},
	{"babybear", babybear.Modulus(), true},
	{"koalabear", koalabear.Modulus(), true},
}

func TestNativeCircuitTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	for _, tc := range testCases {
		assert.Run(func(assert *test.Assert) {
			err := test.IsSolved(&NativeCircuit{}, &NativeCircuit{A: 2, B: 4}, tc.modulus)
			assert.NoError(err)
		}, tc.name)
	}
}

func TestNativeCircuitCompileAndSolve(t *testing.T) {
	assert := test.NewAssert(t)
	for _, tc := range testCases {
		if !tc.supportsCompile {
			continue
		}
		assert.Run(func(assert *test.Assert) {
			ccs, err := frontend.CompileU32(tc.modulus, r1cs.NewBuilder, &NativeCircuit{})
			assert.NoError(err)
			assignment := &NativeCircuit{A: 2, B: 4}
			wit, err := frontend.NewWitness(assignment, tc.modulus)
			assert.NoError(err)
			solution, err := ccs.Solve(wit)
			assert.NoError(err)
			_ = solution

		}, fmt.Sprintf("ccs=r1cs/field=%s", tc.name))
		assert.Run(func(assert *test.Assert) {
			ccs, err := frontend.CompileU32(tc.modulus, scs.NewBuilder, &NativeCircuit{})
			assert.NoError(err)
			assignment := &NativeCircuit{A: 2, B: 4}
			wit, err := frontend.NewWitness(assignment, tc.modulus)
			assert.NoError(err)
			solution, err := ccs.Solve(wit)
			assert.NoError(err)
			_ = solution
		}, fmt.Sprintf("ccs=scs/field=%s", tc.name))
	}
}
