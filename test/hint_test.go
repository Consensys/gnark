package test

import (
	"fmt"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

const id = solver.HintID(123454321)

func identityHint(_ *big.Int, in, out []*big.Int) error {
	if len(in) != len(out) {
		return fmt.Errorf("len(in) = %d ≠ %d = len(out)", len(in), len(out))
	}
	for i := range in {
		out[i].Set(in[i])
	}
	return nil
}

type customNamedHintCircuit struct {
	X []frontend.Variable
}

func (c *customNamedHintCircuit) Define(api frontend.API) error {
	y, err := api.Compiler().NewHintForId(id, len(c.X), c.X...)

	if err != nil {
		return err
	}
	for i := range y {
		api.AssertIsEqual(c.X[i], y[i])
	}

	return nil
}

var assignment, circuit customNamedHintCircuit

func init() {
	solver.RegisterNamedHint(identityHint, id)
	assignment = customNamedHintCircuit{X: []frontend.Variable{1, 2, 3, 4, 5}}
	circuit = customNamedHintCircuit{X: make([]frontend.Variable, len(assignment.X))}
}

func TestHintWithCustomNamePlonk(t *testing.T) {
	plonkTest(t, &circuit, &assignment)
}

func TestHintWithCustomNameGroth16(t *testing.T) {
	groth16Test(t, &circuit, &assignment)
}

func TestHintWithCustomNameEngine(t *testing.T) {
	NewAssert(t).SolvingSucceeded(&circuit, &assignment)
}

func groth16Test(t *testing.T, circuit, assignment frontend.Circuit) {
	run := func(mod *big.Int) func(*testing.T) {
		return func(t *testing.T) {
			cs, err := frontend.Compile(mod, r1cs.NewBuilder, circuit)
			assert.NoError(t, err)
			var (
				pk    groth16.ProvingKey
				vk    groth16.VerifyingKey
				w, pw witness.Witness
				proof groth16.Proof
			)
			pk, vk, err = groth16.Setup(cs)
			assert.NoError(t, err)

			w, err = frontend.NewWitness(assignment, mod)
			assert.NoError(t, err)

			proof, err = groth16.Prove(cs, pk, w)
			assert.NoError(t, err)

			pw, err = w.Public()
			assert.NoError(t, err)

			assert.NoError(t, groth16.Verify(proof, vk, pw))
		}
	}

	for _, id := range fr {
		t.Run(id.String(), run(id.ScalarField()))
	}
}
