package multicommit_test

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/multicommit"
)

// MultipleCommitmentCircuit is an example circuit showing usage of multiple
// independent commitments in-circuit.
type MultipleCommitmentsCircuit struct {
	Secrets [4]frontend.Variable
}

func (c *MultipleCommitmentsCircuit) Define(api frontend.API) error {
	// first callback receives first unique commitment derived from the root commitment
	multicommit.WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
		// compute (X-s[0]) * (X-s[1]) for a random X
		res := api.Mul(api.Sub(commitment, c.Secrets[0]), api.Sub(commitment, c.Secrets[1]))
		api.AssertIsDifferent(res, 0)
		return nil
	}, c.Secrets[:2]...)

	// second callback receives second unique commitment derived from the root commitment
	multicommit.WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
		// compute (X-s[2]) * (X-s[3]) for a random X
		res := api.Mul(api.Sub(commitment, c.Secrets[2]), api.Sub(commitment, c.Secrets[3]))
		api.AssertIsDifferent(res, 0)
		return nil
	}, c.Secrets[2:4]...)

	// we do not have to pass any variables in if other calls to [WithCommitment] have
	multicommit.WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
		// compute (X-s[0]) for a random X
		api.AssertIsDifferent(api.Sub(commitment, c.Secrets[0]), 0)
		return nil
	})

	// we can share variables between the callbacks
	var shared, stored frontend.Variable
	multicommit.WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
		shared = api.Add(c.Secrets[0], commitment)
		stored = commitment
		return nil
	})
	multicommit.WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
		api.AssertIsEqual(api.Sub(shared, stored), c.Secrets[0])
		return nil
	})
	return nil
}

// Full written on how to use multiple commitments in a circuit.
func ExampleWithCommitment() {
	circuit := MultipleCommitmentsCircuit{}
	assignment := MultipleCommitmentsCircuit{Secrets: [4]frontend.Variable{1, 2, 3, 4}}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	secretWitness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(ccs, pk, secretWitness)
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
	fmt.Println("done")
	// Output: done
}
