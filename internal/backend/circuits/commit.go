package circuits

import (
	"crypto/sha256"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
)

type commitCircuit struct {
	Public frontend.Variable `gnark:",public"`
	X      frontend.Variable
}

func (circuit *commitCircuit) Define(api frontend.API) error {
	api.AssertIsDifferent(circuit.Public, 0)
	commitment, err := api.(frontend.Committer).Commit(circuit.X, circuit.Public, 5)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commitment, 0)
	a := api.Mul(circuit.X, circuit.X)
	for i := 0; i < 10; i++ {
		a = api.Mul(a, circuit.X)
	}
	c := api.Add(a, circuit.X)
	api.AssertIsDifferent(c, a)
	return nil
}

type noCommitCircuit struct {
	Public frontend.Variable `gnark:",public"`
	X      frontend.Variable
}

func (circuit *noCommitCircuit) Define(api frontend.API) error {
	api.AssertIsDifferent(circuit.Public, 0)
	a := api.Mul(circuit.X, circuit.X)
	for i := 0; i < 10; i++ {
		a = api.Mul(a, circuit.X)
	}
	c := api.Add(a, circuit.X)
	api.AssertIsDifferent(c, a)
	return nil
}

func init() {
	// need to have separate test cases as the hash-to-field for PLONK and Groth16 verifiers are different
	addEntry(
		"commit_Groth16",
		&commitCircuit{}, &commitCircuit{Public: 16, X: 3}, &commitCircuit{Public: 0, X: 4},
		[]ecc.ID{bn254.ID}, WithBackends(backend.GROTH16), WithProverOpts(backend.WithProverHashToFieldFunction(sha256.New())), WithVerifierOpts(backend.WithVerifierHashToFieldFunction(sha256.New())))
	addEntry(
		"commit_Plonk",
		&commitCircuit{}, &commitCircuit{Public: 16, X: 3}, &commitCircuit{Public: 0, X: 4},
		[]ecc.ID{bn254.ID}, WithBackends(backend.PLONK))
	addEntry(
		"no_commit_Groth16",
		&noCommitCircuit{}, &noCommitCircuit{Public: 16, X: 3}, &noCommitCircuit{Public: 0, X: 4},
		[]ecc.ID{bn254.ID}, WithBackends(backend.GROTH16), WithProverOpts(backend.WithProverHashToFieldFunction(sha256.New())), WithVerifierOpts(backend.WithVerifierHashToFieldFunction(sha256.New())))
	addEntry(
		"no_commit_Plonk",
		&noCommitCircuit{}, &noCommitCircuit{Public: 16, X: 3}, &noCommitCircuit{Public: 0, X: 4},
		[]ecc.ID{bn254.ID}, WithBackends(backend.PLONK))
}
