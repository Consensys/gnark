package solidity_test

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/sha3"
)

type noCommitCircuit struct {
	A, B, Out frontend.Variable `gnark:",public"`
}

func (c *noCommitCircuit) Define(api frontend.API) error {
	res := api.Mul(c.A, c.B)
	api.AssertIsEqual(res, c.Out)
	return nil
}

type commitCircuit struct {
	A, B, Out frontend.Variable `gnark:",public"`
}

func (c *commitCircuit) Define(api frontend.API) error {
	res := api.Mul(c.A, c.B)
	api.AssertIsEqual(res, c.Out)
	cmter, ok := api.(frontend.Committer)
	if !ok {
		return fmt.Errorf("api does not support commitment")
	}
	cmt1, err := cmter.Commit(res)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(cmt1, res)
	return nil
}

type twoCommitCircuit struct {
	A, B, Out frontend.Variable `gnark:",public"`
}

func (c *twoCommitCircuit) Define(api frontend.API) error {
	res := api.Mul(c.A, c.B)
	api.AssertIsEqual(res, c.Out)
	cmter, ok := api.(frontend.Committer)
	if !ok {
		return fmt.Errorf("api does not support commitment")
	}
	cmt1, err := cmter.Commit(res)
	if err != nil {
		return err
	}
	cmt2, err := cmter.Commit(cmt1)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(cmt1, cmt2)
	return nil
}

func TestNoCommitment(t *testing.T) {
	// should succeed both with G16 and PLONK:
	assert := test.NewAssert(t)
	circuit := &noCommitCircuit{}
	assignment := &noCommitCircuit{A: 2, B: 3, Out: 6}
	defaultOpts := []test.TestingOption{
		test.WithCurves(ecc.BN254),
		test.WithValidAssignment(assignment),
	}
	checkCircuit := func(assert *test.Assert, bid backend.ID) {
		opts := append(defaultOpts,
			test.WithBackends(bid),
		)

		assert.CheckCircuit(circuit, opts...)
	}
	assert.Run(func(assert *test.Assert) {
		checkCircuit(assert, backend.GROTH16)
	}, "Groth16")
	assert.Run(func(assert *test.Assert) {
		checkCircuit(assert, backend.PLONK)
	}, "PLONK")
}

func TestSingleCommitment(t *testing.T) {
	// should succeed both with G16 and PLONK:
	// - But for G16 only if the hash-to-field is set to a supported one.
	// - but for PLONK only if the hash-to-field is the default one. If not, then it should fail.
	assert := test.NewAssert(t)
	circuit := &commitCircuit{}
	assignment := &commitCircuit{A: 2, B: 3, Out: 6}
	defaultOpts := []test.TestingOption{
		test.WithCurves(ecc.BN254),
		test.WithValidAssignment(assignment),
	}
	checkCircuit := func(assert *test.Assert, bid backend.ID, newHash func() hash.Hash) {
		opts := append(defaultOpts,
			test.WithBackends(bid),
			test.WithProverOpts(
				backend.WithProverHashToFieldFunction(newHash()),
			),
			test.WithVerifierOpts(
				backend.WithVerifierHashToFieldFunction(newHash()),
			),
			test.WithSolidityExportOptions(solidity.WithHashToFieldFunction(newHash())),
		)

		assert.CheckCircuit(circuit, opts...)
	}
	// G16 success with explicitly set options
	assert.Run(func(assert *test.Assert) {
		checkCircuit(assert, backend.GROTH16, sha256.New)
	}, "groth16", "sha256")
	assert.Run(func(assert *test.Assert) {
		checkCircuit(assert, backend.GROTH16, sha3.NewLegacyKeccak256)
	}, "groth16", "keccak256")
	// G16 success with using TargetSolidityVerifier
	assert.Run(func(assert *test.Assert) {
		opts := append(defaultOpts,
			test.WithBackends(backend.GROTH16),
			test.WithProverOpts(
				solidity.WithProverTargetSolidityVerifier(backend.GROTH16),
			),
			test.WithVerifierOpts(
				solidity.WithVerifierTargetSolidityVerifier(backend.GROTH16),
			),
		)
		assert.CheckCircuit(circuit, opts...)
	}, "groth16", "targetSolidityVerifier")
	// G16 success without any options because we set default options already in
	// assert.CheckCircuit if they are not set.
	assert.Run(func(assert *test.Assert) {
		opts := append(defaultOpts,
			test.WithBackends(backend.GROTH16),
		)
		assert.CheckCircuit(circuit, opts...)
	}, "groth16", "no-options")

	// PLONK success with default options
	assert.Run(func(assert *test.Assert) {
		opts := append(defaultOpts,
			test.WithBackends(backend.PLONK),
		)
		assert.CheckCircuit(circuit, opts...)
	}, "plonk", "default")
	// PLONK success with using TargetSolidityVerifier
	assert.Run(func(assert *test.Assert) {
		opts := append(defaultOpts,
			test.WithBackends(backend.PLONK),
			test.WithProverOpts(
				solidity.WithProverTargetSolidityVerifier(backend.PLONK),
			),
			test.WithVerifierOpts(
				solidity.WithVerifierTargetSolidityVerifier(backend.PLONK),
			),
		)
		assert.CheckCircuit(circuit, opts...)
	}, "plonk", "targetSolidityVerifier")
}

func TestTwoCommitments(t *testing.T) {
	// should succeed with PLONK only.
	// - but for PLONK only if the hash-to-field is the default one. If not, then it should fail.
	assert := test.NewAssert(t)
	circuit := &twoCommitCircuit{}
	assignment := &twoCommitCircuit{A: 2, B: 3, Out: 6}
	assert.CheckCircuit(circuit, test.WithCurves(ecc.BN254), test.WithValidAssignment(assignment), test.WithBackends(backend.PLONK))
}
