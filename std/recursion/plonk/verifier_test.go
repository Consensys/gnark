package plonk

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion"
	"github.com/consensys/gnark/test"
)

//-----------------------------------------------------------------
// Without api.Commit

type InnerCircuitNativeWoCommit struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *InnerCircuitNativeWoCommit) Define(api frontend.API) error {
	res := api.Mul(c.P, c.Q)
	api.AssertIsEqual(res, c.N)
	return nil
}

func getInnerWoCommit(assert *test.Assert, field, outer *big.Int) (constraint.ConstraintSystem, plonk.VerifyingKey, witness.Witness, plonk.Proof) {
	innerCcs, err := frontend.Compile(field, scs.NewBuilder, &InnerCircuitNativeWoCommit{})
	assert.NoError(err)
	srs, err := test.NewKZGSRS(innerCcs)
	assert.NoError(err)
	innerPK, innerVK, err := plonk.Setup(innerCcs, srs)
	assert.NoError(err)

	// inner proof
	innerAssignment := &InnerCircuitNativeWoCommit{
		P: 3,
		Q: 5,
		N: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	assert.NoError(err)
	fsProverHasher, err := recursion.NewShort(outer, field)
	assert.NoError(err)
	kzgProverHasher, err := recursion.NewShort(outer, field)
	assert.NoError(err)
	innerProof, err := plonk.Prove(innerCcs, innerPK, innerWitness,
		backend.WithProverChallengeHashFunction(fsProverHasher),
		backend.WithProverKZGFoldingHashFunction(kzgProverHasher),
	)
	assert.NoError(err)
	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)
	fsVerifierHasher, err := recursion.NewShort(outer, field)
	assert.NoError(err)
	kzgVerifierHash, err := recursion.NewShort(outer, field)
	assert.NoError(err)
	err = plonk.Verify(innerProof, innerVK, innerPubWitness,
		backend.WithVerifierChallengeHashFunction(fsVerifierHasher),
		backend.WithVerifierKZGFoldingHashFunction(kzgVerifierHash),
	)
	assert.NoError(err)
	return innerCcs, innerVK, innerPubWitness, innerProof
}

type OuterCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        Proof[FR, G1El, G2El]
	VerifyingKey VerifyingKey[FR, G1El, G2El]
	InnerWitness Witness[FR]
}

func (c *OuterCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	curve, err := algebra.GetCurve[FR, G1El](api)
	if err != nil {
		return fmt.Errorf("new curve: %w", err)
	}
	pairing, err := algebra.GetPairing[G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("get pairing: %w", err)
	}
	verifier, err := NewVerifier(api, curve, pairing)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	err = verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
	return err
}

func TestBLS12InBW6WoCommit(t *testing.T) {

	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInnerWoCommit(assert, ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField())

	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
		Proof:        PlaceholderProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof),
		VerifyingKey: PlaceholderVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerVK),
	}
	outerAssignment := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BW6_761.ScalarField())
	assert.NoError(err)
	// assert.CheckCircuit(outerCircuit, test.WithValidAssignment(outerAssignment), test.WithCurves(ecc.BW6_761),
	// 	test.NoFuzzing(), test.NoSerializationChecks(), test.NoSolidityChecks())
}

//-----------------------------------------------------------------
// With api.Commit

type InnerCircuitCommit struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *InnerCircuitCommit) Define(api frontend.API) error {

	x := api.Mul(c.P, c.P)
	y := api.Mul(c.Q, c.Q)
	z := api.Add(x, y)

	committer, ok := api.(frontend.Committer)
	if !ok {
		panic("builder does not implement Commit")
	}
	u, err := committer.Commit(x, z)
	if err != nil {
		return err
	}
	// v, err := committer.Commit(c.N)
	// if err != nil {
	// 	return err
	// }

	// api.AssertIsDifferent(v, z)
	api.AssertIsDifferent(u, c.N)

	// api.AssertIsDifferent(z, c.N)

	return nil
}

func getInnerCommit(assert *test.Assert, field, outer *big.Int) (constraint.ConstraintSystem, plonk.VerifyingKey, witness.Witness, plonk.Proof) {

	innerCcs, err := frontend.Compile(field, scs.NewBuilder, &InnerCircuitCommit{})
	assert.NoError(err)

	srs, err := test.NewKZGSRS(innerCcs)
	assert.NoError(err)

	innerPK, innerVK, err := plonk.Setup(innerCcs, srs)
	assert.NoError(err)

	// inner proof
	innerAssignment := &InnerCircuitCommit{
		P: 3,
		Q: 5,
		N: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	assert.NoError(err)
	fsProverHasher, err := recursion.NewShort(outer, field)
	assert.NoError(err)
	kzgProverHasher, err := recursion.NewShort(outer, field)
	assert.NoError(err)
	htfProverdHasher, err := recursion.NewShort(outer, field)
	assert.NoError(err)
	innerProof, err := plonk.Prove(innerCcs, innerPK, innerWitness,
		backend.WithProverChallengeHashFunction(fsProverHasher),
		backend.WithProverKZGFoldingHashFunction(kzgProverHasher),
		backend.WithProverHashToFieldFunction(htfProverdHasher),
	)

	assert.NoError(err)
	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)
	fsVerifierHasher, err := recursion.NewShort(outer, field)
	assert.NoError(err)
	kzgVerifierHash, err := recursion.NewShort(outer, field)
	assert.NoError(err)
	htfVerifierHasher, err := recursion.NewShort(outer, field)
	assert.NoError(err)
	err = plonk.Verify(innerProof, innerVK, innerPubWitness,
		backend.WithVerifierChallengeHashFunction(fsVerifierHasher),
		backend.WithVerifierKZGFoldingHashFunction(kzgVerifierHash),
		backend.WithVerifierHashToFieldFunction(htfVerifierHasher),
	)
	// backend.WithVerifierChallengeHashFunction(fsProverHasher),

	assert.NoError(err)
	return innerCcs, innerVK, innerPubWitness, innerProof
}

func TestBLS12InBW6Commit(t *testing.T) {

	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInnerCommit(assert, ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField())

	// outer proof
	circuitVk, err := ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerVK)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
		Proof:        PlaceholderProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof),
		VerifyingKey: PlaceholderVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerVK),
	}
	outerAssignment := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BW6_761.ScalarField())
	assert.NoError(err)

}
