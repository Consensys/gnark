package plonk

import (
	"fmt"

	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	gnark_kzg "github.com/consensys/gnark/std/commitments/kzg"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion"
	"github.com/consensys/gnark/test"
)

//------------------------------------------------------
// Batching same circuit

type BatchVerifyCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {

	// Number of proofs to batch
	batchSizeProofs int

	// dummy proofs, which are selected instead of the real proof, if the
	// corresponding selector is 0. The dummy proofs always pass.
	// TODO this should be a constant
	DummyProof Proof[FR, G1El, G2El]

	// proofs, verifying keys of the inner circuit
	Proofs        []Proof[FR, G1El, G2El]
	VerifyfingKey VerifyingKey[FR, G1El, G2El] // TODO this should be a constant

	// Corresponds to the public inputs of the inner circuit
	PublicInners []Witness[FR]

	// hash of the public inputs of the inner circuits
	HashPub frontend.Variable `gnark:",public"`
}

func (circuit *BatchVerifyCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {

	// get Plonk verifier
	curve, err := algebra.GetCurve[FR, G1El](api)
	if err != nil {
		return err
	}

	// check that hash(PublicInnters)==HashPub
	var fr FR
	h, err := recursion.NewHash(api, fr.Modulus(), true)
	if err != nil {
		return err
	}
	for i := 0; i < len(circuit.PublicInners); i++ {
		for j := 0; j < len(circuit.PublicInners[i].Public); j++ {
			toHash := curve.MarshalScalar(circuit.PublicInners[i].Public[j])
			h.Write(toHash...)
		}
	}
	s := h.Sum()
	api.AssertIsEqual(s, circuit.HashPub)

	// check that the proofs are correct
	verifier, err := NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	commitments := make([]gnark_kzg.Commitment[G1El], 2*circuit.batchSizeProofs)
	proofs := make([]gnark_kzg.OpeningProof[FR, G1El], 2*circuit.batchSizeProofs)
	points := make([]emulated.Element[FR], 2*circuit.batchSizeProofs)
	for i := 0; i < circuit.batchSizeProofs; i++ {
		commitmentPair, proofPair, pointPair, err := verifier.PrepareVerification(circuit.VerifyfingKey, circuit.Proofs[i], circuit.PublicInners[i])
		if err != nil {
			return err
		}
		copy(commitments[2*i:], commitmentPair)
		copy(proofs[2*i:], proofPair)
		copy(points[2*i:], pointPair)
	}

	kzgVerifier, err := gnark_kzg.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return err
	}
	err = kzgVerifier.BatchVerifyMultiPoints(commitments, proofs, points, circuit.VerifyfingKey.Kzg)

	return err
}

func InstantiateOuterCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	assert *test.Assert,
	batchSizeProofs int,
	witnesses []witness.Witness,
	innerCcs constraint.ConstraintSystem) BatchVerifyCircuit[FR, G1El, G2El, GtEl] {

	// outer ciruit instantation
	outerCircuit := BatchVerifyCircuit[FR, G1El, G2El, GtEl]{
		PublicInners: make([]Witness[FR], batchSizeProofs),
	}
	for i := 0; i < len(witnesses); i++ {
		outerCircuit.PublicInners[i] = PlaceholderWitness[FR](innerCcs)
	}
	outerCircuit.Proofs = make([]Proof[FR, G1El, G2El], batchSizeProofs)
	for i := 0; i < batchSizeProofs; i++ {
		outerCircuit.Proofs[i] = PlaceholderProof[FR, G1El, G2El](innerCcs)
	}
	outerCircuit.DummyProof = PlaceholderProof[FR, G1El, G2El](innerCcs)
	outerCircuit.VerifyfingKey = PlaceholderVerifyingKey[FR, G1El, G2El](innerCcs)
	outerCircuit.batchSizeProofs = batchSizeProofs

	return outerCircuit
}

func AssignWitness[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	assert *test.Assert,
	batchSizeProofs int,
	frHashPub string,
	witnesses []witness.Witness,
	vk native_plonk.VerifyingKey,
	proofs []native_plonk.Proof,
	// selectors []int,
) BatchVerifyCircuit[FR, G1El, G2El, GtEl] {

	assignmentPubToPrivWitnesses := make([]Witness[FR], batchSizeProofs)
	for i := 0; i < batchSizeProofs; i++ {
		curWitness, err := ValueOfWitness[FR](witnesses[i])
		assert.NoError(err)
		assignmentPubToPrivWitnesses[i] = curWitness
	}
	assignmentVerifyingKeys, err := ValueOfVerifyingKey[FR, G1El, G2El](vk)
	assert.NoError(err)
	assignmentProofs := make([]Proof[FR, G1El, G2El], batchSizeProofs)
	for i := 0; i < batchSizeProofs; i++ {
		assignmentProofs[i], err = ValueOfProof[FR, G1El, G2El](proofs[i])
		assert.NoError(err)
	}
	assignmentDummyProof, err := ValueOfProof[FR, G1El, G2El](proofs[0])
	outerAssignment := BatchVerifyCircuit[FR, G1El, G2El, GtEl]{
		Proofs:        assignmentProofs,
		VerifyfingKey: assignmentVerifyingKeys,
		PublicInners:  assignmentPubToPrivWitnesses,
		HashPub:       frHashPub,
		DummyProof:    assignmentDummyProof,
	}

	return outerAssignment
}
