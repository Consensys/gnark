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

// ------------------------------------------------------
// Batching same circuit
type BatchVerifyCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {

	// Number of proofs to batch
	batchSizeProofs int

	// proofs, verifying keys of the inner circuit
	Proofs       []Proof[FR, G1El, G2El]
	VerifyingKey VerifyingKey[FR, G1El, G2El] // TODO this should be a constant

	// Corresponds to the public inputs of the inner circuit
	PublicInners []Witness[FR]
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
	outerCircuit.VerifyingKey = PlaceholderVerifyingKey[FR, G1El, G2El](innerCcs)
	outerCircuit.batchSizeProofs = batchSizeProofs

	return outerCircuit
}

func AssignWitness[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	assert *test.Assert,
	batchSizeProofs int,
	// frHashPub string,
	witnesses []witness.Witness,
	vk native_plonk.VerifyingKey,
	proofs []native_plonk.Proof,
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
	outerAssignment := BatchVerifyCircuit[FR, G1El, G2El, GtEl]{
		Proofs:       assignmentProofs,
		VerifyingKey: assignmentVerifyingKeys,
		PublicInners: assignmentPubToPrivWitnesses,
		// HashPub:       frHashPub,
	}

	return outerAssignment
}

//------------------------------------------------------
// Batching different circuits

// BatchVerifyCircuits embeds BatchVerifyCircuit which stores the data for copies of the same circuit
// /!\ In BatchVerifyCircuits the SRS is common to each of the circuits in Circuits
type BatchVerifyCircuits[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Circuits   []BatchVerifyCircuit[FR, G1El, G2El, GtEl]
	HashPublic frontend.Variable `gnark:",public"`
}

func (circuit *BatchVerifyCircuits[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {

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

	for curCircuit := 0; curCircuit < len(circuit.Circuits); curCircuit++ {
		for i := 0; i < len(circuit.Circuits[curCircuit].PublicInners); i++ {
			for j := 0; j < len(circuit.Circuits[curCircuit].PublicInners[i].Public); j++ {
				toHash := curve.MarshalScalar(circuit.Circuits[curCircuit].PublicInners[i].Public[j])
				h.Write(toHash...)
			}
		}
	}

	s := h.Sum()
	api.AssertIsEqual(s, circuit.HashPublic)

	// run the verifiers
	verifier, err := NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}

	var totalNumberOfCircuits int
	for i := 0; i < len(circuit.Circuits); i++ {
		totalNumberOfCircuits += circuit.Circuits[i].batchSizeProofs
	}

	// at the end of each plonk verifiers, there are 2 KZG openings, at z and \nu z
	commitments := make([]gnark_kzg.Commitment[G1El], 2*totalNumberOfCircuits)
	proofs := make([]gnark_kzg.OpeningProof[FR, G1El], 2*totalNumberOfCircuits)
	points := make([]emulated.Element[FR], 2*totalNumberOfCircuits)

	offset := 0
	for i := 0; i < len(circuit.Circuits); i++ {
		for j := 0; j < circuit.Circuits[i].batchSizeProofs; j++ {
			commitmentPair, proofPair, pointPair, err := verifier.PrepareVerification(circuit.Circuits[i].VerifyingKey, circuit.Circuits[i].Proofs[j], circuit.Circuits[i].PublicInners[j])
			if err != nil {
				return err
			}
			copy(commitments[offset+2*j:], commitmentPair)
			copy(proofs[offset+2*j:], proofPair)
			copy(points[offset+2*j:], pointPair)
		}
		offset += 2 * circuit.Circuits[i].batchSizeProofs
	}
	if err != nil {
		return err
	}

	kzgVerifier, err := gnark_kzg.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return err
	}

	vkKZG := circuit.Circuits[0].VerifyingKey.Kzg
	err = kzgVerifier.BatchVerifyMultiPoints(commitments, proofs, points, vkKZG)

	return err

}
