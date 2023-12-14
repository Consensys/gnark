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
)

// BatchProofs collects proof and witness pairs for efficient batched
// verification.
type BatchProofs[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	// VerifyingKey is the PLONK verification key check the proofs against
	VerifyingKey VerifyingKey[FR, G1El, G2El] `gnark:"-"`
	// proofs and witness pairs to check
	Proofs    []Proof[FR, G1El, G2El]
	Witnesses []Witness[FR]
}

// PlaceholderBatchProofs creates a placeholder for circuit compilation with constant verification key vk.
func PlaceholderBatchProofs[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](size int, ccs constraint.ConstraintSystem, vk VerifyingKey[FR, G1El, G2El]) BatchProofs[FR, G1El, G2El, GtEl] {
	pWits := make([]Witness[FR], size)
	pProofs := make([]Proof[FR, G1El, G2El], size)
	for i := range pWits {
		pWits[i] = PlaceholderWitness[FR](ccs)
		pProofs[i] = PlaceholderProof[FR, G1El, G2El](ccs)
	}
	return BatchProofs[FR, G1El, G2El, GtEl]{
		VerifyingKey: vk,
		Proofs:       pProofs,
		Witnesses:    pWits,
	}
}

func ValueOfBatchProofs[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](proofs []native_plonk.Proof, witnesses []witness.Witness) (BatchProofs[FR, G1El, G2El, GtEl], error) {
	var ret BatchProofs[FR, G1El, G2El, GtEl]
	var err error
	if len(proofs) != len(witnesses) {
		return ret, fmt.Errorf("proof and witness length mismatch")
	}
	wWits := make([]Witness[FR], len(witnesses))
	wProofs := make([]Proof[FR, G1El, G2El], len(proofs))
	for i := range wWits {
		wWits[i], err = ValueOfWitness[FR](witnesses[i])
		if err != nil {
			return ret, fmt.Errorf("assign witness %d: %w", err)
		}
		wProofs[i], err = ValueOfProof[FR, G1El, G2El](proofs[i])
		if err != nil {
			return ret, fmt.Errorf("assign proof %d: %w", err)
		}
	}
	return BatchProofs[FR, G1El, G2El, GtEl]{
		// we omit verification key as it is constant and defined in placeholder
		Proofs:    wProofs,
		Witnesses: wWits,
	}, nil
}

//------------------------------------------------------
// Batching different circuits

// BatchVerifyCircuits embeds BatchVerifyCircuit which stores the data for copies of the same circuit
// /!\ In BatchVerifyCircuits the SRS is common to each of the circuits in Circuits
type BatchVerifyCircuits[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Circuits   []BatchProofs[FR, G1El, G2El, GtEl]
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
		for i := 0; i < len(circuit.Circuits[curCircuit].Witnesses); i++ {
			for j := 0; j < len(circuit.Circuits[curCircuit].Witnesses[i].Public); j++ {
				toHash := curve.MarshalScalar(circuit.Circuits[curCircuit].Witnesses[i].Public[j])
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
			commitmentPair, proofPair, pointPair, err := verifier.PrepareVerification(circuit.Circuits[i].VerifyingKey, circuit.Circuits[i].Proofs[j], circuit.Circuits[i].Witnesses[j])
			if err != nil {
				return err
			}
			copy(commitments[offset+2*j:], commitmentPair)
			copy(proofs[offset+2*j:], proofPair)
			copy(points[offset+2*j:], pointPair)
		}
		offset += 2 * circuit.Circuits[i].batchSizeProofs
	}

	kzgVerifier, err := gnark_kzg.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return err
	}

	vkKZG := circuit.Circuits[0].VerifyingKey.Kzg
	err = kzgVerifier.BatchVerifyMultiPoints(commitments, proofs, points, vkKZG)

	return err

}
