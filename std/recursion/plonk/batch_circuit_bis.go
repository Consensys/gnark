package plonk

import (
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion"
	"github.com/consensys/gnark/test"
)

// Tuple correct couple (proof, witness)
type SnarkWitnessProof[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT] struct {
	Proof   Proof[FR, G1El, G2El]
	Witness Witness[FR]
	// Selector frontend.Variable
}

type WitnessProofSelector struct {
	Proof    native_plonk.Proof
	Witness  witness.Witness
	Selector int
}

type BatchVerifyBisCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {

	// number should be harcoded to the max
	Tuple []SnarkWitnessProof[FR, G1El, G2El]

	// Vk (number should be fixed)
	VerifyingKey []VerifyingKey[FR, G1El, G2El]

	// hash of the public inputs of the inner circuit
	HashPublic frontend.Variable `gnark:",public"`
}

func (circuit *BatchVerifyBisCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {

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
	for i := 0; i < len(circuit.Tuple); i++ {
		for j := 0; j < len(circuit.Tuple[i].Witness.Public); j++ {
			toHash := curve.MarshalScalar(circuit.Tuple[i].Witness.Public[j])
			h.Write(toHash...)
		}
	}
	s := h.Sum()
	api.AssertIsEqual(s, circuit.HashPublic)

	return nil
}

// InstantiateBatchVerifyBisCircuit
// ccs All the types of ccs
// totalCcs All ccs
func InstantiateBatchVerifyBisCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	ccs []constraint.ConstraintSystem,
	totalCcs []constraint.ConstraintSystem) BatchVerifyBisCircuit[FR, G1El, G2El, GtEl] {

	outerCircuit := BatchVerifyBisCircuit[FR, G1El, G2El, GtEl]{
		Tuple:        make([]SnarkWitnessProof[FR, G1El, G2El], len(totalCcs)),
		VerifyingKey: make([]VerifyingKey[FR, G1El, G2El], len(ccs)),
	}
	for i := 0; i < len(totalCcs); i++ {
		outerCircuit.Tuple[i].Witness = PlaceholderWitness[FR](totalCcs[i])
		outerCircuit.Tuple[i].Proof = PlaceholderProof[FR, G1El, G2El](totalCcs[i])
	}
	for i := 0; i < len(ccs); i++ {
		outerCircuit.VerifyingKey[i] = PlaceholderVerifyingKey[FR, G1El, G2El](ccs[i])
	}
	return outerCircuit
}

func AssignWitnessBis[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	assert *test.Assert,
	vks []native_plonk.VerifyingKey,
	wps []WitnessProofSelector,
) BatchVerifyBisCircuit[FR, G1El, G2El, GtEl] {

	var outerAssignment BatchVerifyBisCircuit[FR, G1El, G2El, GtEl]
	var err error

	outerAssignment.VerifyingKey = make([]VerifyingKey[FR, G1El, G2El], len(vks))
	for i := 0; i < len(vks); i++ {
		outerAssignment.VerifyingKey[i], err = ValueOfVerifyingKey[FR, G1El, G2El](vks[i])
		assert.NoError(err)
	}

	outerAssignment.Tuple = make([]SnarkWitnessProof[FR, G1El, G2El], len(wps))
	for i := 0; i < len(wps); i++ {

		outerAssignment.Tuple[i].Proof, err = ValueOfProof[FR, G1El, G2El](wps[i].Proof)
		assert.NoError(err)

		outerAssignment.Tuple[i].Witness, err = ValueOfWitness[FR](wps[i].Witness)
		assert.NoError(err)

		// outerAssignment.Tuple[i].Selector = wps[i].Selector
	}

	return outerAssignment
}
