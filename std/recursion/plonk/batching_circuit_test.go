package plonk

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	gnark_kzg "github.com/consensys/gnark/std/commitments/kzg"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion"
	"github.com/consensys/gnark/test"
)

//------------------------------------------------------
// inner circuits

// inner circuit
type InnerCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *InnerCircuit) Define(api frontend.API) error {
	var res frontend.Variable
	res = c.X
	for i := 0; i < 5; i++ {
		res = api.Mul(res, res)
	}
	api.AssertIsEqual(res, c.Y)

	commitment, err := api.(frontend.Committer).Commit(c.X, res)
	if err != nil {
		return err
	}

	api.AssertIsDifferent(commitment, res)

	return nil
}

// get VK, PK base circuit
func GetInnerCircuitData() (constraint.ConstraintSystem, native_plonk.VerifyingKey, native_plonk.ProvingKey, kzg.SRS) {

	var ic InnerCircuit
	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &ic)
	if err != nil {
		panic("compilation failed: " + err.Error())
	}

	srs, err := test.NewKZGSRS(ccs)
	if err != nil {
		panic(err)
	}

	pk, vk, err := native_plonk.Setup(ccs, srs)
	if err != nil {
		panic("setup failed: " + err.Error())
	}

	return ccs, vk, pk, srs
}

// get proofs
func getProofsWitnesses(assert *test.Assert, ccs constraint.ConstraintSystem, nbInstances int, pk native_plonk.ProvingKey, vk native_plonk.VerifyingKey) ([]native_plonk.Proof, []witness.Witness) {

	proofs := make([]native_plonk.Proof, nbInstances)
	witnesses := make([]witness.Witness, nbInstances)

	for i := 0; i < nbInstances; i++ {
		var assignment InnerCircuit

		var x, y fr_bls12377.Element
		x.SetRandom()
		y.Exp(x, big.NewInt(32))
		assignment.X = x.String()
		assignment.Y = y.String()

		fullWitness, err := frontend.NewWitness(&assignment, ecc.BLS12_377.ScalarField())
		if err != nil {
			panic("secret witness failed: " + err.Error())
		}

		publicWitness, err := fullWitness.Public()
		if err != nil {
			panic("public witness failed: " + err.Error())
		}

		fsProverHasher, err := recursion.NewShort(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
		assert.NoError(err)
		kzgProverHasher, err := recursion.NewShort(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
		assert.NoError(err)
		htfProverHasher, err := recursion.NewShort(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
		assert.NoError(err)

		proof, err := native_plonk.Prove(
			ccs,
			pk,
			fullWitness,
			backend.WithProverChallengeHashFunction(fsProverHasher),
			backend.WithProverKZGFoldingHashFunction(kzgProverHasher),
			backend.WithProverHashToFieldFunction(htfProverHasher),
		)
		if err != nil {
			panic("error proving: " + err.Error())
		}

		proofs[i] = proof
		witnesses[i] = publicWitness

		// sanity check
		fsVerifierHasher, err := recursion.NewShort(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
		assert.NoError(err)
		kzgVerifierHasher, err := recursion.NewShort(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
		assert.NoError(err)
		htfVerifierHasher, err := recursion.NewShort(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
		assert.NoError(err)

		err = native_plonk.Verify(
			proof,
			vk,
			publicWitness,
			backend.WithVerifierChallengeHashFunction(fsVerifierHasher),
			backend.WithVerifierKZGFoldingHashFunction(kzgVerifierHasher),
			backend.WithVerifierHashToFieldFunction(htfVerifierHasher),
		)
		if err != nil {
			panic("error verifying: " + err.Error())
		}
	}
	return proofs, witnesses
}

//------------------------------------------------------
// outer circuit

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

	// selectors[i]==0/1 means that the i-th circuit is un/instantiated
	// Selectors []frontend.Variable

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
		//err = verifier.AssertProof(circuit.VerifyfingKey, circuit.Proofs[i], circuit.PublicInners[i])
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

func instantiateOuterCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
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
	// outerCircuit.Selectors = make([]frontend.Variable, batchSizeProofs)

	return outerCircuit
}

func assignWitness[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
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

// set the outer proof
func TestBatchVerify(t *testing.T) {

	assert := test.NewAssert(t)

	// get ccs, vk, pk, srs
	batchSizeProofs := 10
	innerCcs, vk, pk, _ := GetInnerCircuitData()

	// get tuples (proof, public_witness)
	proofs, witnesses := getProofsWitnesses(assert, innerCcs, batchSizeProofs, pk, vk)

	// hash public inputs of the inner proofs
	h, err := recursion.NewShort(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
	assert.NoError(err)
	for i := 0; i < batchSizeProofs; i++ {
		vec := witnesses[i].Vector()
		tvec := vec.(fr_bls12377.Vector)
		for j := 0; j < len(tvec); j++ {
			h.Write(tvec[j].Marshal())
		}
	}
	hashPub := h.Sum(nil)
	var frHashPub fr_bw6761.Element
	frHashPub.SetBytes(hashPub)

	// selectors := make([]int, batchSizeProofs)
	// for i := 0; i < batchSizeProofs; i++ {
	// 	selectors[i] = i % 2
	// }

	// outer circuit
	outerCircuit := instantiateOuterCircuit[
		sw_bls12377.ScalarField,
		sw_bls12377.G1Affine,
		sw_bls12377.G2Affine,
		sw_bls12377.GT](
		assert,
		batchSizeProofs,
		witnesses,
		innerCcs,
	)

	// witness assignment
	outerAssignment := assignWitness[sw_bls12377.ScalarField,
		sw_bls12377.G1Affine,
		sw_bls12377.G2Affine,
		sw_bls12377.GT](
		assert,
		batchSizeProofs,
		frHashPub.String(),
		witnesses,
		vk,
		proofs,
		// selectors,
	)

	// proving + verifying on bw6-761
	// ccs, err := frontend.Compile(
	// 	ecc.BW6_761.ScalarField(),
	// 	scs.NewBuilder,
	// 	&outerCircuit)
	// assert.NoError(err)

	// srs, err := test.NewKZGSRS(ccs)
	// assert.NoError(err)

	// fullWitness, err := frontend.NewWitness(&outerAssignment, ecc.BW6_761.ScalarField())
	// assert.NoError(err)

	// bw6pk, bw6vk, err := native_plonk.Setup(ccs, srs)
	// assert.NoError(err)

	// proof, err := native_plonk.Prove(ccs, bw6pk, fullWitness)
	// assert.NoError(err)

	// publicWitness, err := fullWitness.Public()
	// assert.NoError(err)

	// err = native_plonk.Verify(proof, bw6vk, publicWitness)
	// assert.NoError(err)

	ccs, err := frontend.Compile(
		ecc.BW6_761.ScalarField(),
		scs.NewBuilder,
		&outerCircuit)
	assert.NoError(err)
	fmt.Printf("nb constraints: %d\n", ccs.GetNbConstraints())

	err = test.IsSolved(&outerCircuit, &outerAssignment, ecc.BW6_761.ScalarField())
	assert.NoError(err)
}
