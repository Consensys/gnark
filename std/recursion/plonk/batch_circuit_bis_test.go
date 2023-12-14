package plonk

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/backend"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/recursion"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
)

// Test BatchVerifyBisCircuit
func TestBatchVerifyBisCircuit(t *testing.T) {

	assert := test.NewAssert(t)

	// hash to compute the public hash, which is the hash of all the public inputs
	// of all the inner circuits
	h, err := recursion.NewShort(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
	assert.NoError(err)

	// get data for outer circuit
	numberTypesCircuits := 4
	vks := make([]native_plonk.VerifyingKey, numberTypesCircuits)
	pks := make([]native_plonk.ProvingKey, numberTypesCircuits)
	ccss := make([]constraint.ConstraintSystem, numberTypesCircuits)
	logExp := make([]int, numberTypesCircuits)
	for i := 0; i < numberTypesCircuits; i++ {
		logExp[i] = (i + 3)
	}
	for i := 0; i < numberTypesCircuits; i++ {
		var ic1 InnerCircuit
		ic1.LogExpo = logExp[i%numberTypesCircuits]
		ccss[i], vks[i], pks[i] = getInnerCircuitDataBis(&ic1)
	}

	totalNumberOfCircuits := 20
	proofWitnessSelector := make([]WitnessProofSelector, totalNumberOfCircuits)
	allCcss := make([]constraint.ConstraintSystem, totalNumberOfCircuits)
	for i := 0; i < totalNumberOfCircuits; i++ {

		// get tuples (proof, public_witness)
		proofWitnessSelector[i].Proof, proofWitnessSelector[i].Witness = getProofsWitnessesBis(
			assert,
			ccss[i%numberTypesCircuits],
			pks[i%numberTypesCircuits],
			vks[i%numberTypesCircuits],
			logExp[i%numberTypesCircuits],
		)
		// proofWitnessSelector[i].Selector = i % numberTypesCircuits
		allCcss[i] = ccss[i%numberTypesCircuits]

		// write the current witness to the hash
		vec := proofWitnessSelector[i].Witness.Vector()
		tvec := vec.(fr_bls12377.Vector)
		for j := 0; j < len(tvec); j++ {
			h.Write(tvec[j].Marshal())
		}
	}

	// instantiating outer circuit
	fullCircuit := InstantiateBatchVerifyBisCircuit[sw_bls12377.ScalarField,
		sw_bls12377.G1Affine,
		sw_bls12377.G2Affine,
		sw_bls12377.GT](ccss, allCcss)

	//  assign witness
	fullAssignment := AssignWitnessBis[sw_bls12377.ScalarField,
		sw_bls12377.G1Affine,
		sw_bls12377.G2Affine,
		sw_bls12377.GT](assert, vks, proofWitnessSelector)

	var frHashPub fr_bw6761.Element
	hashPub := h.Sum(nil)
	frHashPub.SetBytes(hashPub)
	fullAssignment.HashPublic = frHashPub.String()

	// check that solving is done
	err = test.IsSolved(&fullCircuit, &fullAssignment, ecc.BW6_761.ScalarField())
	assert.NoError(err)
}

// get pk, vk, ccs of a circuit
func getInnerCircuitDataBis(circuit frontend.Circuit) (constraint.ConstraintSystem, native_plonk.VerifyingKey, native_plonk.ProvingKey) {

	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		panic("compilation failed: " + err.Error())
	}

	srsCanonical, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		panic(err)
	}

	pk, vk, err := native_plonk.Setup(ccs, srsCanonical, srsLagrange)
	if err != nil {
		panic("setup failed: " + err.Error())
	}

	return ccs, vk, pk
}

func getProofsWitnessesBis(
	assert *test.Assert,
	ccs constraint.ConstraintSystem,
	pk native_plonk.ProvingKey,
	vk native_plonk.VerifyingKey,
	logExpo int) (native_plonk.Proof, witness.Witness) {

	var assignment InnerCircuit

	var x, y fr_bls12377.Element
	x.SetRandom()
	y.Exp(x, big.NewInt(1<<logExpo))
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

	return proof, publicWitness
}
