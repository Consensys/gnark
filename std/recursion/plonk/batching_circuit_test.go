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
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/recursion"
	"github.com/consensys/gnark/test"
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
		ccss[i], vks[i], pks[i], _ = getInnerCircuitData(&ic1)
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
		proofWitnessSelector[i].Selector = i % numberTypesCircuits
		allCcss[i] = ccss[i%numberTypesCircuits]

		// write the current witness to the hash
		vec := proofWitnessSelector[i].Witness.Vector()
		tvec := vec.(fr_bls12377.Vector)
		for j := 0; j < len(tvec); j++ {
			h.Write(tvec[j].Marshal())
		}
	}

	// instantiating outer circuit
	// fullCircuit := InstantiateBatchVerifyBisCircuit[sw_bls12377.ScalarField,
	// 	sw_bls12377.G1Affine,
	// 	sw_bls12377.G2Affine,
	// 	sw_bls12377.GT](ccss, allCcss)

	//  assign witness
	fullAssignment := AssignWitnessBis[sw_bls12377.ScalarField,
		sw_bls12377.G1Affine,
		sw_bls12377.G2Affine,
		sw_bls12377.GT](assert, vks, proofWitnessSelector)

	var frHashPub fr_bw6761.Element
	hashPub := h.Sum(nil)
	frHashPub.SetBytes(hashPub)
	fullAssignment.HashPublic = frHashPub.String()
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

//------------------------------------------------------
// inner circuit

type InnerCircuit struct {
	X       frontend.Variable
	Y       frontend.Variable `gnark:",public"`
	LogExpo int
}

func (c *InnerCircuit) Define(api frontend.API) error {
	var res frontend.Variable
	res = c.X
	for i := 0; i < c.LogExpo; i++ {
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

// get pk, vk, ccs of a circuit
func getInnerCircuitData(circuit frontend.Circuit) (constraint.ConstraintSystem, native_plonk.VerifyingKey, native_plonk.ProvingKey, kzg.SRS) {

	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, circuit)
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
func getProofsWitnesses(
	assert *test.Assert,
	ccs constraint.ConstraintSystem,
	nbInstances int,
	pk native_plonk.ProvingKey,
	vk native_plonk.VerifyingKey,
	logExpo int) ([]native_plonk.Proof, []witness.Witness) {

	proofs := make([]native_plonk.Proof, nbInstances)
	witnesses := make([]witness.Witness, nbInstances)

	for i := 0; i < nbInstances; i++ {

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

func TestBatchVerify(t *testing.T) {

	assert := test.NewAssert(t)

	// number of types of circuits that we batch
	numberOfCircuits := 1

	// assignment
	var fullAssignment BatchVerifyCircuits[
		sw_bls12377.ScalarField,
		sw_bls12377.G1Affine,
		sw_bls12377.G2Affine,
		sw_bls12377.GT]
	fullAssignment.Circuits = make(
		[]BatchVerifyCircuit[sw_bls12377.ScalarField,
			sw_bls12377.G1Affine,
			sw_bls12377.G2Affine,
			sw_bls12377.GT],
		numberOfCircuits,
	)

	// circuit
	var fullCircuit BatchVerifyCircuits[
		sw_bls12377.ScalarField,
		sw_bls12377.G1Affine,
		sw_bls12377.G2Affine,
		sw_bls12377.GT]
	fullCircuit.Circuits = make(
		[]BatchVerifyCircuit[sw_bls12377.ScalarField,
			sw_bls12377.G1Affine,
			sw_bls12377.G2Affine,
			sw_bls12377.GT],
		numberOfCircuits,
	)

	// hash to compute the public hash, which is the hash of all the public inputs
	// of all the inner circuits
	h, err := recursion.NewShort(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
	assert.NoError(err)
	// hashPub := h.Sum(nil)
	// var frHashPub fr_bw6761.Element
	// frHashPub.SetBytes(hashPub)

	curLogExp := 4     // parameter for the current type of circuit
	curBatchSize := 10 // number of copies of the currentn circuit

	for curCircuit := 0; curCircuit < numberOfCircuits; curCircuit++ {

		// get ccs, vk, pk, srs
		var ic1 InnerCircuit
		ic1.LogExpo = curLogExp
		innerCcs, vk, pk, _ := getInnerCircuitData(&ic1)

		// get tuples (proof, public_witness)
		proofs, witnesses := getProofsWitnesses(assert, innerCcs, curBatchSize, pk, vk, ic1.LogExpo)

		// append the current public witnesses to the hash buffer
		for i := 0; i < curBatchSize; i++ {
			vec := witnesses[i].Vector()
			tvec := vec.(fr_bls12377.Vector)
			for j := 0; j < len(tvec); j++ {
				h.Write(tvec[j].Marshal())
			}
		}

		// outer circuit
		fullCircuit.Circuits[curCircuit] = InstantiateOuterCircuit[
			sw_bls12377.ScalarField,
			sw_bls12377.G1Affine,
			sw_bls12377.G2Affine,
			sw_bls12377.GT](
			assert,
			curBatchSize,
			witnesses,
			innerCcs,
		)

		// witness assignment
		fullAssignment.Circuits[curCircuit] = AssignWitness[
			sw_bls12377.ScalarField,
			sw_bls12377.G1Affine,
			sw_bls12377.G2Affine,
			sw_bls12377.GT](
			assert,
			curBatchSize,
			// frHashPub.String(),
			witnesses,
			vk,
			proofs,
		)

		// change the circuit and the batch size
		curLogExp++
		curBatchSize++
	}

	// finally we compute the public hash, which is the hash of every public inputs
	// of the inner circuits
	hashPub := h.Sum(nil)
	var frHashPub fr_bw6761.Element
	frHashPub.SetBytes(hashPub)
	fullAssignment.HashPublic = frHashPub.String()

	ccs, _ := frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, &fullCircuit)
	fmt.Printf("nb constraints: %d\n", ccs.GetNbConstraints())

	err = test.IsSolved(&fullCircuit, &fullAssignment, ecc.BW6_761.ScalarField())
	assert.NoError(err)

}
