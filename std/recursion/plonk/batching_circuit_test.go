package plonk

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
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
func getInnerCircuitData(circuit frontend.Circuit) (constraint.ConstraintSystem, native_plonk.VerifyingKey, native_plonk.ProvingKey) {

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

		proof, err := native_plonk.Prove(ccs, pk, fullWitness,
			GetNativeProverOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()),
		)
		if err != nil {
			panic("error proving: " + err.Error())
		}

		proofs[i] = proof
		witnesses[i] = publicWitness

		// sanity check

		err = native_plonk.Verify(proof, vk, publicWitness,
			GetNativeVerifierOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()),
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
	numberOfCircuits := 3

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

	curLogExp := 4    // parameter for the current type of circuit
	curBatchSize := 5 // number of copies of the currentn circuit

	for curCircuit := 0; curCircuit < numberOfCircuits; curCircuit++ {

		// get ccs, vk, pk, srs
		var ic1 InnerCircuit
		ic1.LogExpo = curLogExp
		innerCcs, vk, pk := getInnerCircuitData(&ic1)

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

	err = test.IsSolved(&fullCircuit, &fullAssignment, ecc.BW6_761.ScalarField())
	assert.NoError(err)

}
