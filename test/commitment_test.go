package test

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	c "github.com/consensys/gnark/frontend/compiled"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/internal/backend/bn254/cs"
	groth16bn254 "github.com/consensys/gnark/internal/backend/bn254/groth16"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

type singleSecretCommittedCircuit struct {
	One frontend.Variable
}

func (c *singleSecretCommittedCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.One, 1)
	commit, err := api.Compiler().Commit(c.One)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commit, 0)
	return nil
}

func setup(t *testing.T, circuit frontend.Circuit) (frontend.CompiledConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey) {
	_r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	assert.NoError(t, err)

	pk, vk, err := groth16.Setup(_r1cs)
	assert.NoError(t, err)

	return _r1cs, pk, vk
}

func prove(t *testing.T, assignment frontend.Circuit, cs frontend.CompiledConstraintSystem, pk groth16.ProvingKey) (*witness.Witness, groth16.Proof) {
	_witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	assert.NoError(t, err)

	proof, err := groth16.Prove(cs, pk, _witness)
	assert.NoError(t, err)

	public, err := _witness.Public()
	assert.NoError(t, err)
	return public, proof
}

func test(t *testing.T, circuit frontend.Circuit, assignment frontend.Circuit) {

	_r1cs, pk, vk := setup(t, circuit)

	public, proof := prove(t, assignment, _r1cs, pk)

	assert.NoError(t, groth16.Verify(proof, vk, public))
}

func TestSingleSecretCommitted(t *testing.T) {
	circuit := singleSecretCommittedCircuit{}
	assignment := singleSecretCommittedCircuit{One: 1}

	test(t, &circuit, &assignment)
}

type noCommitmentCircuit struct { // to see if unadulterated groth16 is still correct
	One frontend.Variable
}

func (c *noCommitmentCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.One, 1)
	return nil
}

func TestNoCommitmentCircuit(t *testing.T) {
	circuit := noCommitmentCircuit{}
	assignment := noCommitmentCircuit{One: 1}

	test(t, &circuit, &assignment)
}

/*func TestSingleSecretCommitmentLong(t *testing.T) {
	circuit := singleSecretCommittedCircuit{}
	assignment := singleSecretCommittedCircuit{One: 1}

	_r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(t, err)

	printConstraints(_r1cs)

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	assert.NoError(t, err)

	pk, vk, err := groth16.Setup(_r1cs)
	assert.NoError(t, err)

	// make sure proving and verifying keys are correct
	//Pk := pk.(*groth16_bn254.ProvingKey)

	proof, err := groth16.Prove(_r1cs, pk, witness)
	assert.NoError(t, err)

	public, err := witness.Public()
	assert.NoError(t, err)
	assert.NoError(t, groth16.Verify(proof, vk, public))
}*/

// Just to see if the A,B,C values are computed correctly
type singleSecretFauxCommitmentCircuit struct {
	One        frontend.Variable `gnark:",public"`
	Commitment frontend.Variable `gnark:",public"`
}

func (c *singleSecretFauxCommitmentCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.One, 1)
	api.AssertIsDifferent(c.Commitment, 0)
	return nil
}

func TestSingleSecretFauxCommitmentCircuit(t *testing.T) {
	test(t, &singleSecretFauxCommitmentCircuit{}, &singleSecretFauxCommitmentCircuit{
		One:        1,
		Commitment: 2,
	})
}

func assertEqual(t *testing.T, expected, seen []bn254.G1Affine) {
	assert.Equal(t, len(expected), len(seen))
	for i := range expected {
		assert.True(t, expected[i].Equal(&seen[i]), "at index %d", i)
	}
}

func TestSingleSecretSetup(t *testing.T) {
	fr.ResetSetRandom()
	_, rpk, rvk := setup(t, &singleSecretCommittedCircuit{})
	fr.ResetSetRandom()
	_, fpk, fvk := setup(t, &singleSecretFauxCommitmentCircuit{})

	rPk, fPk, rVk, fVk := rpk.(*groth16bn254.ProvingKey), fpk.(*groth16bn254.ProvingKey),
		rvk.(*groth16bn254.VerifyingKey), fvk.(*groth16bn254.VerifyingKey)

	assertEqual(t, rPk.G1.K, fPk.G1.K)

	assert.Equal(t, len(fVk.G1.K), len(rVk.G1.K)+rVk.CommitmentKey.Size())
	assertEqual(t, fVk.G1.K, []bn254.G1Affine{rVk.G1.K[0], rVk.CommitmentKey.Basis()[0], rVk.G1.K[1]})
}

func TestSingleSecretProof(t *testing.T) {
	fr.ResetSetRandom()
	rcs, rpk, _ := setup(t, &singleSecretCommittedCircuit{})
	_, rproof := prove(t, &singleSecretCommittedCircuit{
		One: 1,
	}, rcs, rpk)

	rProof := rproof.(*groth16bn254.Proof)
	rCs := rcs.(*cs.R1CS)
	commWireFr, err := solveCommitmentWire(&rCs.CommitmentInfo, &rProof.Commitment, []*big.Int{})
	assert.NoError(t, err)
	fmt.Println("test routine computed commitment variable = ", commWireFr.Text(16))

	fr.ResetSetRandom()
	fcs, fpk, _ := setup(t, &singleSecretFauxCommitmentCircuit{})
	_, fproof := prove(t, &singleSecretFauxCommitmentCircuit{
		One:        1,
		Commitment: commWireFr,
	}, fcs, fpk)

	fProof := fproof.(*groth16bn254.Proof)
	assertEqual(t, []bn254.G1Affine{fProof.Ar, fProof.Krs}, []bn254.G1Affine{rProof.Ar, rProof.Krs})
}

func solveCommitmentWire(commitmentInfo *c.Info, commitment *bn254.G1Affine, publicCommitted []*big.Int) (fr.Element, error) {
	res, err := fr.Hash(commitmentInfo.SerializeCommitment(commitment.Marshal(), publicCommitted, (fr.Bits-1)/8+1), []byte(c.Dst), 1)
	return res[0], err
}
