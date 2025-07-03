package evmprecompiles

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	kzg_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type kzgPointEvalCircuit struct {
	VersionedHash      [2]frontend.Variable
	EvaluationPoint    emulated.Element[sw_bls12381.ScalarField]
	ClaimedValue       emulated.Element[sw_bls12381.ScalarField]
	Commitment         [3]frontend.Variable
	Proof              [3]frontend.Variable
	ExpectedBlobSize   [2]frontend.Variable
	ExpectedBlsModulus [2]frontend.Variable

	ExpectedSuccess frontend.Variable
}

func (c *kzgPointEvalCircuit) Define(api frontend.API) error {
	err := KzgPointEvaluation(api, c.VersionedHash, c.EvaluationPoint, c.ClaimedValue, c.Commitment, c.Proof, c.ExpectedSuccess, c.ExpectedBlobSize, c.ExpectedBlsModulus)
	if err != nil {
		return fmt.Errorf("KzgPointEvaluation: %w", err)
	}
	return nil
}

func TestKzgPointEvaluationPrecompile(t *testing.T) {
	assert := test.NewAssert(t)

	// setup loading
	f, err := os.Open(locTrustedSetup)
	assert.NoError(err, "failed to open trusted setup file")
	defer f.Close()
	setup, err := parseTrustedSetup(f)
	assert.NoError(err, "failed to parse trusted setup")

	// compute the proving key for commitment and opening
	pk, err := setup.toProvingKey()
	assert.NoError(err, "failed to convert trusted setup to proving key")

	// commit to a random polynomial
	randPoly := make(fr.Vector, evmBlockSize)
	randPoly.MustSetRandom()
	kzgCommitment, err := kzg_bls12381.Commit(randPoly, *pk)
	assert.NoError(err, "failed to compute KZG commitment")

	// compute the KZG proof for a random evaluation point
	var evaluationPoint fr.Element
	evaluationPoint.MustSetRandom()
	kzgProof, err := kzg_bls12381.Open(randPoly, evaluationPoint, *pk)
	assert.NoError(err, "failed to compute KZG proof")

	// prepare the witness elements
	// - versioned hash (hash of the commitment)
	commitmentBytes := kzgCommitment.Bytes()
	h := sha256.Sum256(commitmentBytes[:])
	h[0] = blobCommitmentVersionKZG

	encode := func(b []byte) string {
		return "0x" + hex.EncodeToString(b)
	}

	witnessHash := [2]frontend.Variable{
		encode(h[16:32]),
		encode(h[0:16]),
	}
	// - commitment into 3 limbs
	witnessCommitment := [3]frontend.Variable{
		encode(commitmentBytes[32:48]),
		encode(commitmentBytes[16:32]),
		encode(commitmentBytes[0:16]),
	}
	// - proof into 3 limbs
	proofUncompressed := kzgProof.H.Bytes()
	witnessProof := [3]frontend.Variable{
		encode(proofUncompressed[32:48]),
		encode(proofUncompressed[16:32]),
		encode(proofUncompressed[0:16]),
	}

	// prepare the constant return values
	witnessBlobSize := [2]frontend.Variable{
		0,
		evmBlockSize,
	}
	witnessBlsModulus := [2]frontend.Variable{
		"0x73eda753299d7d483339d80809a1d805",
		"0x53bda402fffe5bfeffffffff00000001",
	}

	// prepare the full witness
	witness := kzgPointEvalCircuit{
		VersionedHash:      witnessHash,
		EvaluationPoint:    emulated.ValueOf[sw_bls12381.ScalarField](evaluationPoint),
		ClaimedValue:       emulated.ValueOf[sw_bls12381.ScalarField](kzgProof.ClaimedValue),
		Commitment:         witnessCommitment,
		Proof:              witnessProof,
		ExpectedBlobSize:   witnessBlobSize,
		ExpectedBlsModulus: witnessBlsModulus,
		ExpectedSuccess:    1,
	}
	err = test.IsSolved(&kzgPointEvalCircuit{}, &witness, ecc.BLS12_377.ScalarField())
	assert.NoError(err, "test solver")
}

func TestTrustedSetupCompleteness(t *testing.T) {
	assert := test.NewAssert(t)

	f, err := os.Open(locTrustedSetup)
	assert.NoError(err, "failed to open trusted setup file")
	defer f.Close()

	setup, err := parseTrustedSetup(f)
	assert.NoError(err, "failed to parse trusted setup")
	pk, err := setup.toProvingKey()
	assert.NoError(err, "failed to convert trusted setup to proving key")
	vk, err := setup.toVerifyingKey()
	assert.NoError(err, "failed to convert trusted setup to verifying key")

	randPoly := make(fr.Vector, evmBlockSize)
	randPoly.MustSetRandom()
	kzgCommitment, err := kzg_bls12381.Commit(randPoly, *pk)
	assert.NoError(err, "failed to compute KZG commitment")
	var evaluationPoint fr.Element
	evaluationPoint.MustSetRandom()
	kzgProof, err := kzg_bls12381.Open(randPoly, evaluationPoint, *pk)
	assert.NoError(err, "failed to compute KZG proof")

	err = kzg_bls12381.Verify(&kzgCommitment, &kzgProof, evaluationPoint, *vk)
	assert.NoError(err, "KZG verification failed")

}
