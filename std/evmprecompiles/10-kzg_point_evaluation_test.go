package evmprecompiles

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	kzg_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

const (
	// locTrustedSetup is the location of the trusted setup file for the KZG precompile.
	locTrustedSetup = "kzg_trusted_setup.json"
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
	err := KzgPointEvaluation(api, c.VersionedHash, &c.EvaluationPoint, &c.ClaimedValue, c.Commitment, c.Proof, c.ExpectedSuccess, c.ExpectedBlobSize, c.ExpectedBlsModulus)
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

// trustedSetupJSON represents the trusted setup for the KZG precompile. It is
// used to verify the KZG commitments and openings. The setup is available at
// https://github.com/ethereum/go-ethereum/blob/master/crypto/kzg4844/trusted_setup.json.
// It was generated during the KZG Ceremony.
type trustedSetupJSON struct {
	G1         []string `json:"g1_monomial"`
	G1Lagrange []string `json:"g1_lagrange"`
	G2         []string `json:"g2_monomial"`
}

// parseTrustedSetup reads the trusted setup from the given reader and returns a
// trustedSetupJSON struct. It validates the setup to ensure it has the correct
// number of elements in G1, G2, and G1Lagrange. The G1 and G1Lagrange arrays
// must have exactly `evmBlockSize` elements, while G2 must have at least 2
// elements (but in practice has more for future extensibility). If the setup is
// invalid, it returns an error.
func parseTrustedSetup(r io.Reader) (*trustedSetupJSON, error) {
	var setup trustedSetupJSON
	dec := json.NewDecoder(r)
	if err := dec.Decode(&setup); err != nil {
		return nil, fmt.Errorf("decode trusted setup: %w", err)
	}
	if len(setup.G1) == 0 || len(setup.G2) == 0 || len(setup.G1Lagrange) == 0 {
		return nil, fmt.Errorf("invalid trusted setup: missing G1 or G2 or G1Lagrange")
	}
	if len(setup.G1) != evmBlockSize || len(setup.G1Lagrange) != evmBlockSize {
		return nil, fmt.Errorf("invalid trusted setup: G1 must have %d elements, got %d", evmBlockSize, len(setup.G1))
	}
	return &setup, nil
}

// toProvingKey converts the trusted setup JSON to a ProvingKey for allowing to
// compute the commitment and opening proof.
func (t *trustedSetupJSON) toProvingKey() (*kzg_bls12381.ProvingKey, error) {
	pk := kzg_bls12381.ProvingKey{
		G1: make([]bls12381.G1Affine, len(t.G1)),
	}
	for i, g1 := range t.G1 {
		decoded, err := decodePrefixed(g1)
		if err != nil {
			return nil, fmt.Errorf("decode G1 element %d: %w", i, err)
		}
		nbDec, err := pk.G1[i].SetBytes(decoded)
		if err != nil {
			return nil, fmt.Errorf("set G1 element %d: %w", i, err)
		}
		if nbDec != len(decoded) {
			return nil, fmt.Errorf("set G1 element %d: expected %d bytes, got %d", i, len(decoded), nbDec)
		}
	}
	return &pk, nil
}

// toVerifyingKey converts the trusted setup JSON to a VerifyingKey for allowing
// to verify the opening proof.
func (t *trustedSetupJSON) toVerifyingKey() (*kzg_bls12381.VerifyingKey, error) {
	var vk kzg_bls12381.VerifyingKey
	if len(t.G2) < 2 {
		return nil, fmt.Errorf("invalid trusted setup: G2 must have at least 2 elements")
	}
	if len(t.G1) < 1 {
		return nil, fmt.Errorf("invalid trusted setup: G1 must have at least 1 element")
	}
	decoded, err := decodePrefixed(t.G1[0])
	if err != nil {
		return nil, fmt.Errorf("decode G1 element 0: %w", err)
	}
	nbDec, err := vk.G1.SetBytes(decoded)
	if err != nil {
		return nil, fmt.Errorf("set G1 element 0: %w", err)
	}
	if nbDec != len(decoded) {
		return nil, fmt.Errorf("set G1 element 0: expected %d bytes, got %d", len(decoded), nbDec)
	}
	for i := range 2 {
		decoded, err := decodePrefixed(t.G2[i])
		if err != nil {
			return nil, fmt.Errorf("decode G2 element %d: %w", i, err)
		}
		nbDec, err := vk.G2[i].SetBytes(decoded)
		if err != nil {
			return nil, fmt.Errorf("set G2 element %d: %w", i, err)
		}
		if nbDec != len(decoded) {
			return nil, fmt.Errorf("set G2 element %d: expected %d bytes, got %d", i, len(decoded), nbDec)
		}
		vk.Lines[i] = bls12381.PrecomputeLines(vk.G2[i])
	}
	return &vk, nil
}

func decodePrefixed(line string) ([]byte, error) {
	if !strings.HasPrefix(line, "0x") {
		return nil, fmt.Errorf("invalid prefix in line: %s", line)
	}
	decoded, err := hex.DecodeString(line[2:])
	if err != nil {
		return nil, fmt.Errorf("decode hex string: %w", err)
	}
	return decoded, nil
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
