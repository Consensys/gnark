package evmprecompiles

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
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
}

func (c *kzgPointEvalCircuit) Define(api frontend.API) error {
	err := KzgPointEvaluation(api, c.VersionedHash, &c.EvaluationPoint, &c.ClaimedValue, c.Commitment, c.Proof, c.ExpectedBlobSize, c.ExpectedBlsModulus)
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
	}
	err = test.IsSolved(&kzgPointEvalCircuit{}, &witness, ecc.BLS12_377.ScalarField())
	assert.NoError(err, "test solver")
}

type kzgPointEvalFailureCircuit struct {
	VersionedHash      [2]frontend.Variable
	EvaluationPoint    emulated.Element[sw_bls12381.ScalarField]
	ClaimedValue       emulated.Element[sw_bls12381.ScalarField]
	Commitment         [3]frontend.Variable
	Proof              [3]frontend.Variable
	ExpectedBlobSize   [2]frontend.Variable
	ExpectedBlsModulus [2]frontend.Variable
}

func (c *kzgPointEvalFailureCircuit) Define(api frontend.API) error {
	err := KzgPointEvaluationFailure(api, c.VersionedHash, &c.EvaluationPoint, &c.ClaimedValue, c.Commitment, c.Proof, c.ExpectedBlobSize, c.ExpectedBlsModulus)
	if err != nil {
		return fmt.Errorf("KzgPointEvaluationFailure: %w", err)
	}
	return nil
}

func runFailureCircuit(_ *test.Assert, evaluationPoint fr.Element, claimedValue fr.Element, hashBytes []byte, commitmentBytes [48]byte, proofBytes [48]byte, blobSize []int, blsModulus []string) error {
	witnessHash := [2]frontend.Variable{
		encode(hashBytes[16:32]),
		encode(hashBytes[0:16]),
	}
	// - commitment into 3 limbs
	witnessCommitment := [3]frontend.Variable{
		encode(commitmentBytes[32:48]),
		encode(commitmentBytes[16:32]),
		encode(commitmentBytes[0:16]),
	}
	// - proof into 3 limbs
	witnessProof := [3]frontend.Variable{
		encode(proofBytes[32:48]),
		encode(proofBytes[16:32]),
		encode(proofBytes[0:16]),
	}

	// prepare the constant return values
	witnessBlobSize := [2]frontend.Variable{
		blobSize[0],
		blobSize[1],
	}
	witnessBlsModulus := [2]frontend.Variable{
		blsModulus[0],
		blsModulus[1],
	}

	// prepare the full witness
	witness := kzgPointEvalFailureCircuit{
		VersionedHash:      witnessHash,
		EvaluationPoint:    emulated.ValueOf[sw_bls12381.ScalarField](evaluationPoint),
		ClaimedValue:       emulated.ValueOf[sw_bls12381.ScalarField](claimedValue),
		Commitment:         witnessCommitment,
		Proof:              witnessProof,
		ExpectedBlobSize:   witnessBlobSize,
		ExpectedBlsModulus: witnessBlsModulus,
	}
	return test.IsSolved(&kzgPointEvalFailureCircuit{}, &witness, ecc.BLS12_377.ScalarField())
}

func TestKzgPointEvaluationPrecompileFailure(t *testing.T) {
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

	// -- ensure that for valid inputs the circuit fails
	assert.Run(func(assert *test.Assert) {
		err = runFailureCircuit(assert,
			evaluationPoint,
			kzgProof.ClaimedValue,
			h[:],
			commitmentBytes,
			kzgProof.H.Bytes(),
			[]int{0, evmBlockSize},
			[]string{evmBlsModulusHi, evmBlsModulusLo},
		)
		assert.Error(err, "should fail on valid inputs")
	}, "valid-inputs")
	// -- generate proof not on curve and not on subgroup
	assert.Run(func(assert *test.Assert) {
		var proof bls12381.G1Affine
		for {
			proof.X.MustSetRandom()
			proof.Y.MustSetRandom()
			if !proof.IsOnCurve() {
				break
			}
		}
		proofBytes := proof.Bytes()
		err = runFailureCircuit(assert,
			evaluationPoint,
			kzgProof.ClaimedValue,
			h[:],
			commitmentBytes,
			proofBytes,
			[]int{0, evmBlockSize},
			[]string{evmBlsModulusHi, evmBlsModulusLo},
		)
		assert.NoError(err, "should pass")
	}, "proof-not-on-curve")
	assert.Run(func(assert *test.Assert) {
		var proof bls12381.G1Affine
		var r fp.Element
		r.MustSetRandom()
		proofJac := bls12381.GeneratePointNotInG1(r)
		proof.FromJacobian(&proofJac)
		proofBytes := proof.Bytes()
		err = runFailureCircuit(assert,
			evaluationPoint,
			kzgProof.ClaimedValue,
			h[:],
			commitmentBytes,
			proofBytes,
			[]int{0, evmBlockSize},
			[]string{evmBlsModulusHi, evmBlsModulusLo},
		)
		assert.NoError(err, "should pass")
	}, "proof-not-in-subgroup")
	// -- generate commitment not on curve and not on subgroup
	assert.Run(func(assert *test.Assert) {
		var commitment bls12381.G1Affine
		for {
			commitment.X.MustSetRandom()
			commitment.Y.MustSetRandom()
			if !commitment.IsOnCurve() {
				break
			}
		}
		commitmentBytes := commitment.Bytes()
		h := sha256.Sum256(commitmentBytes[:])
		h[0] = blobCommitmentVersionKZG
		err = runFailureCircuit(assert,
			evaluationPoint,
			kzgProof.ClaimedValue,
			h[:],
			commitmentBytes,
			kzgProof.H.Bytes(),
			[]int{0, evmBlockSize},
			[]string{evmBlsModulusHi, evmBlsModulusLo},
		)
		assert.NoError(err, "should pass")
	}, "commitment-not-on-curve")
	assert.Run(func(assert *test.Assert) {
		var commitment bls12381.G1Affine
		var r fp.Element
		r.MustSetRandom()
		commitmentJac := bls12381.GeneratePointNotInG1(r)
		commitment.FromJacobian(&commitmentJac)
		commitmentBytes := commitment.Bytes()
		h := sha256.Sum256(commitmentBytes[:])
		h[0] = blobCommitmentVersionKZG
		err = runFailureCircuit(assert,
			evaluationPoint,
			kzgProof.ClaimedValue,
			h[:],
			commitmentBytes,
			kzgProof.H.Bytes(),
			[]int{0, evmBlockSize},
			[]string{evmBlsModulusHi, evmBlsModulusLo},
		)
		assert.NoError(err, "should pass")
	}, "commitment-not-in-subgroup")
	// -- generate proof masks invalid
	assert.Run(func(assert *test.Assert) {
		// internally all cases
		assert.Run(func(assert *test.Assert) {
			// - mask 0b000 uncompressed
			proofBytes := kzgProof.H.RawBytes()
			var proofXBytes [bls12381.SizeOfG1AffineCompressed]byte
			copy(proofXBytes[:], proofBytes[:])
			assert.Equal(byte(0b000<<5), proofXBytes[0]&0xe0, "proof should be uncompressed")
			err = runFailureCircuit(assert,
				evaluationPoint,
				kzgProof.ClaimedValue,
				h[:],
				commitmentBytes,
				proofXBytes,
				[]int{0, evmBlockSize},
				[]string{evmBlsModulusHi, evmBlsModulusLo},
			)
			assert.NoError(err, "should pass")
		}, "0b000")
		assert.Run(func(assert *test.Assert) {
			// - mask 0b001 invalid
			proofBytes := kzgProof.H.Bytes()
			proofBytes[0] = (proofBytes[0] & 0x1f) | (0b001 << 5)
			assert.Equal(byte(0b001<<5), proofBytes[0]&0xe0, "proof should be invalid")
			err = runFailureCircuit(assert,
				evaluationPoint,
				kzgProof.ClaimedValue,
				h[:],
				commitmentBytes,
				proofBytes,
				[]int{0, evmBlockSize},
				[]string{evmBlsModulusHi, evmBlsModulusLo},
			)
			assert.NoError(err, "should pass")
		}, "0b001")
		assert.Run(func(assert *test.Assert) {
			// - mask 0b010 uncompressed infinity
			var proof bls12381.G1Affine
			proof.SetInfinity()
			proofBytes := proof.RawBytes()
			var proofXBytes [bls12381.SizeOfG1AffineCompressed]byte
			copy(proofXBytes[:], proofBytes[:])
			assert.Equal(byte(0b010<<5), proofXBytes[0]&0xe0, "proof should be uncompressed infinity")
			err = runFailureCircuit(assert,
				evaluationPoint,
				kzgProof.ClaimedValue,
				h[:],
				commitmentBytes,
				proofXBytes,
				[]int{0, evmBlockSize},
				[]string{evmBlsModulusHi, evmBlsModulusLo},
			)
			assert.NoError(err, "should pass")
		}, "0b010")
		assert.Run(func(assert *test.Assert) {
			// - mask 0b011 invalid
			proofBytes := kzgProof.H.Bytes()
			proofBytes[0] = (proofBytes[0] & 0x1f) | (0b011 << 5)
			assert.Equal(byte(0b011<<5), proofBytes[0]&0xe0, "proof should be invalid")
			err = runFailureCircuit(assert,
				evaluationPoint,
				kzgProof.ClaimedValue,
				h[:],
				commitmentBytes,
				proofBytes,
				[]int{0, evmBlockSize},
				[]string{evmBlsModulusHi, evmBlsModulusLo},
			)
			assert.NoError(err, "should pass")
		}, "0b011")
		assert.Run(func(assert *test.Assert) {
			// - mask 0b111 invalid
			proofBytes := kzgProof.H.Bytes()
			proofBytes[0] = (proofBytes[0] & 0x1f) | (0b111 << 5)
			assert.Equal(byte(0b111<<5), proofBytes[0]&0xe0, "proof should be invalid")
			err = runFailureCircuit(assert,
				evaluationPoint,
				kzgProof.ClaimedValue,
				h[:],
				commitmentBytes,
				proofBytes,
				[]int{0, evmBlockSize},
				[]string{evmBlsModulusHi, evmBlsModulusLo},
			)
			assert.NoError(err, "should pass")
		}, "0b111")
		assert.Run(func(assert *test.Assert) {
			// we have mask for compressed infinity but x coordinate has value
			proofBytes := kzgProof.H.Bytes()
			proofBytes[0] = (proofBytes[0] & 0x1f) | (0b110 << 5)
			assert.Equal(byte(0b110<<5), proofBytes[0]&0xe0, "proof should be compressed infinity")
			err = runFailureCircuit(assert,
				evaluationPoint,
				kzgProof.ClaimedValue,
				h[:],
				commitmentBytes,
				proofBytes,
				[]int{0, evmBlockSize},
				[]string{evmBlsModulusHi, evmBlsModulusLo},
			)
			assert.NoError(err, "should pass")
		}, "0b110")
	}, "proof-mask-invalid")
	assert.Run(func(assert *test.Assert) {
		// -- proof x coordinate overflows field
		// lets try to randomly create a proof with x coordinate small enough
		// that when we add modulus it is still 381 bits so that we can fit the
		// mask properly.
		// - lets ensure we don't overwrite our pristine data (but it should be
		// OK nevertheless, we create valid opening)
		randPoly := make(fr.Vector, evmBlockSize)
		var evaluationPoint fr.Element
		var kzgProof kzg_bls12381.OpeningProof
		var commitmentBytes [bls12381.SizeOfG1AffineCompressed]byte
		var h [sha256.Size]byte
		x := new(big.Int)
		for {
			randPoly.MustSetRandom()
			kzgCommitment, err := kzg_bls12381.Commit(randPoly, *pk)
			assert.NoError(err, "failed to compute KZG commitment")
			evaluationPoint.MustSetRandom()
			kzgProof, err = kzg_bls12381.Open(randPoly, evaluationPoint, *pk)
			assert.NoError(err, "failed to compute KZG proof")
			commitmentBytes = kzgCommitment.Bytes()
			h = sha256.Sum256(commitmentBytes[:])
			h[0] = blobCommitmentVersionKZG

			x = kzgProof.H.X.BigInt(x)
			x.Add(x, fp.Modulus())
			if x.BitLen() <= 381 {
				break
			}
		}
		proofBytes := kzgProof.H.Bytes()
		var proofXBytes [bls12381.SizeOfG1AffineCompressed]byte
		x.FillBytes(proofXBytes[:])
		proofXBytes[0] |= proofBytes[0] & 0xe0
		assert.Equal(proofBytes[0]&0xe0, proofXBytes[0]&0xe0, "proof prefix should be unchanged")
		err = runFailureCircuit(assert,
			evaluationPoint,
			kzgProof.ClaimedValue,
			h[:],
			commitmentBytes,
			proofXBytes,
			[]int{0, evmBlockSize},
			[]string{evmBlsModulusHi, evmBlsModulusLo},
		)
		assert.NoError(err, "should pass")
	}, "proof-x-coordinate-overflow")
	// -- generate commitment masks invalid
	assert.Run(func(assert *test.Assert) {
		// internally all cases
		assert.Run(func(assert *test.Assert) {
			// - mask 0b000 uncompressed
			commitmentBytes := kzgCommitment.RawBytes()
			var cmtXBytes [bls12381.SizeOfG1AffineCompressed]byte
			copy(cmtXBytes[:], commitmentBytes[:])
			assert.Equal(byte(0b000<<5), cmtXBytes[0]&0xe0, "proof should be uncompressed")
			err = runFailureCircuit(assert,
				evaluationPoint,
				kzgProof.ClaimedValue,
				h[:],
				cmtXBytes,
				kzgProof.H.Bytes(),
				[]int{0, evmBlockSize},
				[]string{evmBlsModulusHi, evmBlsModulusLo},
			)
			assert.NoError(err, "should pass")
		}, "0b000")
		assert.Run(func(assert *test.Assert) {
			// - mask 0b001 invalid
			commitmentBytes := kzgCommitment.Bytes()
			commitmentBytes[0] = (commitmentBytes[0] & 0x1f) | (0b001 << 5)
			assert.Equal(byte(0b001<<5), commitmentBytes[0]&0xe0, "proof should be invalid")
			err = runFailureCircuit(assert,
				evaluationPoint,
				kzgProof.ClaimedValue,
				h[:],
				commitmentBytes,
				kzgProof.H.Bytes(),
				[]int{0, evmBlockSize},
				[]string{evmBlsModulusHi, evmBlsModulusLo},
			)
			assert.NoError(err, "should pass")
		}, "0b001")
		assert.Run(func(assert *test.Assert) {
			// - mask 0b010 uncompressed infinity
			var commitment bls12381.G1Affine
			commitment.SetInfinity()
			cmtBytes := commitment.RawBytes()
			var cmtXBytes [bls12381.SizeOfG1AffineCompressed]byte
			copy(cmtXBytes[:], cmtBytes[:])
			assert.Equal(byte(0b010<<5), cmtXBytes[0]&0xe0, "proof should be uncompressed infinity")
			err = runFailureCircuit(assert,
				evaluationPoint,
				kzgProof.ClaimedValue,
				h[:],
				cmtXBytes,
				kzgProof.H.Bytes(),
				[]int{0, evmBlockSize},
				[]string{evmBlsModulusHi, evmBlsModulusLo},
			)
			assert.NoError(err, "should pass")
		}, "0b010")
		assert.Run(func(assert *test.Assert) {
			// - mask 0b011 invalid
			cmtBytes := kzgCommitment.Bytes()
			cmtBytes[0] = (cmtBytes[0] & 0x1f) | (0b011 << 5)
			assert.Equal(byte(0b011<<5), cmtBytes[0]&0xe0, "proof should be invalid")
			err = runFailureCircuit(assert,
				evaluationPoint,
				kzgProof.ClaimedValue,
				h[:],
				cmtBytes,
				kzgProof.H.Bytes(),
				[]int{0, evmBlockSize},
				[]string{evmBlsModulusHi, evmBlsModulusLo},
			)
			assert.NoError(err, "should pass")
		}, "0b011")
		assert.Run(func(assert *test.Assert) {
			// - mask 0b111 invalid
			cmtBytes := kzgCommitment.Bytes()
			cmtBytes[0] = (cmtBytes[0] & 0x1f) | (0b111 << 5)
			assert.Equal(byte(0b111<<5), cmtBytes[0]&0xe0, "proof should be invalid")
			err = runFailureCircuit(assert,
				evaluationPoint,
				kzgProof.ClaimedValue,
				h[:],
				cmtBytes,
				kzgProof.H.Bytes(),
				[]int{0, evmBlockSize},
				[]string{evmBlsModulusHi, evmBlsModulusLo},
			)
			assert.NoError(err, "should pass")
		}, "0b111")
		assert.Run(func(assert *test.Assert) {
			// we have mask for compressed infinity but x coordinate has value
			cmtBytes := kzgCommitment.Bytes()
			cmtBytes[0] = (cmtBytes[0] & 0x1f) | (0b110 << 5)
			assert.Equal(byte(0b110<<5), cmtBytes[0]&0xe0, "proof should be compressed infinity")
			err = runFailureCircuit(assert,
				evaluationPoint,
				kzgProof.ClaimedValue,
				h[:],
				cmtBytes,
				kzgProof.H.Bytes(),
				[]int{0, evmBlockSize},
				[]string{evmBlsModulusHi, evmBlsModulusLo},
			)
			assert.NoError(err, "should pass")
		}, "0b110")
	}, "commitment-mask-invalid")
	// -- commitment x coordinate overflows field
	assert.Run(func(assert *test.Assert) {
		randPoly := make(fr.Vector, evmBlockSize)
		var evaluationPoint fr.Element
		var kzgProof kzg_bls12381.OpeningProof
		var commitmentBytes [bls12381.SizeOfG1AffineCompressed]byte
		var h [sha256.Size]byte
		x := new(big.Int)
		for {
			randPoly.MustSetRandom()
			kzgCommitment, err := kzg_bls12381.Commit(randPoly, *pk)
			assert.NoError(err, "failed to compute KZG commitment")
			evaluationPoint.MustSetRandom()
			kzgProof, err = kzg_bls12381.Open(randPoly, evaluationPoint, *pk)
			assert.NoError(err, "failed to compute KZG proof")
			commitmentBytes = kzgCommitment.Bytes()
			h = sha256.Sum256(commitmentBytes[:])
			h[0] = blobCommitmentVersionKZG

			x = kzgCommitment.X.BigInt(x)
			x.Add(x, fp.Modulus())
			if x.BitLen() <= 381 {
				break
			}
		}
		var cmtXBytes [bls12381.SizeOfG1AffineCompressed]byte
		x.FillBytes(cmtXBytes[:])
		cmtXBytes[0] |= commitmentBytes[0] & 0xe0
		assert.Equal(commitmentBytes[0]&0xe0, cmtXBytes[0]&0xe0, "commitment prefix should be unchanged")
		err = runFailureCircuit(assert,
			evaluationPoint,
			kzgProof.ClaimedValue,
			h[:],
			cmtXBytes,
			kzgProof.H.Bytes(),
			[]int{0, evmBlockSize},
			[]string{evmBlsModulusHi, evmBlsModulusLo},
		)
		assert.NoError(err, "should pass")
	}, "commitment-x-coordinate-overflow-hashinitial")
	assert.Run(func(assert *test.Assert) {
		randPoly := make(fr.Vector, evmBlockSize)
		var evaluationPoint fr.Element
		var kzgProof kzg_bls12381.OpeningProof
		var commitmentBytes [bls12381.SizeOfG1AffineCompressed]byte
		var h [sha256.Size]byte
		x := new(big.Int)
		for {
			randPoly.MustSetRandom()
			kzgCommitment, err := kzg_bls12381.Commit(randPoly, *pk)
			assert.NoError(err, "failed to compute KZG commitment")
			evaluationPoint.MustSetRandom()
			kzgProof, err = kzg_bls12381.Open(randPoly, evaluationPoint, *pk)
			assert.NoError(err, "failed to compute KZG proof")
			commitmentBytes = kzgCommitment.Bytes()

			x = kzgCommitment.X.BigInt(x)
			x.Add(x, fp.Modulus())
			if x.BitLen() <= 381 {
				break
			}
		}
		var cmtXBytes [bls12381.SizeOfG1AffineCompressed]byte
		x.FillBytes(cmtXBytes[:])
		cmtXBytes[0] |= commitmentBytes[0] & 0xe0
		assert.Equal(commitmentBytes[0]&0xe0, cmtXBytes[0]&0xe0, "commitment prefix should be unchanged")
		h = sha256.Sum256(cmtXBytes[:])
		h[0] = blobCommitmentVersionKZG

		err = runFailureCircuit(assert,
			evaluationPoint,
			kzgProof.ClaimedValue,
			h[:],
			cmtXBytes,
			kzgProof.H.Bytes(),
			[]int{0, evmBlockSize},
			[]string{evmBlsModulusHi, evmBlsModulusLo},
		)
		assert.NoError(err, "should pass")
	}, "commitment-x-coordinate-overflow-hashnew")
	// -- generate hash version incorrect
	assert.Run(func(assert *test.Assert) {
		// random value not 1
		var b [1]byte
		for {
			_, err := rand.Reader.Read(b[:])
			assert.NoError(err, "rand")
			if b[0] != blobCommitmentVersionKZG {
				break
			}
		}
		var hh [sha256.Size]byte
		copy(hh[:], h[:])
		hh[0] = b[0]
		err = runFailureCircuit(assert,
			evaluationPoint,
			kzgProof.ClaimedValue,
			hh[:],
			commitmentBytes,
			kzgProof.H.Bytes(),
			[]int{0, evmBlockSize},
			[]string{evmBlsModulusHi, evmBlsModulusLo},
		)
		assert.NoError(err, "should pass")
	}, "hash-version-incorrect")
	// -- generate hash incorrect
	assert.Run(func(assert *test.Assert) {
		// change at random place
		var b [2]byte
		for {
			_, err := rand.Reader.Read(b[:])
			assert.NoError(err, "rand")
			if b[1] != 0 {
				break
			}
		}
		loc := b[0] % (sha256.Size - 1)
		var hh [sha256.Size]byte
		copy(hh[:], h[:])
		hh[loc] ^= b[1]
		err = runFailureCircuit(assert,
			evaluationPoint,
			kzgProof.ClaimedValue,
			hh[:],
			commitmentBytes,
			kzgProof.H.Bytes(),
			[]int{0, evmBlockSize},
			[]string{evmBlsModulusHi, evmBlsModulusLo},
		)
		assert.NoError(err, "should pass")
	}, "hash-incorrect")
	// -- generate invalid expected result
	assert.Run(func(assert *test.Assert) {
		// change expected blob size
		assert.Run(func(assert *test.Assert) {
			var evmBlockSizes [2]int
			var buf [16]byte
			_, err := rand.Reader.Read(buf[:])
			assert.NoError(err, "rand")
			evmBlockSizes[0] = int(binary.LittleEndian.Uint64(buf[0:8]))
			evmBlockSizes[1] = int(binary.LittleEndian.Uint64(buf[8:16]))
			err = runFailureCircuit(assert,
				evaluationPoint,
				kzgProof.ClaimedValue,
				h[:],
				commitmentBytes,
				kzgProof.H.Bytes(),
				evmBlockSizes[:],
				[]string{evmBlsModulusHi, evmBlsModulusLo},
			)
			assert.NoError(err, "should pass")
		}, "two-ints")
		assert.Run(func(assert *test.Assert) {
			var evmBlockSizeNew int
			for {
				var buf [8]byte
				_, err := rand.Reader.Read(buf[:])
				assert.NoError(err, "rand")
				evmBlockSizeNew := int(binary.LittleEndian.Uint64(buf[:]))
				if evmBlockSizeNew != evmBlockSize {
					break
				}
			}
			err = runFailureCircuit(assert,
				evaluationPoint,
				kzgProof.ClaimedValue,
				h[:],
				commitmentBytes,
				kzgProof.H.Bytes(),
				[]int{0, evmBlockSizeNew},
				[]string{evmBlsModulusHi, evmBlsModulusLo},
			)
			assert.NoError(err, "should pass")
		}, "one-int")
	}, "expected-blob-size-invalid")
	assert.Run(func(assert *test.Assert) {
		// change expected bls modulus
		var buf [32]byte
		_, err := rand.Reader.Read(buf[:])
		assert.NoError(err, "rand")
		err = runFailureCircuit(assert,
			evaluationPoint,
			kzgProof.ClaimedValue,
			h[:],
			commitmentBytes,
			kzgProof.H.Bytes(),
			[]int{0, evmBlockSize},
			[]string{encode(buf[16:32]), encode(buf[0:16])},
		)
		assert.NoError(err, "should pass")
	}, "expected-bls-modulus-invalid")
	// -- change claimed value
	assert.Run(func(assert *test.Assert) {
		var claimedValue fr.Element
		claimedValue.MustSetRandom()
		err = runFailureCircuit(assert,
			evaluationPoint,
			claimedValue,
			h[:],
			commitmentBytes,
			kzgProof.H.Bytes(),
			[]int{0, evmBlockSize},
			[]string{evmBlsModulusHi, evmBlsModulusLo},
		)
		assert.NoError(err, "should pass")
	}, "claimed-value-invalid")
	// -- change evaluation point
	assert.Run(func(assert *test.Assert) {
		var evaluationPoint fr.Element
		evaluationPoint.MustSetRandom()
		err = runFailureCircuit(assert,
			evaluationPoint,
			kzgProof.ClaimedValue,
			h[:],
			commitmentBytes,
			kzgProof.H.Bytes(),
			[]int{0, evmBlockSize},
			[]string{evmBlsModulusHi, evmBlsModulusLo},
		)
		assert.NoError(err, "should pass")
	}, "evaluation-point-invalid")
}

func encode(b []byte) string {
	return "0x" + hex.EncodeToString(b)
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
