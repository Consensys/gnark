package test

import (
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/backend/witness"
)

// solidityVerification checks that the exported solidity contract can verify the proof
// and that the proof is valid.
// It uses gnark-solidity-checker see test.WithSolidity option.
func (assert *Assert) solidityVerification(b backend.ID, c ecc.ID, vk solidity.VerifyingKey,
	proof any,
	validPublicWitness witness.Witness,
	opts []solidity.ExportOption,
) {
	if !SolcCheck {
		// we return, we don't have the solidity check build tag defined
		return
	}
	var nbPubWit int
	switch c {
	case ecc.BN254:
		nbPubWit = len(validPublicWitness.Vector().(fr_bn254.Vector))
	case ecc.BLS12_381:
		nbPubWit = len(validPublicWitness.Vector().(fr_bls12381.Vector))
	default:
		panic("solidity verification not implemented for this curve: " + c.String())
	}
	if nbPubWit == 0 {
		assert.Log("skipping solidity tests for zero public witness length")
		return
	}

	if assert.b != nil {
		assert.b.Helper()
	} else {
		assert.t.Helper()
	}

	// make temp dir
	tmpDir, err := os.MkdirTemp("", "gnark-solidity-check*")
	assert.NoError(err)
	defer os.RemoveAll(tmpDir)

	// export solidity contract
	fSolidity, err := os.Create(filepath.Join(tmpDir, "gnark_verifier.sol"))
	assert.NoError(err)

	err = vk.ExportSolidity(fSolidity, opts...)
	assert.NoError(err)

	err = fSolidity.Close()
	assert.NoError(err)

	// generate assets
	// gnark-solidity-checker generate --dir tmpdir --solidity contract_g16.sol
	cmd := exec.Command("go", "tool", "gnark-solidity-checker", "generate", "--dir", tmpDir, "--solidity", "gnark_verifier.sol")
	assert.Log("running ", cmd.String())
	out, err := cmd.CombinedOutput()
	assert.NoError(err, string(out))

	// len(vk.K) - 1 == len(publicWitness) + len(commitments)
	numOfCommitments := vk.NbPublicWitness() - nbPubWit

	// map ecc.ID to the curve name expected by gnark-solidity-checker
	var curveName string
	switch c {
	case ecc.BN254:
		curveName = "bn254"
	case ecc.BLS12_381:
		curveName = "bls12-381"
	default:
		panic("unsupported curve for solidity checker: " + c.String())
	}

	checkerOpts := []string{"tool", "gnark-solidity-checker", "verify", "--curve", curveName}
	if b == backend.GROTH16 {
		checkerOpts = append(checkerOpts, "--groth16")
	} else if b == backend.PLONK {
		checkerOpts = append(checkerOpts, "--plonk")
	} else {
		panic("not implemented")
	}

	// proof to hex
	_proof, ok := proof.(interface{ MarshalSolidity() []byte })
	if !ok {
		panic("proof does not implement MarshalSolidity()")
	}

	proofStr := hex.EncodeToString(_proof.MarshalSolidity())

	if numOfCommitments > 0 {
		checkerOpts = append(checkerOpts, "--commitment", strconv.Itoa(numOfCommitments))
	}

	// public witness to hex
	bPublicWitness, err := validPublicWitness.MarshalBinary()
	assert.NoError(err)
	// that's quite dirty...
	// first 4 bytes -> nbPublic
	// next 4 bytes -> nbSecret
	// next 4 bytes -> nb elements in the vector (== nbPublic + nbSecret)
	bPublicWitness = bPublicWitness[12:]
	publicWitnessStr := hex.EncodeToString(bPublicWitness)

	checkerOpts = append(checkerOpts, "--dir", tmpDir)
	checkerOpts = append(checkerOpts, "--nb-public-inputs", strconv.Itoa(nbPubWit))
	checkerOpts = append(checkerOpts, "--proof", proofStr)
	checkerOpts = append(checkerOpts, "--public-inputs", publicWitnessStr)

	// verify proof
	// gnark-solidity-checker verify --dir tmdir --groth16 --nb-public-inputs 1 --proof 1234 --public-inputs dead
	cmd = exec.Command("go", checkerOpts...)
	assert.Log("running ", cmd.String())
	out, err = cmd.CombinedOutput()
	assert.NoError(err, string(out))
}
