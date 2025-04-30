package evmprecompiles

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	kzg_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/commitments/kzg"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

const (
	kzgSize        = 128
	polynomialSize = 100
	nbPolynomials  = 5
)

type kzgPointEvaluationPrecompile struct {
	VersionHash     []uints.U8
	Z               emulated.Element[sw_bls12381.ScalarField]
	Y               emulated.Element[sw_bls12381.ScalarField]
	ComSerialised   []uints.U8
	ProofSerialised []uints.U8
	Vk              kzg.VerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine]
}

func (c *kzgPointEvaluationPrecompile) Define(api frontend.API) error {

	res, err := KzgPointEvaluation(api, c.Z, c.Y, c.ComSerialised, c.ProofSerialised, c.Vk)
	if err != nil {
		return err
	}

	if len(res) != len(blobPrecompileReturnValueBytes) {
		return errors.New("wrong size return value")
	}

	for i := 0; i < len(res); i++ {
		api.AssertIsEqual(res[i].Val, blobPrecompileReturnValueBytes[i])
	}

	return nil
}

func TestKzgPointOpeningPrecompile(t *testing.T) {

	assert := test.NewAssert(t)

	alpha, err := rand.Int(rand.Reader, ecc.BLS12_381.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bls12381.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	f := make([]fr.Element, polynomialSize)
	for i := range f {
		f[i].SetRandom()
	}
	com, err := kzg_bls12381.Commit(f, srs.Pk)
	assert.NoError(err)
	var point fr.Element
	point.SetRandom()
	proof, err := kzg_bls12381.Open(f, point, srs.Pk)
	assert.NoError(err)

	comSerialised := com.Bytes()
	proofSerialised := proof.H.Bytes()

	// versioned hash
	h := sha256.Sum256(comSerialised[:])
	h[0] = blobCommitmentVersionKZG

	var witness, circuit kzgPointEvaluationPrecompile
	witness.VersionHash = make([]uints.U8, 32)
	for i := 0; i < 32; i++ {
		witness.VersionHash[i] = uints.NewU8(h[i])
	}
	witness.Z = emulated.ValueOf[sw_bls12381.ScalarField](point)
	witness.Y = emulated.ValueOf[sw_bls12381.ScalarField](proof.ClaimedValue)
	witness.ComSerialised = make([]uints.U8, fp.Bytes)
	witness.ProofSerialised = make([]uints.U8, fp.Bytes)
	for i := 0; i < fp.Bytes; i++ {
		witness.ComSerialised[i] = uints.NewU8(comSerialised[i])
		witness.ProofSerialised[i] = uints.NewU8(proofSerialised[i])
	}
	witness.Vk, err = kzg.ValueOfVerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine](srs.Vk)

	circuit.VersionHash = make([]uints.U8, 32)
	circuit.ComSerialised = make([]uints.U8, fp.Bytes)
	circuit.ProofSerialised = make([]uints.U8, fp.Bytes)

	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}
