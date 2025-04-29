package evmprecompiles

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	kzg_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/commitments/kzg"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

const (
	kzgSize        = 128
	polynomialSize = 100
	nbPolynomials  = 5
)

type kzgPointEvaluationPrecompile struct {
	Data []uints.U8
	Vk   kzg.VerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine]
}

func (c *kzgPointEvaluationPrecompile) Define(api frontend.API) error {

	res, err := KzgPointEvaluation(api, c.Data, c.Vk)
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

	pointSerialised := point.Bytes()
	claimedValueSerialised := proof.ClaimedValue.Bytes()
	comSerialised := com.Bytes()
	proofSerialised := proof.H.Bytes()

	totalSize := 32 + 32 + 32 + 48 + 48
	inputs := make([]byte, totalSize)
	offset := 32
	copy(inputs[offset:], pointSerialised[:])
	offset += 32
	copy(inputs[offset:], claimedValueSerialised[:])
	offset += 32
	copy(inputs[offset:], comSerialised[:])
	offset += 48
	copy(inputs[offset:], proofSerialised[:])

	var witness, circuit kzgPointEvaluationPrecompile
	witness.Data = make([]uints.U8, totalSize)
	circuit.Data = make([]uints.U8, totalSize)
	for i := 0; i < totalSize; i++ {
		witness.Data[i] = uints.NewU8(inputs[i])
	}
	witness.Vk, err = kzg.ValueOfVerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine](srs.Vk)

	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}
