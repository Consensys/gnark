package evmprecompiles

import (
	"crypto/rand"
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
	Point           emulated.Element[sw_bls12381.ScalarField]
	ClaimedValue    emulated.Element[sw_bls12381.ScalarField]
	ComCompressed   []uints.U8
	ProofCompressed []uints.U8
	Vk              kzg.VerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine]
}

func (c *kzgPointEvaluationPrecompile) Define(api frontend.API) error {

	res := KzgPointEvaluation(api, &c.Point, &c.ClaimedValue, c.ComCompressed, c.ProofCompressed, c.Vk)

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
	nbBytesSerialised := fp.Bytes

	var witness, circuit kzgPointEvaluationPrecompile
	witness.Point = emulated.ValueOf[sw_bls12381.ScalarField](point)
	witness.ClaimedValue = emulated.ValueOf[sw_bls12381.ScalarField](proof.ClaimedValue)
	witness.ComCompressed = make([]uints.U8, nbBytesSerialised)
	for i := 0; i < nbBytesSerialised; i++ {
		witness.ComCompressed[i] = uints.NewU8(comSerialised[i])
	}
	witness.ProofCompressed = make([]uints.U8, nbBytesSerialised)
	for i := 0; i < nbBytesSerialised; i++ {
		witness.ProofCompressed[i] = uints.NewU8(proofSerialised[i])
	}
	witness.Vk, err = kzg.ValueOfVerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine](srs.Vk)
	assert.NoError(err)
	circuit.ComCompressed = make([]uints.U8, nbBytesSerialised)
	circuit.ProofCompressed = make([]uints.U8, nbBytesSerialised)

	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}
