package sw_bw6761

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type scalarMulG2GLVAndFakeGLVCircuit struct {
	In  G2Affine
	Res G2Affine
	S   Scalar
}

func (c *scalarMulG2GLVAndFakeGLVCircuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return err
	}
	res := g2.ScalarMul(&c.In, &c.S)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestScalarMulG2GLVAndFakeGLV(t *testing.T) {
	assert := test.NewAssert(t)
	// Use a fixed scalar for reproducibility
	s := big.NewInt(12345)
	var sFr fr.Element
	sFr.SetBigInt(s)

	_, in1 := randomG1G2Affines()
	var res bw6761.G2Affine
	res.ScalarMultiplication(&in1, s)

	witness := scalarMulG2GLVAndFakeGLVCircuit{
		In:  NewG2Affine(in1),
		S:   NewScalar(sFr),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&scalarMulG2GLVAndFakeGLVCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestScalarMulG2GLVAndFakeGLVRandom(t *testing.T) {
	assert := test.NewAssert(t)
	// Use a random scalar
	s, _ := rand.Int(rand.Reader, fr.Modulus())
	var sFr fr.Element
	sFr.SetBigInt(s)

	_, in1 := randomG1G2Affines()
	var res bw6761.G2Affine
	res.ScalarMultiplication(&in1, s)

	witness := scalarMulG2GLVAndFakeGLVCircuit{
		In:  NewG2Affine(in1),
		S:   NewScalar(sFr),
		Res: NewG2Affine(res),
	}
	err := test.IsSolved(&scalarMulG2GLVAndFakeGLVCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
