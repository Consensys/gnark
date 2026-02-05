package sw_bw6761

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
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

// Circuit for testing G2 scalar multiplication with complete arithmetic (handles edge cases)
type scalarMulG2CompleteCircuit struct {
	In, Res G2Affine
	S       Scalar
}

func (c *scalarMulG2CompleteCircuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return fmt.Errorf("new G2 struct: %w", err)
	}
	res := g2.scalarMulGLVAndFakeGLV(&c.In, &c.S, algopts.WithCompleteArithmetic())
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

// TestScalarMulG2EdgeCases tests edge cases: s=0, s=1, s=-1, Q=(0,0)
func TestScalarMulG2EdgeCases(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, _, gen := bw6761.Generators()

	// Test case: s = 1 (result should be Q)
	t.Run("s=1", func(t *testing.T) {
		var s fr.Element
		s.SetOne()
		var res bw6761.G2Affine
		res.Set(&gen) // [1]Q = Q

		witness := scalarMulG2CompleteCircuit{
			In:  NewG2Affine(gen),
			S:   NewScalar(s),
			Res: NewG2Affine(res),
		}
		err := test.IsSolved(&scalarMulG2CompleteCircuit{}, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	})

	// Test case: s = -1 (result should be -Q)
	t.Run("s=-1", func(t *testing.T) {
		var s fr.Element
		s.SetOne()
		s.Neg(&s) // s = -1
		var res bw6761.G2Affine
		res.Neg(&gen) // [-1]Q = -Q

		witness := scalarMulG2CompleteCircuit{
			In:  NewG2Affine(gen),
			S:   NewScalar(s),
			Res: NewG2Affine(res),
		}
		err := test.IsSolved(&scalarMulG2CompleteCircuit{}, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	})

	// Test case: s = 0 (result should be (0,0))
	t.Run("s=0", func(t *testing.T) {
		var s fr.Element
		s.SetZero()
		var res bw6761.G2Affine // zero value is (0,0)

		witness := scalarMulG2CompleteCircuit{
			In:  NewG2Affine(gen),
			S:   NewScalar(s),
			Res: NewG2Affine(res),
		}
		err := test.IsSolved(&scalarMulG2CompleteCircuit{}, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	})

}
