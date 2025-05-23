package sw_bls12381

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

type unmarshalPoint struct {
	CompressedPoint []uints.U8
	X               emulated.Element[BaseField]
	Y               emulated.Element[BaseField]
}

func (c *unmarshalPoint) Define(api frontend.API) error {

	g, err := NewG1(api)
	if err != nil {
		return err
	}

	point, err := g.UnmarshalCompressed(c.CompressedPoint)
	if err != nil {
		return err
	}

	g.curveF.AssertIsEqual(&point.X, &c.X)
	g.curveF.AssertIsEqual(&point.Y, &c.Y)

	return nil
}

func TestUnmarshalPoint(t *testing.T) {

	assert := test.NewAssert(t)

	{
		_, _, p, _ := bls12381.Generators()
		pMarshalled := p.Bytes()
		var witness, circuit unmarshalPoint
		nbBytes := fp.Bytes
		witness.CompressedPoint = make([]uints.U8, nbBytes)
		circuit.CompressedPoint = make([]uints.U8, nbBytes)
		for i := 0; i < nbBytes; i++ {
			witness.CompressedPoint[i] = uints.NewU8(pMarshalled[i])
		}
		witness.X = emulated.ValueOf[BaseField](p.X)
		witness.Y = emulated.ValueOf[BaseField](p.Y)

		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}

	// infinity
	{
		var witness, circuit unmarshalPoint
		nbBytes := fp.Bytes
		witness.CompressedPoint = make([]uints.U8, nbBytes)
		circuit.CompressedPoint = make([]uints.U8, nbBytes)
		var p bls12381.G1Affine
		p.X.SetZero()
		p.Y.SetZero()
		pMarshalled := p.Bytes()
		for i := 0; i < nbBytes; i++ {
			witness.CompressedPoint[i] = uints.NewU8(pMarshalled[i])
		}
		witness.X = emulated.ValueOf[BaseField](0)
		witness.Y = emulated.ValueOf[BaseField](0)

		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}

}
