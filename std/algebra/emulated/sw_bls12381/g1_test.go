package sw_bls12381

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fp_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type ToBytesG1Test struct {
	P               G1Affine
	CompressedPoint []uints.U8
}

func (c *ToBytesG1Test) Define(api frontend.API) error {
	g, err := NewG1(api)
	if err != nil {
		return err
	}
	bytes, err := g.ToCompressedBytes(c.P)
	if err != nil {
		return err
	}
	for i := 0; i < len(c.CompressedPoint); i++ {
		api.AssertIsEqual(c.CompressedPoint[i].Val, bytes[i].Val)
	}
	return nil
}

func TestToBytesG1(t *testing.T) {
	assert := test.NewAssert(t)
	{
		_, _, p, _ := bls12381.Generators()
		var r fr_bls12381.Element
		r.SetRandom()
		p.ScalarMultiplication(&p, r.BigInt(new(big.Int)))
		pMarshalled := p.Bytes()
		var witness, circuit ToBytesG1Test
		nbBytes := fp_bls12381.Bytes
		witness.CompressedPoint = make([]uints.U8, nbBytes)
		circuit.CompressedPoint = make([]uints.U8, nbBytes)
		for i := 0; i < nbBytes; i++ {
			witness.CompressedPoint[i] = uints.NewU8(pMarshalled[i])
		}
		witness.P = G1Affine{
			X: emulated.ValueOf[emulated.BLS12381Fp](p.X),
			Y: emulated.ValueOf[emulated.BLS12381Fp](p.Y),
		}

		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
	// infinity
	{
		var witness, circuit ToBytesG1Test
		nbBytes := fp_bls12381.Bytes
		witness.CompressedPoint = make([]uints.U8, nbBytes)
		circuit.CompressedPoint = make([]uints.U8, nbBytes)
		var p bls12381.G1Affine
		p.X.SetZero()
		p.Y.SetZero()
		pMarshalled := p.Bytes()
		for i := 0; i < nbBytes; i++ {
			witness.CompressedPoint[i] = uints.NewU8(pMarshalled[i])
		}
		witness.P = G1Affine{
			X: emulated.ValueOf[emulated.BLS12381Fp](0),
			Y: emulated.ValueOf[emulated.BLS12381Fp](0),
		}

		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
}

type FromBytesG1Test struct {
	CompressedPoint []uints.U8
	X               emulated.Element[BaseField]
	Y               emulated.Element[BaseField]
}

func (c *FromBytesG1Test) Define(api frontend.API) error {
	g, err := NewG1(api)
	if err != nil {
		return err
	}
	point, err := g.FromCompressedBytes(c.CompressedPoint)
	if err != nil {
		return err
	}
	g.curveF.AssertIsEqual(&point.X, &c.X)
	g.curveF.AssertIsEqual(&point.Y, &c.Y)
	return nil
}

func TestFromBytesG1(t *testing.T) {
	assert := test.NewAssert(t)
	{
		_, _, p, _ := bls12381.Generators()
		var r fr_bls12381.Element
		r.SetRandom()
		p.ScalarMultiplication(&p, r.BigInt(new(big.Int)))
		pMarshalled := p.Bytes()
		var witness, circuit FromBytesG1Test
		nbBytes := fp_bls12381.Bytes
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
		var witness, circuit FromBytesG1Test
		nbBytes := fp_bls12381.Bytes
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
