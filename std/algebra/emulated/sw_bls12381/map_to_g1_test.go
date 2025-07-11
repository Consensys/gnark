package sw_bls12381

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/hash_to_curve"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

// Test clear cofactor
type ClearCofactorCircuit struct {
	Point G1Affine
	Res   G1Affine
}

func (circuit *ClearCofactorCircuit) Define(api frontend.API) error {
	g, err := NewG1(api)
	if err != nil {
		return err
	}
	clearedPoint := g.ClearCofactor(&circuit.Point)
	g.AssertIsEqual(clearedPoint, &circuit.Res)
	return nil
}

func TestClearCofactor(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, g1, _ := bls12381.Generators()
	var g2 bls12381.G1Affine
	g2.ClearCofactor(&g1)
	witness := ClearCofactorCircuit{
		Point: NewG1Affine(g1),
		Res:   NewG1Affine(g2),
	}
	err := test.IsSolved(&ClearCofactorCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

// Test MapToCurve
type MapToCurveCircuit struct {
	U   emulated.Element[BaseField]
	Res G1Affine
}

func (circuit *MapToCurveCircuit) Define(api frontend.API) error {
	g, err := NewG1(api)
	if err != nil {
		return err
	}

	r, err := g.MapToCurve1(&circuit.U)
	if err != nil {
		return err
	}

	g.AssertIsEqual(r, &circuit.Res)

	return nil
}

func TestMapToCurve(t *testing.T) {

	assert := test.NewAssert(t)
	var a fp.Element
	a.SetRandom()
	g := bls12381.MapToCurve1(&a)

	witness := MapToCurveCircuit{
		U:   emulated.ValueOf[emulated.BLS12381Fp](a.String()),
		Res: NewG1Affine(g),
	}
	err := test.IsSolved(&MapToCurveCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

// Test Map to G1
type MapToG1Circuit struct {
	A emulated.Element[BaseField]
	R G1Affine
}

func (circuit *MapToG1Circuit) Define(api frontend.API) error {
	g, err := NewG1(api)
	if err != nil {
		return fmt.Errorf("new G1: %w", err)
	}
	res, err := g.MapToG1(&circuit.A)
	if err != nil {
		return err
	}

	g.AssertIsEqual(res, &circuit.R)

	return nil
}

func TestMapToG1(t *testing.T) {

	assert := test.NewAssert(t)
	var a fp.Element
	a.SetRandom()
	g := bls12381.MapToG1(a)

	witness := MapToG1Circuit{
		A: emulated.ValueOf[emulated.BLS12381Fp](a.String()),
		R: NewG1Affine(g),
	}
	err := test.IsSolved(&MapToG1Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type IsogenyG1Circuit struct {
	In  G1Affine
	Res G1Affine
}

func (c *IsogenyG1Circuit) Define(api frontend.API) error {
	g, err := NewG1(api)
	if err != nil {
		return err
	}
	res := g.isogeny(&c.In)
	g.AssertIsEqual(res, &c.Res)
	return nil
}

func TestIsogenyG1(t *testing.T) {
	assert := test.NewAssert(t)
	in, _ := randomG1G2Affines()
	var res bls12381.G1Affine
	res.Set(&in)
	hash_to_curve.G1Isogeny(&res.X, &res.Y)
	witness := IsogenyG1Circuit{
		In:  NewG1Affine(in),
		Res: NewG1Affine(res),
	}
	err := test.IsSolved(&IsogenyG1Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type EncodeToG1Circuit struct {
	Msg []uints.U8
	Res G1Affine
	Dst []byte
}

func (c *EncodeToG1Circuit) Define(api frontend.API) error {
	g, err := NewG1(api)
	if err != nil {
		return fmt.Errorf("new G1: %w", err)
	}
	res, err := g.EncodeToG1(c.Msg, []byte(c.Dst))
	if err != nil {
		return fmt.Errorf("encode to G1: %w", err)
	}

	g.AssertIsEqual(res, &c.Res)
	return nil
}

func TestEncodeToG1(t *testing.T) {
	assert := test.NewAssert(t)
	dst := []byte("BLS12381G1Test")
	for _, msgLen := range []int{0, 1, 31, 32, 33, 63, 64, 65} {
		assert.Run(func(assert *test.Assert) {
			msg := make([]byte, msgLen)
			_, err := rand.Reader.Read(msg)
			assert.NoError(err, "failed to generate random message")
			res, err := bls12381.EncodeToG1(msg, dst)
			assert.NoError(err, "failed to encode message to G1")
			circuit := EncodeToG1Circuit{Msg: make([]uints.U8, msgLen), Dst: dst}
			witness := EncodeToG1Circuit{Msg: uints.NewU8Array(msg), Res: NewG1Affine(res)}
			err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
			assert.NoError(err, "solving failed")
		}, fmt.Sprintf("msgLen=%d", msgLen))
	}
}

type HashToG1Circuit struct {
	Msg []uints.U8
	Res G1Affine
	Dst []byte
}

func (c *HashToG1Circuit) Define(api frontend.API) error {
	g, err := NewG1(api)
	if err != nil {
		return fmt.Errorf("new G1: %w", err)
	}
	res, err := g.HashToG1(c.Msg, []byte(c.Dst))
	if err != nil {
		return fmt.Errorf("hash to G1: %w", err)
	}

	g.AssertIsEqual(res, &c.Res)
	return nil
}

func TestHashToG1(t *testing.T) {
	assert := test.NewAssert(t)
	dst := []byte("BLS12381G1Test")
	for _, msgLen := range []int{0, 1, 31, 32, 33, 63, 64, 65} {
		assert.Run(func(assert *test.Assert) {
			msg := make([]byte, msgLen)
			_, err := rand.Reader.Read(msg)
			assert.NoError(err, "failed to generate random message")
			res, err := bls12381.HashToG1(msg, dst)
			assert.NoError(err, "failed to hash message to G1")
			circuit := HashToG1Circuit{Msg: make([]uints.U8, msgLen), Dst: dst}
			witness := HashToG1Circuit{Msg: uints.NewU8Array(msg), Res: NewG1Affine(res)}
			err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
			assert.NoError(err, "solving failed")
		}, fmt.Sprintf("msgLen=%d", msgLen))
	}
}
