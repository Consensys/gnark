package sw_bls12381

import (
	"encoding/hex"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381fp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/hash_to_curve"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/hash/tofield"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

func getMsgs() []string {
	return []string{"", "a", "ab", "abc", "abcd", "abcde", "abcdef", "abcdefg", "1", "2", "3", "4", "5", "5656565656565656565656565656565656565656565656565656565656565656"}
}

func getDst() []byte {
	dstHex := "412717974da474d0f8c420f320ff81e8432adb7c927d9bd082b4fb4d16c0a236"
	dst := make([]byte, len(dstHex)/2)
	hex.Decode(dst, []byte(dstHex))
	return dst
}

type hashToFieldCircuit struct {
	Msg []byte
	Dst []byte
	Res bls12381fp.Element
}

func (c *hashToFieldCircuit) Define(api frontend.API) error {
	msg := uints.NewU8Array(c.Msg)
	uniformBytes, _ := tofield.ExpandMsgXmd(api, msg, c.Dst, 64)
	fp, _ := emulated.NewField[emulated.BLS12381Fp](api)

	ele := bytesToElement(api, fp, uniformBytes)

	fp.AssertIsEqual(ele, fp.NewElement(c.Res))

	return nil
}

func TestHashToFieldTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	dst := getDst()

	for _, msg := range getMsgs() {

		rawEles, _ := bls12381fp.Hash([]byte(msg), dst, 1)

		circuit := hashToFieldCircuit{
			Msg: []byte(msg),
			Dst: dst,
			Res: rawEles[0],
		}
		witness := hashToFieldCircuit{
			Msg: []byte(msg),
			Dst: dst,
			Res: rawEles[0],
		}
		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
}

type mapToCurveCircuit struct {
	Msg []byte
	Dst []byte
	Res G2Affine
}

func (c *mapToCurveCircuit) Define(api frontend.API) error {
	msg := uints.NewU8Array(c.Msg)
	fp, _ := emulated.NewField[emulated.BLS12381Fp](api)
	g2, err := NewG2(api)
	if err != nil {
		return err
	}

	uniformBytes, _ := tofield.ExpandMsgXmd(api, msg, c.Dst, 128)
	ele1 := bytesToElement(api, fp, uniformBytes[:64])
	ele2 := bytesToElement(api, fp, uniformBytes[64:])
	e := fields_bls12381.E2{A0: *ele1, A1: *ele2}
	affine, err := g2.MapToCurve2(&e)
	if err != nil {
		return err
	}

	g2.AssertIsEqual(affine, &c.Res)

	return nil
}

func TestMapToCurveTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	dst := getDst()

	for _, msg := range getMsgs() {

		rawEles, _ := bls12381fp.Hash([]byte(msg), dst, 2)
		rawAffine := bls12381.MapToCurve2(&bls12381.E2{A0: rawEles[0], A1: rawEles[1]})
		wrappedRawAffine := NewG2Affine(rawAffine)

		circuit := mapToCurveCircuit{
			Msg: []byte(msg),
			Dst: dst,
			Res: wrappedRawAffine,
		}
		witness := mapToCurveCircuit{
			Msg: []byte(msg),
			Dst: dst,
			Res: wrappedRawAffine,
		}
		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
}

type MapToCurve2CircuitDirect struct {
	In       fields_bls12381.E2
	Expected G2Affine
}

func (c *MapToCurve2CircuitDirect) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return err
	}
	res, err := g2.MapToCurve2(&c.In)
	if err != nil {
		return err
	}
	g2.AssertIsEqual(res, &c.Expected)
	return nil
}

func TestMapToCurve2Direct(t *testing.T) {
	assert := test.NewAssert(t)
	var e2 bls12381.E2
	e2.A0.SetRandom()
	e2.A1.SetRandom()

	res := bls12381.MapToCurve2(&e2)

	assignment := MapToCurve2CircuitDirect{
		In:       fields_bls12381.FromE2(&e2),
		Expected: NewG2Affine(res),
	}
	err := test.IsSolved(&MapToCurve2CircuitDirect{}, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type TestG2IsogenyCircuit struct {
	In       G2Affine
	Expected G2Affine
}

func (c *TestG2IsogenyCircuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return err
	}
	res := g2.isogeny(&c.In)
	g2.AssertIsEqual(res, &c.Expected)
	return nil
}

func TestG2Isogeny(t *testing.T) {
	assert := test.NewAssert(t)
	_, in := randomG1G2Affines()
	var res bls12381.G2Affine
	res.Set(&in)
	hash_to_curve.G2Isogeny(&res.X, &res.Y)
	assignment := TestG2IsogenyCircuit{
		In:       NewG2Affine(in),
		Expected: NewG2Affine(res),
	}
	err := test.IsSolved(&TestG2IsogenyCircuit{}, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type clearCofactorCircuit struct {
	In  G2Affine
	Res G2Affine
}

func (c *clearCofactorCircuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return err
	}
	res := g2.ClearCofactor(&c.In)
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestClearCofactorTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	_, in := randomG1G2Affines()

	inAffine := NewG2Affine(in)

	in.ClearCofactor(&in)
	circuit := clearCofactorCircuit{
		In:  inAffine,
		Res: NewG2Affine(in),
	}
	witness := clearCofactorCircuit{
		In:  inAffine,
		Res: NewG2Affine(in),
	}
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type hashToG2Circuit struct {
	Msg []byte
	Dst []byte
	Res G2Affine
}

func (c *hashToG2Circuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return err
	}
	res, e := g2.HashToG2(uints.NewU8Array(c.Msg), c.Dst)
	if e != nil {
		return e
	}

	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func TestHashToG2TestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	dst := getDst()

	for _, msg := range getMsgs() {

		expected, _ := bls12381.HashToG2([]uint8(msg), dst)
		wrappedRes := NewG2Affine(expected)

		circuit := hashToG2Circuit{
			Msg: []uint8(msg),
			Dst: dst,
			Res: wrappedRes,
		}
		witness := hashToG2Circuit{
			Msg: []uint8(msg),
			Dst: dst,
			Res: wrappedRes,
		}
		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
}
