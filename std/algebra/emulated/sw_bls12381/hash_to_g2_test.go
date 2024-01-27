package sw_bls12381

import (
	"encoding/hex"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381fp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/hash/tofield"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

func getMsgs() []string {
	return []string{"", "a", "ab", "abc", "abcd", "abcde", "abcdef", "abcdefg", "1", "2", "3", "4", "5"}
}

func getDst() []byte {
	dstHex := "412717974da474d0f8c420f320ff81e8432adb7c927d9bd082b4fb4d16c0a236"
	dst := make([]byte, len(dstHex)/2)
	hex.Decode(dst, []byte(dstHex))
	return dst
}

type hashToFieldCircuit struct {
	msg []byte
	dst []byte
}

func (c *hashToFieldCircuit) Define(api frontend.API) error {
	msg := uints.NewU8Array(c.msg)
	uniformBytes, _ := tofield.ExpandMsgXmd(api, msg, c.dst, 64)
	fp, _ := emulated.NewField[emulated.BLS12381Fp](api)

	ele := bytesToElement(api, fp, uniformBytes)

	rawEles, _ := bls12381fp.Hash(c.msg, c.dst, 1)
	wrappedEle := fp.NewElement(rawEles[0])

	fp.AssertIsEqual(ele, wrappedEle)

	return nil
}

func TestHashToFieldTestSolve(t *testing.T) {
	assert := test.NewAssert(t)

	for _, msg := range getMsgs() {

		witness := hashToFieldCircuit{
			msg: []byte(msg),
			dst: getDst(),
		}
		err := test.IsSolved(&hashToFieldCircuit{}, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
}

type mapToCurveCircuit struct {
	msg []byte
	dst []byte
}

func (c *mapToCurveCircuit) Define(api frontend.API) error {
	msg := uints.NewU8Array(c.msg)
	uniformBytes, _ := tofield.ExpandMsgXmd(api, msg, c.dst, 128)
	fp, _ := emulated.NewField[emulated.BLS12381Fp](api)
	ext2 := fields_bls12381.NewExt2(api)
	mapper := newMapper(api, ext2, fp)

	ele1 := bytesToElement(api, fp, uniformBytes[:64])
	ele2 := bytesToElement(api, fp, uniformBytes[64:])
	e := fields_bls12381.E2{A0: *ele1, A1: *ele2}
	affine := mapper.mapToCurve(e)

	rawEles, _ := bls12381fp.Hash(c.msg, c.dst, 2)
	rawAffine := bls12381.MapToCurve2(&bls12381.E2{A0: rawEles[0], A1: rawEles[1]})
	wrappedRawAffine := NewG2Affine(rawAffine)

	g2 := NewG2(api)
	g2.AssertIsEqual(affine, &wrappedRawAffine)

	return nil
}

func TestMapToCurveTestSolve(t *testing.T) {
	assert := test.NewAssert(t)

	for _, msg := range getMsgs() {

		witness := hashToFieldCircuit{
			msg: []byte(msg),
			dst: getDst(),
		}
		err := test.IsSolved(&mapToCurveCircuit{}, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
}

type clearCofactorCircuit struct {
	In  G2Affine
	Res G2Affine
}

func (c *clearCofactorCircuit) Define(api frontend.API) error {
	g2 := NewG2(api)
	fp, _ := emulated.NewField[emulated.BLS12381Fp](api)
	res := clearCofactor(g2, fp, &c.In)
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
	msg []byte
	dst []byte
}

func (c *hashToG2Circuit) Define(api frontend.API) error {
	res, e := HashToG2(api, uints.NewU8Array(c.msg), c.dst)
	if e != nil {
		return e
	}

	expected, _ := bls12381.HashToG2(c.msg, c.dst)
	wrappedRes := NewG2Affine(expected)

	g2 := NewG2(api)
	g2.AssertIsEqual(res, &wrappedRes)
	return nil
}

func TestHashToG2TestSolve(t *testing.T) {
	assert := test.NewAssert(t)

	for _, msg := range getMsgs() {

		witness := hashToG2Circuit{
			msg: []uint8(msg),
			dst: getDst(),
		}
		err := test.IsSolved(&hashToG2Circuit{}, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
}
