package sw_bls12381

import (
	"errors"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/conversion"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

var (
	ErrInvalidSizeEncodedX = errors.New("invalid number of bytes on the encoded point")
	halfP                  = "2001204777610833696708894912867952078278441409969503942666029068062015825245418932221343814564507832018947136279893"
)

// UnmarshalCompressed unmarshal a compressed point.
// See https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/11/.
// #constraints: 585600 when compiled on BN254, emulating BLS12-381 base field
func (g1 *G1) UnmarshalCompressed(compressedPoint []uints.U8) (*G1Affine, error) {

	// 1 - compute the x coordinate (so it fits in Fp)
	nbBytes := fp.Bytes
	uapi, err := uints.New[uints.U32](g1.api)
	if err != nil {
		return nil, err
	}
	mask := uints.NewU32(0x1FFFFFFF)   // mask = [0xFF, 0xFF, 0xFF, 0x1F]
	unmask := uints.NewU32(0xE0000000) // unmaks = ^mask
	firstFourBytes := uapi.PackMSB(
		compressedPoint[0],
		compressedPoint[1],
		compressedPoint[2],
		compressedPoint[3])
	firstFourBytesPrefix := uapi.And(unmask, firstFourBytes)
	firstFourBytesUnMasked := uapi.And(mask, firstFourBytes)
	unpackedFirstFourBytes := uapi.UnpackMSB(firstFourBytesUnMasked)
	unpackedFirstFourBytesPrefix := uapi.UnpackMSB(firstFourBytesPrefix)
	prefix := unpackedFirstFourBytesPrefix[0].Val
	unmaskedXCoord := make([]uints.U8, nbBytes)
	copy(unmaskedXCoord, unpackedFirstFourBytes)
	copy(unmaskedXCoord[4:], compressedPoint[4:])
	x, err := conversion.BytesToEmulated[BaseField](g1.api, unmaskedXCoord)
	if err != nil {
		return nil, err
	}

	// 1 - hint y coordinate of the result
	if len(compressedPoint) != nbBytes {
		return nil, ErrInvalidSizeEncodedX
	}
	rawBytesCompressedPoints := make([]frontend.Variable, nbBytes)
	for i := 0; i < nbBytes; i++ {
		rawBytesCompressedPoints[i] = compressedPoint[i].Val
	}
	yRawBytes, err := g1.api.NewHint(unmarshalHint, nbBytes, rawBytesCompressedPoints...)
	if err != nil {
		return nil, err
	}
	yMarshalled := make([]uints.U8, nbBytes)
	for i := 0; i < nbBytes; i++ {
		yMarshalled[i] = uapi.ByteValueOf(yRawBytes[i])
	}
	y, err := conversion.BytesToEmulated[BaseField](g1.api, yMarshalled)
	if err != nil {
		return nil, err
	}

	res := &G1Affine{
		X: *x,
		Y: *y,
	}

	// 3 - subgroup check

	// if the point is infinity, we do the subgroup check on the base point (otherwise the subgroup
	// check fails for (0,0) ). We check later on that the actual point is equal to (0,0).
	compressedInfinity := 0xc0 // b1100 0000
	isCompressedInfinity := g1.api.IsZero(g1.api.Sub(compressedInfinity, prefix))
	_, _, g, _ := bls12381.Generators()
	base := NewG1Affine(g)
	resTmpX := g1.curveF.Select(isCompressedInfinity, &base.X, x)
	resTmpY := g1.curveF.Select(isCompressedInfinity, &base.Y, y)
	resTmp := &G1Affine{
		X: *resTmpX,
		Y: *resTmpY,
	}
	g1.AssertIsOnG1(resTmp)

	// 4 - check logic with the mask

	// if p=O, we set P'=(0,0) and check equality, else we artificially set P'=P and check equality
	isInfinity := g1.api.IsZero(g1.api.Sub(compressedInfinity, prefix))
	zero := emulated.ValueOf[BaseField](0)
	infX := g1.curveF.Select(isInfinity, &zero, x)
	infY := g1.curveF.Select(isInfinity, &zero, y)
	g1.curveF.AssertIsEqual(infX, x)
	g1.curveF.AssertIsEqual(infY, y)

	// if we take the smallest y, then y < p/2. The constraint also works if p=0 and prefix=compressedInfinity
	emulatedHalfP := emulated.ValueOf[BaseField](halfP)
	compressedSmallest := 0x80
	isCompressedSmallest := g1.api.IsZero(g1.api.Sub(compressedSmallest, prefix))
	negY := g1.curveF.Neg(y)
	negY = g1.curveF.Reduce(negY)
	smallest := g1.curveF.Select(isCompressedSmallest, y, negY)
	g1.curveF.AssertIsLessOrEqual(smallest, &emulatedHalfP)

	// if we take the largest y, then -y < p/2. The constraint also works if p=0 and prefix=compressedInfinity
	compressedLargest := 0xa0
	isCompressedLargest := g1.api.IsZero(g1.api.Sub(compressedLargest, prefix))
	smallest = g1.curveF.Select(isCompressedLargest, negY, y)
	g1.curveF.AssertIsLessOrEqual(smallest, &emulatedHalfP)

	return res, nil
}
