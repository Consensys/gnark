package sw_bls12381

import (
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/conversion"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	mMask                 byte = 0b111 << 5
	mUncompressed         byte = 0b000 << 5
	_                     byte = 0b001 << 5 // invalid
	mUncompressedInfinity byte = 0b010 << 5
	_                     byte = 0b011 << 5 // invalid
	mCompressedSmallest   byte = 0b100 << 5
	mCompressedLargest    byte = 0b101 << 5
	mCompressedInfinity   byte = 0b110 << 5
	_                     byte = 0b111 << 5 // invalid
)

// UnmarshalCompressed unmarshals a compressed point in G1. See [pairing
// friendly curves IETF draft] for the details of the encoding.
//
// We assume that the input is a valid compressed point. The length of the input
// must be 48 bytes (but we keep it as a slice for future compatibility with
// interfaces).
//
// The method supports the following compressed point formats:
//   - compressed regular point, with y lexicographically smallest (header 0b100<<5)
//   - compressed regular point, with y lexicographically largest (header 0b101<<5)
//   - compressed point at infinity (header 0b110<<5).
//
// Particulary, the method DOES NOT support uncompressed points (header
// 0b000<<5) and uncompressed points at infinity (header 0b010<<5).
//
// The method performs curve membership check and subgroup membership check.
//
// [pairing friendly curves IETF draft]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/11/.
func (g1 *G1) UnmarshalCompressed(compressedPoint []uints.U8) (*G1Affine, error) {
	// for future compatibility (adding method to the [algebra.Pairing]
	// interface) we haven't set the method signature to be [48]uints.U8, but
	// rather a slice. Thus we need to check the length of the input.
	if len(compressedPoint) != bls12381.SizeOfG1AffineCompressed {
		return nil, fmt.Errorf("compressed point must be %d bytes, got %d", bls12381.SizeOfG1AffineCompressed, len(compressedPoint))
	}
	// 1 - compute the x coordinate (so it fits in Fp)
	nbBytes := fp.Bytes
	uapi, err := uints.NewBytes(g1.api)
	if err != nil {
		return nil, fmt.Errorf("new uints api: %w", err)
	}
	unmask := uints.NewU8(mMask)                   // unmaks = ^mask
	prefix := uapi.And(unmask, compressedPoint[0]) // prefix = compressedPoint[0] & unmask

	// first we remove the prefix from the first byte. The prefix indicates if
	// the input is compressed and point at infinity. It also indicates the sign
	// of the y coordinate. The prefix is first three bits 0b11100000=0xE0. So to get
	// unprefixed x coordinate, we need to mask the first byte with 0x1F = ^0xE0.
	mask := uints.NewU8(^mMask)                     // mask = [0x1F]
	firstByte := uapi.And(mask, compressedPoint[0]) // firstByte = compressedPoint[0] & mask
	unmaskedXCoord := make([]uints.U8, nbBytes)
	unmaskedXCoord[0] = firstByte
	copy(unmaskedXCoord[1:], compressedPoint[1:])
	x, err := conversion.BytesToEmulated[BaseField](g1.api, unmaskedXCoord)
	if err != nil {
		return nil, fmt.Errorf("bytes to emulated: %w", err)
	}

	// 1 - hint y coordinate of the result
	rawBytesCompressedPoints := make([]frontend.Variable, nbBytes)
	for i := range nbBytes {
		rawBytesCompressedPoints[i] = compressedPoint[i].Val
	}
	hout, err := g1.curveF.NewHintWithNativeInput(unmarshalG1, 1, rawBytesCompressedPoints...)
	if err != nil {
		return nil, fmt.Errorf("unmarshal hint: %w", err)
	}
	y := hout[0]
	res := &G1Affine{X: *x, Y: *y}

	// 3 - subgroup check

	// if the point is infinity, we do the subgroup check on the base point (otherwise the subgroup
	// check fails for (0,0) ). We check later on that the actual point is equal to (0,0).
	isCompressedInfinity := g1.api.IsZero(g1.api.Sub(mCompressedInfinity, prefix.Val))
	_, _, g, _ := bls12381.Generators()
	base := NewG1Affine(g)
	resTmpX := g1.curveF.Select(isCompressedInfinity, &base.X, x)
	resTmpY := g1.curveF.Select(isCompressedInfinity, &base.Y, y)
	resTmp := &G1Affine{X: *resTmpX, Y: *resTmpY}
	g1.AssertIsOnG1(resTmp)

	// 4 - check logic with the mask

	// if p=O, we set P'=(0,0) and check equality, else we artificially set P'=P and check equality
	isInfinity := g1.api.IsZero(g1.api.Sub(mCompressedInfinity, prefix.Val))
	zero := emulated.ValueOf[BaseField](0)
	infX := g1.curveF.Select(isInfinity, &zero, x)
	infY := g1.curveF.Select(isInfinity, &zero, y)
	g1.curveF.AssertIsEqual(infX, x)
	g1.curveF.AssertIsEqual(infY, y)

	// if we take the smallest y, then y < p/2. The constraint also works if p=0 and prefix=compressedInfinity
	isCompressedSmallest := g1.api.IsZero(g1.api.Sub(mCompressedSmallest, prefix.Val))
	negY := g1.curveF.Neg(y)
	negY = g1.curveF.Reduce(negY)
	smallest := g1.curveF.Select(isCompressedSmallest, y, negY)
	g1.curveF.AssertIsLessOrEqual(smallest, g1.halfp)

	// if we take the largest y, then -y < p/2. The constraint also works if p=0 and prefix=compressedInfinity
	isCompressedLargest := g1.api.IsZero(g1.api.Sub(mCompressedLargest, prefix.Val))
	smallest = g1.curveF.Select(isCompressedLargest, negY, y)
	g1.curveF.AssertIsLessOrEqual(smallest, g1.halfp)

	return res, nil
}
