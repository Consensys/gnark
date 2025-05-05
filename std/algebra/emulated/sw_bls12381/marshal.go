package sw_bls12381

import (
	"errors"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

var (
	ErrInvalidSizeEncodedX = errors.New("invalid number of bytes on the encoded point")
	halfP                  = "2001204777610833696708894912867952078278441409969503942666029068062015825245418932221343814564507832018947136279893"
)

// b is Marshalled following gnark-crypto marshall function, that is
// [MSB ... LSB]
// bitsFromU8 returns the bits of the element it represents, in little endian:
//
//		  b = [   0x..  , ..  ,    0x..    ]
//	   b' = [   0x..  , ..  ,    0x..    ] <- bitReverse(b)
//					 [ lsb..Msb||    ||  lsb..MSB ]
func bitsFromU8(api frontend.API, b []uints.U8) []frontend.Variable {

	nbBits := 8 * len(b)
	res := make([]frontend.Variable, nbBits)

	lb := len(b)
	for i := 0; i < len(b); i++ {
		buf := api.ToBinary(b[i].Val, 8)
		copy(res[8*(lb-1-i):8*(lb-i)], buf) // <- bit reverse op is done here
	}

	return res
}

// Unmarshall build the finite field element from its bytes representation.
// The byte representation follows the format of gnark-crypto's marshal function, that
// is [MSB || ... || LSB ]
// Should we move it elsewhere ?
// #constraints: 1772 when compiled on BN254, emulating BLS12-381 base field
func Unmarshall[F emulated.FieldParams](api frontend.API, b []uints.U8) (*emulated.Element[F], error) {

	emApi, err := emulated.NewField[F](api)
	if err != nil {
		return nil, err
	}

	bs := bitsFromU8(api, b)

	res := emApi.FromBits(bs...)

	return res, nil
}

// unmarshallHint
// inputs bytes of a compressed bls12381 point
// outputs bytes of the y coordinate of the decompressed point
func unmarshallHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {

	nbBytes := fp.Bytes
	xCoord := make([]byte, nbBytes)
	if len(inputs) != nbBytes {
		return ErrInvalidSizeEncodedX
	}
	for i := 0; i < nbBytes; i++ {
		tmp := inputs[i].Bytes()
		if len(tmp) == 0 {
			xCoord[i] = 0
		} else {
			xCoord[i] = tmp[len(tmp)-1] // tmp is in big endian
		}
	}

	var point bls12381.G1Affine
	_, err := point.SetBytes(xCoord)
	if err != nil {
		return err
	}

	// /!\ this step is needed because currently we can't mix
	// native and emulated elements in a hint
	yMarshalled := point.Y.Marshal()
	for i := 0; i < len(yMarshalled); i++ {
		outputs[i].SetBytes([]byte{yMarshalled[i]})
	}

	return nil
}

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
	x, err := Unmarshall[BaseField](g1.api, unmaskedXCoord)

	// 1 - hint y coordinate of the result
	if len(compressedPoint) != nbBytes {
		return nil, ErrInvalidSizeEncodedX
	}
	rawBytesCompressedPoints := make([]frontend.Variable, nbBytes)
	for i := 0; i < nbBytes; i++ {
		rawBytesCompressedPoints[i] = compressedPoint[i].Val
	}
	yRawBytes, err := g1.api.NewHint(unmarshallHint, nbBytes, rawBytesCompressedPoints...)
	if err != nil {
		return nil, err
	}
	yMarshalled := make([]uints.U8, nbBytes)
	for i := 0; i < nbBytes; i++ {
		yMarshalled[i] = uapi.ByteValueOf(yRawBytes[i])
	}
	y, err := Unmarshall[BaseField](g1.api, yMarshalled)

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
