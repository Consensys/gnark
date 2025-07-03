package sw_bls12381

import (
	"errors"
	"fmt"
	"math/big"
	"slices"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fp_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// G1Affine is the point in G1. It is an alias to the generic emulated affine
// point.
type G1Affine = sw_emulated.AffinePoint[BaseField]

// Scalar is the scalar in the groups. It is an alias to the emulated element
// defined over the scalar field of the groups.
type Scalar = emulated.Element[ScalarField]

var (
	ErrInvalidSizeEncodedX = errors.New("invalid number of bytes on the encoded point")

	halfP = "2001204777610833696708894912867952078278441409969503942666029068062015825245418932221343814564507832018947136279893"
)

// NewG1Affine allocates a witness from the native G1 element and returns it.
func NewG1Affine(v bls12381.G1Affine) G1Affine {
	return G1Affine{
		X: emulated.ValueOf[BaseField](v.X),
		Y: emulated.ValueOf[BaseField](v.Y),
	}
}

type G1 struct {
	api    frontend.API
	curveF *emulated.Field[BaseField]
	w      *emulated.Element[BaseField]
}

func NewG1(api frontend.API) (*G1, error) {
	ba, err := emulated.NewField[BaseField](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	w := ba.NewElement("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436")
	return &G1{
		api:    api,
		curveF: ba,
		w:      w,
	}, nil
}

func (g1 *G1) ToCompressedBytes(p G1Affine, opts ...algopts.AlgebraOption) ([]uints.U8, error) {
	nbBytes := fp_bls12381.Bytes
	uapi, err := uints.New[uints.U32](g1.api)
	if err != nil {
		return nil, err
	}
	xBytes, err := Marshal[BaseField](g1.api, &p.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := Marshal[BaseField](g1.api, &p.Y)
	if err != nil {
		return nil, err
	}
	// Compute masked 4 bytes
	rawBytes := make([]frontend.Variable, 2*nbBytes)
	for i := 0; i < nbBytes; i++ {
		rawBytes[i] = xBytes[nbBytes-i-1].Val
	}
	for i := 0; i < nbBytes; i++ {
		rawBytes[nbBytes+i] = yBytes[nbBytes-i-1].Val
	}
	bytes, err := g1.api.NewHint(g1MarshalMaskHint, 4, rawBytes...)
	if err != nil {
		return nil, err
	}
	// Verify mask
	mask := uints.NewU32(0x1FFFFFFF)   // mask = [0xFF, 0xFF, 0xFF, 0x1F]
	unmask := uints.NewU32(0xE0000000) // unmaks = ^mask
	firstFourBytes := uapi.PackMSB(
		uapi.ByteValueOf(bytes[0]),
		uapi.ByteValueOf(bytes[1]),
		uapi.ByteValueOf(bytes[2]),
		uapi.ByteValueOf(bytes[3]),
	)
	firstFourBytesUnMasked := uapi.And(mask, firstFourBytes)
	unpackedFirstFourBytes := uapi.UnpackMSB(firstFourBytesUnMasked)
	for i := 0; i < 4; i++ {
		g1.api.AssertIsEqual(unpackedFirstFourBytes[i].Val, xBytes[nbBytes-i-1].Val)
	}
	// Verify flags
	firstFourBytesPrefix := uapi.And(unmask, firstFourBytes)
	unpackedFirstFourBytesPrefix := uapi.UnpackMSB(firstFourBytesPrefix)
	prefix := unpackedFirstFourBytesPrefix[0].Val

	// if p=O, we set P'=(0,0) and check equality, else we artificially set P'=P and check equality
	compressedInfinity := 0xc0 // b1100 0000
	isInfinity := g1.api.IsZero(g1.api.Sub(compressedInfinity, prefix))
	zero := emulated.ValueOf[BaseField](0)
	infX := g1.curveF.Select(isInfinity, &zero, &p.X)
	infY := g1.curveF.Select(isInfinity, &zero, &p.Y)
	g1.curveF.AssertIsEqual(infX, &p.X)
	g1.curveF.AssertIsEqual(infY, &p.Y)

	// if we take the smallest y, then y < p/2. The constraint also works if p=0 and prefix=compressedInfinity
	emulatedHalfP := emulated.ValueOf[BaseField](halfP)
	compressedSmallest := 0x80
	isCompressedSmallest := g1.api.IsZero(g1.api.Sub(compressedSmallest, prefix))
	negY := g1.curveF.Neg(&p.Y)
	negY = g1.curveF.Reduce(negY)
	smallest := g1.curveF.Select(isCompressedSmallest, &p.Y, negY)
	g1.curveF.AssertIsLessOrEqual(smallest, &emulatedHalfP)

	// if we take the largest y, then -y < p/2. The constraint also works if p=0 and prefix=compressedInfinity
	compressedLargest := 0xa0
	isCompressedLargest := g1.api.IsZero(g1.api.Sub(compressedLargest, prefix))
	smallest = g1.curveF.Select(isCompressedLargest, negY, &p.Y)
	g1.curveF.AssertIsLessOrEqual(smallest, &emulatedHalfP)

	// Construct response
	res := make([]uints.U8, nbBytes)
	copy(res, xBytes)
	slices.Reverse(res)
	copy(res[:4], uapi.UnpackMSB(firstFourBytes))
	return res, nil
}

func (g1 *G1) FromCompressedBytes(bytes []uints.U8, opts ...algopts.AlgebraOption) (*G1Affine, error) {
	// 1 - compute the x coordinate (so it fits in Fp)
	nbBytes := fp_bls12381.Bytes
	uapi, err := uints.New[uints.U32](g1.api)
	if err != nil {
		return nil, err
	}
	mask := uints.NewU32(0x1FFFFFFF)   // mask = [0xFF, 0xFF, 0xFF, 0x1F]
	unmask := uints.NewU32(0xE0000000) // unmaks = ^mask
	firstFourBytes := uapi.PackMSB(
		bytes[0],
		bytes[1],
		bytes[2],
		bytes[3],
	)
	firstFourBytesPrefix := uapi.And(unmask, firstFourBytes)
	firstFourBytesUnMasked := uapi.And(mask, firstFourBytes)
	unpackedFirstFourBytes := uapi.UnpackMSB(firstFourBytesUnMasked)
	unpackedFirstFourBytesPrefix := uapi.UnpackMSB(firstFourBytesPrefix)
	prefix := unpackedFirstFourBytesPrefix[0].Val
	unmaskedXCoord := make([]uints.U8, nbBytes)
	copy(unmaskedXCoord, unpackedFirstFourBytes)
	copy(unmaskedXCoord[4:], bytes[4:])
	x, err := Unmarshal[BaseField](g1.api, unmaskedXCoord)
	if err != nil {
		return nil, err
	}

	// 2 - hint y coordinate of the result
	if len(bytes) != nbBytes {
		return nil, ErrInvalidSizeEncodedX
	}
	rawBytesCompressedPoints := make([]frontend.Variable, nbBytes)
	for i := 0; i < nbBytes; i++ {
		rawBytesCompressedPoints[i] = bytes[i].Val
	}
	yRawBytes, err := g1.api.NewHint(g1UnmarshalHint, nbBytes, rawBytesCompressedPoints...)
	if err != nil {
		return nil, err
	}
	yMarshalled := make([]uints.U8, nbBytes)
	for i := 0; i < nbBytes; i++ {
		yMarshalled[i] = uapi.ByteValueOf(yRawBytes[i])
	}
	y, err := Unmarshal[BaseField](g1.api, yMarshalled)
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

func (g1 G1) neg(p *G1Affine) *G1Affine {
	xr := &p.X
	yr := g1.curveF.Neg(&p.Y)
	return &G1Affine{
		X: *xr,
		Y: *yr,
	}
}

func (g1 *G1) phi(q *G1Affine) *G1Affine {
	x := g1.curveF.Mul(&q.X, g1.w)

	return &G1Affine{
		X: *x,
		Y: q.Y,
	}
}

func (g1 *G1) double(p *G1Affine) *G1Affine {
	mone := g1.curveF.NewElement(-1)
	// compute λ = (3p.x²)/2*p.y
	xx3a := g1.curveF.Mul(&p.X, &p.X)
	xx3a = g1.curveF.MulConst(xx3a, big.NewInt(3))
	y1 := g1.curveF.MulConst(&p.Y, big.NewInt(2))
	λ := g1.curveF.Div(xx3a, y1)

	// xr = λ²-2p.x
	xr := g1.curveF.Eval([][]*baseEl{{λ, λ}, {mone, &p.X}}, []int{1, 2})

	// yr = λ(p-xr) - p.y
	yr := g1.curveF.Eval([][]*baseEl{{λ, g1.curveF.Sub(&p.X, xr)}, {mone, &p.Y}}, []int{1, 1})

	return &G1Affine{
		X: *xr,
		Y: *yr,
	}
}

func (g1 *G1) doubleN(p *G1Affine, n int) *G1Affine {
	pn := p
	for s := 0; s < n; s++ {
		pn = g1.double(pn)
	}
	return pn
}

func (g1 G1) add(p, q *G1Affine) *G1Affine {
	mone := g1.curveF.NewElement(-1)
	// compute λ = (q.y-p.y)/(q.x-p.x)
	qypy := g1.curveF.Sub(&q.Y, &p.Y)
	qxpx := g1.curveF.Sub(&q.X, &p.X)
	λ := g1.curveF.Div(qypy, qxpx)

	// xr = λ²-p.x-q.x
	xr := g1.curveF.Eval([][]*baseEl{{λ, λ}, {mone, g1.curveF.Add(&p.X, &q.X)}}, []int{1, 1})

	// p.y = λ(p.x-xr) - p.y
	yr := g1.curveF.Eval([][]*baseEl{{λ, g1.curveF.Sub(&p.X, xr)}, {mone, &p.Y}}, []int{1, 1})

	return &G1Affine{
		X: *xr,
		Y: *yr,
	}
}

func (g1 G1) doubleAndAdd(p, q *G1Affine) *G1Affine {

	mone := g1.curveF.NewElement(-1)
	// compute λ1 = (q.y-p.y)/(q.x-p.x)
	yqyp := g1.curveF.Sub(&q.Y, &p.Y)
	xqxp := g1.curveF.Sub(&q.X, &p.X)
	λ1 := g1.curveF.Div(yqyp, xqxp)

	// compute x1 = λ1²-p.x-q.x
	x2 := g1.curveF.Eval([][]*baseEl{{λ1, λ1}, {mone, g1.curveF.Add(&p.X, &q.X)}}, []int{1, 1})

	// omit y2 computation

	// compute -λ2 = λ1+2*p.y/(x2-p.x)
	ypyp := g1.curveF.MulConst(&p.Y, big.NewInt(2))
	x2xp := g1.curveF.Sub(x2, &p.X)
	λ2 := g1.curveF.Div(ypyp, x2xp)
	λ2 = g1.curveF.Add(λ1, λ2)

	// compute x3 = (-λ2)²-p.x-x2
	x3 := g1.curveF.Eval([][]*baseEl{{λ2, λ2}, {mone, &p.X}, {mone, x2}}, []int{1, 1, 1})

	// compute y3 = -λ2*(x3- p.x)-p.y
	y3 := g1.curveF.Eval([][]*baseEl{{λ2, g1.curveF.Sub(x3, &p.X)}, {mone, &p.Y}}, []int{1, 1})

	return &G1Affine{
		X: *x3,
		Y: *y3,
	}
}

func (g1 *G1) scalarMulBySeedSquare(q *G1Affine) *G1Affine {
	z := g1.double(q)
	z = g1.add(q, z)
	z = g1.double(z)
	z = g1.doubleAndAdd(z, q)
	z = g1.doubleN(z, 2)
	z = g1.doubleAndAdd(z, q)
	z = g1.doubleN(z, 8)
	z = g1.doubleAndAdd(z, q)
	t0 := g1.double(z)
	t0 = g1.add(z, t0)
	t0 = g1.double(t0)
	t0 = g1.doubleAndAdd(t0, z)
	t0 = g1.doubleN(t0, 2)
	t0 = g1.doubleAndAdd(t0, z)
	t0 = g1.doubleN(t0, 8)
	t0 = g1.doubleAndAdd(t0, z)
	t0 = g1.doubleN(t0, 31)
	z = g1.add(t0, z)
	z = g1.doubleN(z, 32)
	z = g1.doubleAndAdd(z, q)
	z = g1.doubleN(z, 32)

	return z
}

func (g1 *G1) computeCurveEquation(P *G1Affine) (left, right *baseEl) {
	// Curve: Y² == X³ + aX + b, where a=0 and b=4
	// (X,Y) ∈ {Y² == X³ + aX + b} U (0,0)

	// if P=(0,0) we assign b=0 otherwise 4, and continue
	selector := g1.api.And(g1.curveF.IsZero(&P.X), g1.curveF.IsZero(&P.Y))
	four := g1.curveF.NewElement("4")
	b := g1.curveF.Select(selector, g1.curveF.Zero(), four)

	left = g1.curveF.Mul(&P.Y, &P.Y)
	right = g1.curveF.Eval([][]*emulated.Element[BaseField]{{&P.X, &P.X, &P.X}, {b}}, []int{1, 1})
	return left, right
}

func (g1 *G1) AssertIsOnCurve(P *G1Affine) {
	left, right := g1.computeCurveEquation(P)
	g1.curveF.AssertIsEqual(left, right)
}

func (g1 *G1) AssertIsOnG1(P *G1Affine) {
	// 1- Check P is on the curve
	g1.AssertIsOnCurve(P)

	// 2- Check P has the right subgroup order
	// [x²]ϕ(P)
	phiP := g1.phi(P)
	_P := g1.scalarMulBySeedSquare(phiP)
	_P = g1.neg(_P)

	// [r]Q == 0 <==>  P = -[x²]ϕ(P)
	g1.AssertIsEqual(_P, P)
}

// AssertIsEqual asserts that p and q are the same point.
func (g1 *G1) AssertIsEqual(p, q *G1Affine) {
	g1.curveF.AssertIsEqual(&p.X, &q.X)
	g1.curveF.AssertIsEqual(&p.Y, &q.Y)
}

func (g1 *G1) IsEqual(p, q *G1Affine) frontend.Variable {
	xDiff := g1.curveF.Sub(&p.X, &q.X)
	yDiff := g1.curveF.Sub(&p.Y, &q.Y)
	xIsZero := g1.curveF.IsZero(xDiff)
	yIsZero := g1.curveF.IsZero(yDiff)
	return g1.api.And(xIsZero, yIsZero)
}

// NewScalar allocates a witness from the native scalar and returns it.
func NewScalar(v fr_bls12381.Element) Scalar {
	return emulated.ValueOf[ScalarField](v)
}

// ScalarField is the [emulated.FieldParams] implementation of the curve scalar field.
type ScalarField = emulated.BLS12381Fr

// BaseField is the [emulated.FieldParams] implementation of the curve base field.
type BaseField = emulated.BLS12381Fp
