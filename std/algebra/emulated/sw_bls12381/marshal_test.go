package sw_bls12381

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	fp_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

type unmarshalPoint struct {
	CP []uints.U8
	P  G1Affine
}

func (c *unmarshalPoint) Define(api frontend.API) error {
	g, err := NewG1(api)
	if err != nil {
		return fmt.Errorf("new G1: %w", err)
	}

	point, err := g.UnmarshalCompressed(c.CP)
	if err != nil {
		return fmt.Errorf("unmarshal compressed: %w", err)
	}
	g.AssertIsEqual(point, &c.P)
	return nil
}

func TestUnmarshalPoint(t *testing.T) {
	assert := test.NewAssert(t)

	// -- valid cases
	//  - compressed point, smallest y coordinate
	assert.Run(func(assert *test.Assert) {
		var p bls12381.G1Affine
		var s fr_bls12381.Element
		b := new(big.Int)
		_, _, g, _ := bls12381.Generators()
		for {
			s.MustSetRandom()
			p.ScalarMultiplication(&g, s.BigInt(b))
			if !p.Y.LexicographicallyLargest() {
				break
			}
		}
		pMarshalled := p.Bytes()
		assert.CheckCircuit(
			&unmarshalPoint{CP: make([]uints.U8, bls12381.SizeOfG1AffineCompressed)},
			test.WithValidAssignment(&unmarshalPoint{CP: uints.NewU8Array(pMarshalled[:]), P: NewG1Affine(p)}))
	}, "case=valid/small-y")
	//  - compressed point, largest y coordinate
	assert.Run(func(assert *test.Assert) {
		var p bls12381.G1Affine
		var s fr_bls12381.Element
		b := new(big.Int)
		_, _, g, _ := bls12381.Generators()
		for {
			s.MustSetRandom()
			p.ScalarMultiplication(&g, s.BigInt(b))
			if p.Y.LexicographicallyLargest() {
				break
			}
		}
		pMarshalled := p.Bytes()
		assert.CheckCircuit(
			&unmarshalPoint{CP: make([]uints.U8, bls12381.SizeOfG1AffineCompressed)},
			test.WithValidAssignment(&unmarshalPoint{CP: uints.NewU8Array(pMarshalled[:]), P: NewG1Affine(p)}))
	}, "case=valid/large-y")
	//  - compressed point, infinity
	assert.Run(func(assert *test.Assert) {
		var p bls12381.G1Affine
		p.SetInfinity()
		pMarshalled := p.Bytes()
		assert.CheckCircuit(
			&unmarshalPoint{CP: make([]uints.U8, bls12381.SizeOfG1AffineCompressed)},
			test.WithValidAssignment(&unmarshalPoint{CP: uints.NewU8Array(pMarshalled[:]), P: NewG1Affine(p)}))
	}, "case=valid/infinity")

	// -- invalid cases:
	//  - compressed point, have smallest y coordinate but mask for largest y coordinate
	assert.Run(func(assert *test.Assert) {
		var p bls12381.G1Affine
		var s fr_bls12381.Element
		b := new(big.Int)
		_, _, g, _ := bls12381.Generators()
		for {
			s.MustSetRandom()
			p.ScalarMultiplication(&g, s.BigInt(b))
			if !p.Y.LexicographicallyLargest() {
				break
			}
		}
		pMarshalled := p.Bytes()
		// check that mask is what we expect
		assert.Equal(mCompressedSmallest, pMarshalled[0]&mMask, "mask should be for smallest y coordinate")
		// swap out the mask
		pMarshalled[0] = (pMarshalled[0] &^ mMask) | mCompressedLargest // modify the mask
		assert.CheckCircuit(
			&unmarshalPoint{CP: make([]uints.U8, bls12381.SizeOfG1AffineCompressed)},
			test.WithInvalidAssignment(&unmarshalPoint{CP: uints.NewU8Array(pMarshalled[:]), P: NewG1Affine(p)}),
		)
	}, "case=invalid/small-y-mask-large-y")
	//  - compressed point, have largest y coordinate but mask for smallest y coordinate
	assert.Run(func(assert *test.Assert) {
		var p bls12381.G1Affine
		var s fr_bls12381.Element
		b := new(big.Int)
		_, _, g, _ := bls12381.Generators()
		for {
			s.MustSetRandom()
			p.ScalarMultiplication(&g, s.BigInt(b))
			if p.Y.LexicographicallyLargest() {
				break
			}
		}
		pMarshalled := p.Bytes()
		// check that mask is what we expect
		assert.Equal(mCompressedLargest, pMarshalled[0]&mMask, "mask should be for largest y coordinate")
		// swap out the mask
		pMarshalled[0] = (pMarshalled[0] &^ mMask) | mCompressedSmallest // modify the mask
		assert.CheckCircuit(
			&unmarshalPoint{CP: make([]uints.U8, bls12381.SizeOfG1AffineCompressed)},
			test.WithInvalidAssignment(&unmarshalPoint{CP: uints.NewU8Array(pMarshalled[:]), P: NewG1Affine(p)}),
		)
	}, "case=invalid/large-y-mask-small-y")
	//  - compressed point, have mask for infinity but not infinity
	assert.Run(func(assert *test.Assert) {
		var p bls12381.G1Affine
		var s fr_bls12381.Element
		b := new(big.Int)
		_, _, g, _ := bls12381.Generators()
		s.MustSetRandom()
		p.ScalarMultiplication(&g, s.BigInt(b))
		pMarshalled := p.Bytes()
		// check that mask is what we expect
		assert.Equal(byte(0b100)<<5, pMarshalled[0]&(0b110<<5), "mask should be for compressed point")
		// swap out the mask
		pMarshalled[0] = (pMarshalled[0] &^ mMask) | mCompressedInfinity // modify the mask
		assert.CheckCircuit(
			&unmarshalPoint{CP: make([]uints.U8, bls12381.SizeOfG1AffineCompressed)},
			test.WithInvalidAssignment(&unmarshalPoint{CP: uints.NewU8Array(pMarshalled[:]), P: NewG1Affine(p)}),
		)
	}, "case=invalid/infinity-mask-not-infinity")
	//  - compressed point, mask for smallest y coordinate but point at infinity
	assert.Run(func(assert *test.Assert) {
		var p bls12381.G1Affine
		p.SetInfinity()
		pMarshalled := p.Bytes()
		// check that mask is what we expect
		assert.Equal(mCompressedInfinity, pMarshalled[0]&mMask, "mask should be compressed infinity")
		// swap out the mask
		pMarshalled[0] = (pMarshalled[0] &^ mMask) | mCompressedSmallest // modify the mask
		assert.CheckCircuit(
			&unmarshalPoint{CP: make([]uints.U8, bls12381.SizeOfG1AffineCompressed)},
			test.WithInvalidAssignment(&unmarshalPoint{CP: uints.NewU8Array(pMarshalled[:]), P: NewG1Affine(p)}),
		)
	}, "case=invalid/infinity-mask-smallest-y")
	//  - compressed point, mask for largest y coordinate but point at infinity
	assert.Run(func(assert *test.Assert) {
		var p bls12381.G1Affine
		p.SetInfinity()
		pMarshalled := p.Bytes()
		// check that mask is what we expect
		assert.Equal(mCompressedInfinity, pMarshalled[0]&mMask, "mask should be compressed infinity")
		// swap out the mask
		pMarshalled[0] = (pMarshalled[0] &^ mMask) | mCompressedLargest // modify the mask
		assert.CheckCircuit(
			&unmarshalPoint{CP: make([]uints.U8, bls12381.SizeOfG1AffineCompressed)},
			test.WithInvalidAssignment(&unmarshalPoint{CP: uints.NewU8Array(pMarshalled[:]), P: NewG1Affine(p)}),
		)
	}, "case=invalid/infinity-mask-large-y")
	//  - compressed point, not in group
	assert.Run(func(assert *test.Assert) {
		var p bls12381.G1Affine
		var s fp_bls12381.Element
		s.MustSetRandom()
		pj := bls12381.GeneratePointNotInG1(s)
		p.FromJacobian(&pj)
		pMarshalled := p.Bytes()
		// check that mask is what we expect
		assert.Equal(byte(0b100)<<5, pMarshalled[0]&(0b110<<5), "mask should be compressed regular")
		assert.CheckCircuit(
			&unmarshalPoint{CP: make([]uints.U8, bls12381.SizeOfG1AffineCompressed)},
			test.WithInvalidAssignment(&unmarshalPoint{CP: uints.NewU8Array(pMarshalled[:]), P: NewG1Affine(p)}),
		)
	}, "case=invalid/not-in-group")
	//  - compressed point, not on curve
	assert.Run(func(assert *test.Assert) {
		var p bls12381.G1Affine
		for {
			p.X.SetRandom()
			p.Y.SetRandom()
			if !p.IsOnCurve() {
				break
			}
		}
		pMarshalled := p.Bytes()
		// check that mask is what we expect
		assert.Equal(byte(0b100)<<5, pMarshalled[0]&(0b110<<5), "mask should be compressed regular")
		assert.CheckCircuit(
			&unmarshalPoint{CP: make([]uints.U8, bls12381.SizeOfG1AffineCompressed)},
			test.WithInvalidAssignment(&unmarshalPoint{CP: uints.NewU8Array(pMarshalled[:]), P: NewG1Affine(p)}),
		)
	}, "case=invalid/not-on-curve")

	// -- invalid mask
	// - uncompressed 0b000 << 5, point random
	assert.Run(func(assert *test.Assert) {
		var p bls12381.G1Affine
		var s fr_bls12381.Element
		b := new(big.Int)
		_, _, g, _ := bls12381.Generators()
		s.MustSetRandom()
		p.ScalarMultiplication(&g, s.BigInt(b))
		pMarshalled := p.Bytes()
		// check that mask is what we expect
		assert.Equal(byte(0b100)<<5, pMarshalled[0]&(0b110<<5), "mask should be compressed regular")
		// swap out the mask
		pMarshalled[0] = (pMarshalled[0] &^ mMask) | mUncompressed // modify the mask
		assert.CheckCircuit(
			&unmarshalPoint{CP: make([]uints.U8, bls12381.SizeOfG1AffineCompressed)},
			test.WithInvalidAssignment(&unmarshalPoint{CP: uints.NewU8Array(pMarshalled[:]), P: NewG1Affine(p)}),
		)
	}, "case=invalid/uncompressed-random")
	// - uncompressed 0b000 << 5, point infinity
	assert.Run(func(assert *test.Assert) {
		var p bls12381.G1Affine
		p.SetInfinity()
		pMarshalled := p.Bytes()
		// check that mask is what we expect
		assert.Equal(mCompressedInfinity, pMarshalled[0]&mMask, "mask should be compressed infinity")
		// swap out the mask
		pMarshalled[0] = (pMarshalled[0] &^ mMask) | mUncompressed // modify the mask
		assert.CheckCircuit(
			&unmarshalPoint{CP: make([]uints.U8, bls12381.SizeOfG1AffineCompressed)},
			test.WithInvalidAssignment(&unmarshalPoint{CP: uints.NewU8Array(pMarshalled[:]), P: NewG1Affine(p)}),
		)
	}, "case=invalid/uncompressed-infinity")
	// - uncompressed infinity 0b010 << 5, point random
	assert.Run(func(assert *test.Assert) {
		var p bls12381.G1Affine
		var s fr_bls12381.Element
		b := new(big.Int)
		_, _, g, _ := bls12381.Generators()
		s.MustSetRandom()
		p.ScalarMultiplication(&g, s.BigInt(b))
		pMarshalled := p.Bytes()
		// check that mask is what we expect
		assert.Equal(byte(0b100)<<5, pMarshalled[0]&(0b110<<5), "mask should be compressed regular")
		// swap out the mask
		pMarshalled[0] = (pMarshalled[0] &^ mMask) | mUncompressedInfinity // modify the mask
		assert.CheckCircuit(
			&unmarshalPoint{CP: make([]uints.U8, bls12381.SizeOfG1AffineCompressed)},
			test.WithInvalidAssignment(&unmarshalPoint{CP: uints.NewU8Array(pMarshalled[:]), P: NewG1Affine(p)}),
		)
	}, "case=invalid/uncompressed-infinity-random")
	// - uncompressed infinity 0b010 << 5, point infinity
	assert.Run(func(assert *test.Assert) {
		var p bls12381.G1Affine
		p.SetInfinity()
		pMarshalled := p.Bytes()
		// check that mask is what we expect
		assert.Equal(mCompressedInfinity, pMarshalled[0]&mMask, "mask should be compressed infinity")
		// swap out the mask
		pMarshalled[0] = (pMarshalled[0] &^ mMask) | mUncompressedInfinity // modify the mask
		assert.CheckCircuit(
			&unmarshalPoint{CP: make([]uints.U8, bls12381.SizeOfG1AffineCompressed)},
			test.WithInvalidAssignment(&unmarshalPoint{CP: uints.NewU8Array(pMarshalled[:]), P: NewG1Affine(p)}),
		)
	}, "case=invalid/uncompressed-infinity-infinity")
	// - explicit invalid 0b001 << 5, point random
	assert.Run(func(assert *test.Assert) {
		var p bls12381.G1Affine
		var s fr_bls12381.Element
		b := new(big.Int)
		_, _, g, _ := bls12381.Generators()
		s.MustSetRandom()
		p.ScalarMultiplication(&g, s.BigInt(b))
		pMarshalled := p.Bytes()
		// check that mask is what we expect
		assert.Equal(byte(0b100)<<5, pMarshalled[0]&(0b110<<5), "mask should be compressed regular")
		// swap out the mask
		pMarshalled[0] = (pMarshalled[0] &^ mMask) | (0b001 << 5) // modify the mask
		assert.CheckCircuit(
			&unmarshalPoint{CP: make([]uints.U8, bls12381.SizeOfG1AffineCompressed)},
			test.WithInvalidAssignment(&unmarshalPoint{CP: uints.NewU8Array(pMarshalled[:]), P: NewG1Affine(p)}),
		)
	}, "case=invalid/explicit-invalid-001-random")
	// - explicit invalid 0b001 << 5, point infinity
	assert.Run(func(assert *test.Assert) {
		var p bls12381.G1Affine
		p.SetInfinity()
		pMarshalled := p.Bytes()
		// check that mask is what we expect
		assert.Equal(mCompressedInfinity, pMarshalled[0]&mMask, "mask should be compressed infinity")
		// swap out the mask
		pMarshalled[0] = (pMarshalled[0] &^ mMask) | (0b001 << 5) // modify the mask
		assert.CheckCircuit(
			&unmarshalPoint{CP: make([]uints.U8, bls12381.SizeOfG1AffineCompressed)},
			test.WithInvalidAssignment(&unmarshalPoint{CP: uints.NewU8Array(pMarshalled[:]), P: NewG1Affine(p)}),
		)
	}, "case=invalid/explicit-invalid-001-infinity")
	// - explicit invalid 0b011 << 5, point random
	assert.Run(func(assert *test.Assert) {
		var p bls12381.G1Affine
		var s fr_bls12381.Element
		b := new(big.Int)
		_, _, g, _ := bls12381.Generators()
		s.MustSetRandom()
		p.ScalarMultiplication(&g, s.BigInt(b))
		pMarshalled := p.Bytes()
		// check that mask is what we expect
		assert.Equal(byte(0b100)<<5, pMarshalled[0]&(0b110<<5), "mask should be compressed regular")
		// swap out the mask
		pMarshalled[0] = (pMarshalled[0] &^ mMask) | (0b011 << 5) // modify the mask
		assert.CheckCircuit(
			&unmarshalPoint{CP: make([]uints.U8, bls12381.SizeOfG1AffineCompressed)},
			test.WithInvalidAssignment(&unmarshalPoint{CP: uints.NewU8Array(pMarshalled[:]), P: NewG1Affine(p)}),
		)
	}, "case=invalid/explicit-invalid-011-random")
	// - explicit invalid 0b011 << 5, point infinity
	assert.Run(func(assert *test.Assert) {
		var p bls12381.G1Affine
		p.SetInfinity()
		pMarshalled := p.Bytes()
		// check that mask is what we expect
		assert.Equal(mCompressedInfinity, pMarshalled[0]&mMask, "mask should be compressed infinity")
		// swap out the mask
		pMarshalled[0] = (pMarshalled[0] &^ mMask) | (0b011 << 5) // modify the mask
		assert.CheckCircuit(
			&unmarshalPoint{CP: make([]uints.U8, bls12381.SizeOfG1AffineCompressed)},
			test.WithInvalidAssignment(&unmarshalPoint{CP: uints.NewU8Array(pMarshalled[:]), P: NewG1Affine(p)}),
		)
	}, "case=invalid/explicit-invalid-011-infinity")
	// - explicit invalid 0b111 << 5, point random
	assert.Run(func(assert *test.Assert) {
		var p bls12381.G1Affine
		var s fr_bls12381.Element
		b := new(big.Int)
		_, _, g, _ := bls12381.Generators()
		s.MustSetRandom()
		p.ScalarMultiplication(&g, s.BigInt(b))
		pMarshalled := p.Bytes()
		// check that mask is what we expect
		assert.Equal(byte(0b100)<<5, pMarshalled[0]&(0b110<<5), "mask should be compressed regular")
		// swap out the mask
		pMarshalled[0] = (pMarshalled[0] &^ mMask) | (0b111 << 5) // modify the mask
		assert.CheckCircuit(
			&unmarshalPoint{CP: make([]uints.U8, bls12381.SizeOfG1AffineCompressed)},
			test.WithInvalidAssignment(&unmarshalPoint{CP: uints.NewU8Array(pMarshalled[:]), P: NewG1Affine(p)}),
		)
	}, "case=invalid/explicit-invalid-111-random")
	// - explicit invalid 0b111 << 5, point infinity
	assert.Run(func(assert *test.Assert) {
		var p bls12381.G1Affine
		p.SetInfinity()
		pMarshalled := p.Bytes()
		// check that mask is what we expect
		assert.Equal(mCompressedInfinity, pMarshalled[0]&mMask, "mask should be compressed infinity")
		// swap out the mask
		pMarshalled[0] = (pMarshalled[0] &^ mMask) | (0b111 << 5) // modify the mask
		assert.CheckCircuit(
			&unmarshalPoint{CP: make([]uints.U8, bls12381.SizeOfG1AffineCompressed)},
			test.WithInvalidAssignment(&unmarshalPoint{CP: uints.NewU8Array(pMarshalled[:]), P: NewG1Affine(p)}),
		)
	}, "case=invalid/explicit-invalid-111-infinity")
	// - x coordinate overflows the field
	assert.Run(func(assert *test.Assert) {
		var p bls12381.G1Affine
		var s fr_bls12381.Element
		b := new(big.Int)
		x := new(big.Int)
		xof := new(big.Int)
		_, _, g, _ := bls12381.Generators()
		for {
			s.MustSetRandom()
			p.ScalarMultiplication(&g, s.BigInt(b))
			p.X.BigInt(x)
			xof.Add(x, fp_bls12381.Modulus())     // overflow x coordinate
			if xof.BitLen() <= fp_bls12381.Bits { // to ensure we can fit the mask
				break
			}
		}
		pMarshalled := p.Bytes()
		var xBytes, xofBytes [bls12381.SizeOfG1AffineCompressed]byte
		xof.FillBytes(xofBytes[:])
		x.FillBytes(xBytes[:])
		xofBytes[0] |= pMarshalled[0] & mMask // add the mask
		xBytes[0] |= pMarshalled[0] & mMask   // add the mask
		if !bytes.Equal(xBytes[:], pMarshalled[:]) {
			assert.Fail("sanity check for correct serialization failed")
		}
		assert.CheckCircuit(
			&unmarshalPoint{CP: make([]uints.U8, bls12381.SizeOfG1AffineCompressed)},
			test.WithInvalidAssignment(&unmarshalPoint{CP: uints.NewU8Array(xofBytes[:]), P: NewG1Affine(p)}),
		)
	}, "case=invalid/x-overflow")
}
