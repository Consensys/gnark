//go:build js && wasm

// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package bls12381

import (
	"encoding/binary"
	"errors"
	"fmt"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/iop"
	"github.com/consensys/gnark/backend/accelerated/webgpu/plonk/internal/bridge"
)

const (
	frBytes           = fr.Bytes
	g1CoordinateBytes = fp.Bytes
	g1PointBytes      = 3 * g1CoordinateBytes
)

func packFrVectorRegularLEInto(dst []byte, values []fr.Element) []byte {
	required := len(values) * frBytes
	if cap(dst) < required {
		dst = make([]byte, required)
	} else {
		dst = dst[:required]
	}
	for i := range values {
		base := i * frBytes
		writeFrRegularLE(dst[base:base+frBytes], &values[i])
	}
	return dst
}

func packFrVectorsRegularLEPaddedInto(dst []byte, vectors [][]fr.Element, elementCount int) ([]byte, error) {
	if elementCount <= 0 {
		return nil, errors.New("webgpu plonk bls12_381: empty MSM batch")
	}
	required := len(vectors) * elementCount * frBytes
	if cap(dst) < required {
		dst = make([]byte, required)
	} else {
		dst = dst[:required]
		clear(dst)
	}
	for i, values := range vectors {
		if len(values) > elementCount {
			return nil, fmt.Errorf("webgpu plonk bls12_381: MSM batch vector %d has %d elements, expected at most %d", i, len(values), elementCount)
		}
		start := i * elementCount * frBytes
		packFrVectorRegularLEInto(dst[start:start+len(values)*frBytes], values)
	}
	return dst, nil
}

func writeFrRegularLE(dst []byte, value *fr.Element) {
	be := value.Bytes()
	for i := 0; i < frBytes; i++ {
		dst[i] = be[frBytes-1-i]
	}
}

func readFrRegularLE(src []byte) (fr.Element, error) {
	if len(src) != frBytes {
		return fr.Element{}, fmt.Errorf("webgpu plonk bls12_381: expected %d Fr bytes, got %d", frBytes, len(src))
	}
	var le [frBytes]byte
	copy(le[:], src)
	return fr.LittleEndian.Element(&le)
}

func unpackFrVectorRegularLEInto(dst []fr.Element, src []byte) error {
	if len(src) != len(dst)*frBytes {
		return fmt.Errorf("webgpu plonk bls12_381: expected %d Fr vector bytes, got %d", len(dst)*frBytes, len(src))
	}
	for i := range dst {
		value, err := readFrRegularLE(src[i*frBytes : (i+1)*frBytes])
		if err != nil {
			return err
		}
		dst[i] = value
	}
	return nil
}

type canonicalizeGroupKey struct {
	inputBitReversed bool
	inverseCoset     bool
}

func canonicalizePolynomialsRegularWithWebGPU(polys []*iop.Polynomial, elementCount int) error {
	n := elementCount
	groups := make(map[canonicalizeGroupKey][]*iop.Polynomial)
	for _, p := range polys {
		if p == nil {
			continue
		}
		if p.Basis == iop.Canonical {
			p.ToRegular()
			continue
		}
		coeffs := p.Coefficients()
		if len(coeffs) != n {
			return fmt.Errorf("webgpu plonk bls12_381: canonicalize polynomial has %d coefficients, expected %d", len(coeffs), n)
		}
		switch p.Basis {
		case iop.Lagrange:
		case iop.LagrangeCoset:
		default:
			return fmt.Errorf("webgpu plonk bls12_381: unsupported polynomial basis %d", p.Basis)
		}
		switch p.Layout {
		case iop.Regular:
		case iop.BitReverse:
		default:
			return fmt.Errorf("webgpu plonk bls12_381: unsupported polynomial layout %d", p.Layout)
		}
		key := canonicalizeGroupKey{
			inputBitReversed: p.Layout == iop.BitReverse,
			inverseCoset:     p.Basis == iop.LagrangeCoset,
		}
		groups[key] = append(groups[key], p)
	}

	vectorBytes := n * frBytes
	for key, group := range groups {
		valuesPacked := make([]byte, len(group)*vectorBytes)
		for i, p := range group {
			packFrVectorRegularLEInto(valuesPacked[i*vectorBytes:(i+1)*vectorBytes], p.Coefficients())
		}
		canonicalPacked, err := bridge.Bridge.CanonicalizeQuotientVectors("bls12_381", valuesPacked, len(group), n, key.inputBitReversed, key.inverseCoset)
		if err != nil {
			return err
		}
		if len(canonicalPacked) != len(valuesPacked) {
			return fmt.Errorf("webgpu plonk bls12_381: quotient canonicalize returned %d bytes, expected %d", len(canonicalPacked), len(valuesPacked))
		}
		for i, p := range group {
			if err := unpackFrVectorRegularLEInto(p.Coefficients(), canonicalPacked[i*vectorBytes:(i+1)*vectorBytes]); err != nil {
				return err
			}
			p.Basis = iop.Canonical
			p.Layout = iop.Regular
		}
	}
	return nil
}

func canonicalizeQuotientFromCosetWithWebGPU(p *iop.Polynomial) error {
	return canonicalizePolynomialsRegularWithWebGPU([]*iop.Polynomial{p}, len(p.Coefficients()))
}

func lagrangePolynomialsRegularWithWebGPU(polys []*iop.Polynomial, elementCount int) error {
	n := elementCount
	filtered := make([]*iop.Polynomial, 0, len(polys))
	for _, p := range polys {
		if p == nil {
			continue
		}
		if p.Basis == iop.Lagrange {
			p.ToRegular()
			continue
		}
		if p.Basis != iop.Canonical || p.Layout != iop.Regular {
			return fmt.Errorf("webgpu plonk bls12_381: expected canonical regular polynomial, got basis %d layout %d", p.Basis, p.Layout)
		}
		if len(p.Coefficients()) != n {
			return fmt.Errorf("webgpu plonk bls12_381: lagrange polynomial has %d coefficients, expected %d", len(p.Coefficients()), n)
		}
		filtered = append(filtered, p)
	}
	if len(filtered) == 0 {
		return nil
	}

	vectorBytes := n * frBytes
	valuesPacked := make([]byte, len(filtered)*vectorBytes)
	for i, p := range filtered {
		packFrVectorRegularLEInto(valuesPacked[i*vectorBytes:(i+1)*vectorBytes], p.Coefficients())
	}
	lagrangePacked, err := bridge.Bridge.LagrangeQuotientVectors("bls12_381", valuesPacked, len(filtered), n)
	if err != nil {
		return err
	}
	if len(lagrangePacked) != len(valuesPacked) {
		return fmt.Errorf("webgpu plonk bls12_381: quotient lagrange returned %d bytes, expected %d", len(lagrangePacked), len(valuesPacked))
	}
	for i, p := range filtered {
		if err := unpackFrVectorRegularLEInto(p.Coefficients(), lagrangePacked[i*vectorBytes:(i+1)*vectorBytes]); err != nil {
			return err
		}
		p.Basis = iop.Lagrange
		p.Layout = iop.Regular
	}
	return nil
}

func packG1AffineJacobianBatch(points []curve.G1Affine) []byte {
	out := make([]byte, len(points)*g1PointBytes)
	for i := range points {
		base := i * g1PointBytes
		writeFPMontLE(out[base:base+g1CoordinateBytes], &points[i].X)
		writeFPMontLE(out[base+g1CoordinateBytes:base+2*g1CoordinateBytes], &points[i].Y)
		writeG1JacobianZOne(out[base+2*g1CoordinateBytes : base+3*g1CoordinateBytes])
	}
	return out
}

func decodeG1AffineFromPacked(packed []byte, err error) (curve.G1Affine, error) {
	if err != nil {
		return curve.G1Affine{}, err
	}
	if len(packed) != 2*g1CoordinateBytes {
		return curve.G1Affine{}, fmt.Errorf("webgpu plonk bls12_381: expected %d G1 bytes, got %d", 2*g1CoordinateBytes, len(packed))
	}
	return curve.G1Affine{
		X: readFPMontLE(packed[:g1CoordinateBytes]),
		Y: readFPMontLE(packed[g1CoordinateBytes:]),
	}, nil
}

func decodeG1AffineBatchFromPacked(packed []byte, count int, err error) ([]curve.G1Affine, error) {
	if err != nil {
		return nil, err
	}
	expected := count * 2 * g1CoordinateBytes
	if len(packed) != expected {
		return nil, fmt.Errorf("webgpu plonk bls12_381: expected %d G1 batch bytes, got %d", expected, len(packed))
	}
	res := make([]curve.G1Affine, count)
	for i := range res {
		start := i * 2 * g1CoordinateBytes
		res[i] = curve.G1Affine{
			X: readFPMontLE(packed[start : start+g1CoordinateBytes]),
			Y: readFPMontLE(packed[start+g1CoordinateBytes : start+2*g1CoordinateBytes]),
		}
	}
	return res, nil
}

func readFPMontLE(src []byte) fp.Element {
	var z fp.Element
	for i := range z {
		z[i] = binary.LittleEndian.Uint64(src[i*8 : (i+1)*8])
	}
	return z
}

func writeFPMontLE(dst []byte, value *fp.Element) {
	for i := range *value {
		binary.LittleEndian.PutUint64(dst[i*8:(i+1)*8], (*value)[i])
	}
}

func writeG1JacobianZOne(dst []byte) {
	var one fp.Element
	one.SetOne()
	writeFPMontLE(dst, &one)
}
