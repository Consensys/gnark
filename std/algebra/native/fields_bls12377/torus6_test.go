// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package fields_bls12377

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type torusSquareCircuit struct {
	Y        E6
	Expected E6
}

func (c *torusSquareCircuit) Define(api frontend.API) error {
	result := TorusSquareWithHint(api, c.Y)
	result.AssertIsEqual(api, c.Expected)
	return nil
}

func TestTorusSquare(t *testing.T) {
	assert := test.NewAssert(t)

	// Generate random element in cyclotomic subgroup via torus
	var y bls12377.E6
	y.SetRandom()

	// Compute expected result: y' = 2y / (1 + y²·v)
	var ySq, num, denom, expected bls12377.E6
	num.Double(&y)
	ySq.Square(&y)
	denom.MulByNonResidue(&ySq)
	var one bls12377.E6
	one.SetOne()
	denom.Add(&denom, &one)
	expected.Inverse(&denom)
	expected.Mul(&expected, &num)

	circuit := &torusSquareCircuit{}
	var witness torusSquareCircuit
	witness.Y.Assign(&y)
	witness.Expected.Assign(&expected)
	assert.CheckCircuit(circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

type torusMulCircuit struct {
	Y1, Y2   E6
	Expected E6
}

func (c *torusMulCircuit) Define(api frontend.API) error {
	result := TorusMulWithHint(api, c.Y1, c.Y2)
	result.AssertIsEqual(api, c.Expected)
	return nil
}

func TestTorusMul(t *testing.T) {
	assert := test.NewAssert(t)

	var y1, y2 bls12377.E6
	y1.SetRandom()
	y2.SetRandom()

	// Compute expected result: y' = (y1 + y2) / (1 + y1·y2·v)
	var prod, num, denom, expected bls12377.E6
	num.Add(&y1, &y2)
	prod.Mul(&y1, &y2)
	denom.MulByNonResidue(&prod)
	var one bls12377.E6
	one.SetOne()
	denom.Add(&denom, &one)
	expected.Inverse(&denom)
	expected.Mul(&expected, &num)

	circuit := &torusMulCircuit{}
	var witness torusMulCircuit
	witness.Y1.Assign(&y1)
	witness.Y2.Assign(&y2)
	witness.Expected.Assign(&expected)
	assert.CheckCircuit(circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

type torusMulBy01Circuit struct {
	Y        E6
	L0, L1   E2
	Expected E6
}

func (c *torusMulBy01Circuit) Define(api frontend.API) error {
	result := TorusMulBy01WithHint(api, c.Y, c.L0, c.L1)
	result.AssertIsEqual(api, c.Expected)
	return nil
}

func TestTorusMulBy01(t *testing.T) {
	assert := test.NewAssert(t)

	var y bls12377.E6
	var l0, l1 bls12377.E2
	y.SetRandom()
	l0.SetRandom()
	l1.SetRandom()

	// Compute expected result: y' = (y + sparse) / (1 + y·sparse·v)
	var sparse, prod, num, denom, expected bls12377.E6
	sparse.B0 = l0
	sparse.B1 = l1
	// sparse.B2 = 0

	num.Add(&y, &sparse)
	prod.Set(&y)
	prod.MulBy01(&l0, &l1)
	denom.MulByNonResidue(&prod)
	var one bls12377.E6
	one.SetOne()
	denom.Add(&denom, &one)
	expected.Inverse(&denom)
	expected.Mul(&expected, &num)

	circuit := &torusMulBy01Circuit{}
	var witness torusMulBy01Circuit
	witness.Y.Assign(&y)
	witness.L0.Assign(&l0)
	witness.L1.Assign(&l1)
	witness.Expected.Assign(&expected)
	assert.CheckCircuit(circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

type torusDecompressCircuit struct {
	Y        E6
	Expected E12
}

func (c *torusDecompressCircuit) Define(api frontend.API) error {
	result := TorusDecompressWithHint(api, c.Y)
	result.AssertIsEqual(api, c.Expected)
	return nil
}

func TestTorusDecompress(t *testing.T) {
	assert := test.NewAssert(t)

	var y bls12377.E6
	y.SetRandom()

	// Compute expected result: x = (1 + y·w) / (1 - y·w)
	var num, denom, expected bls12377.E12
	num.C0.SetOne()
	num.C1.Set(&y)
	denom.C0.SetOne()
	denom.C1.Neg(&y)
	expected.Inverse(&denom)
	expected.Mul(&expected, &num)

	circuit := &torusDecompressCircuit{}
	var witness torusDecompressCircuit
	witness.Y.Assign(&y)
	witness.Expected.Assign(&expected)
	assert.CheckCircuit(circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

type torusCompressCircuit struct {
	X        E12
	Expected E6
}

func (c *torusCompressCircuit) Define(api frontend.API) error {
	result := TorusCompressWithHint(api, c.X)
	result.AssertIsEqual(api, c.Expected)
	return nil
}

func TestTorusCompress(t *testing.T) {
	assert := test.NewAssert(t)

	// Generate a cyclotomic element (which can be compressed)
	var y bls12377.E6
	y.SetRandom()

	// Decompress to E12 first
	var num, denom, x bls12377.E12
	num.C0.SetOne()
	num.C1.Set(&y)
	denom.C0.SetOne()
	denom.C1.Neg(&y)
	x.Inverse(&denom)
	x.Mul(&x, &num)

	// Now compress should give back y
	circuit := &torusCompressCircuit{}
	var witness torusCompressCircuit
	witness.X.Assign(&x)
	witness.Expected.Assign(&y)
	assert.CheckCircuit(circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

type frobeniusTorusCircuit struct {
	Y        E6
	Expected E6
}

func (c *frobeniusTorusCircuit) Define(api frontend.API) error {
	result := FrobeniusTorus(api, c.Y)
	result.AssertIsEqual(api, c.Expected)
	return nil
}

func TestFrobeniusTorus(t *testing.T) {
	assert := test.NewAssert(t)

	// Generate random torus element
	var y bls12377.E6
	y.SetRandom()

	// Decompress to E12
	var num, denom, W bls12377.E12
	num.C0.SetOne()
	num.C1.Set(&y)
	denom.C0.SetOne()
	denom.C1.Neg(&y)
	W.Inverse(&denom)
	W.Mul(&W, &num)

	// Apply Frobenius to W
	var frobW bls12377.E12
	frobW.Frobenius(&W)

	// Compress Frob(W) back to torus
	var c0PlusOne, expected bls12377.E6
	c0PlusOne.Set(&frobW.C0)
	var one bls12377.E6
	one.SetOne()
	c0PlusOne.Add(&c0PlusOne, &one)
	expected.Inverse(&c0PlusOne)
	expected.Mul(&expected, &frobW.C1)

	circuit := &frobeniusTorusCircuit{}
	var witness frobeniusTorusCircuit
	witness.Y.Assign(&y)
	witness.Expected.Assign(&expected)
	assert.CheckCircuit(circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

type torusRoundTripCircuit struct {
	Y E6
}

func (c *torusRoundTripCircuit) Define(api frontend.API) error {
	// Decompress to E12, then compress back - should get original
	decompressed := TorusDecompressWithHint(api, c.Y)
	compressed := TorusCompressWithHint(api, decompressed)
	compressed.AssertIsEqual(api, c.Y)
	return nil
}

func TestTorusRoundTrip(t *testing.T) {
	assert := test.NewAssert(t)

	var y bls12377.E6
	y.SetRandom()

	circuit := &torusRoundTripCircuit{}
	var witness torusRoundTripCircuit
	witness.Y.Assign(&y)
	assert.CheckCircuit(circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}
