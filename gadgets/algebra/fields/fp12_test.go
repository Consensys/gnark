/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package fields

import (
	"math/big"
	"strconv"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
	"github.com/consensys/gurvy/bls377"
	"github.com/consensys/gurvy/bls377/fp"
)

//--------------------------------------------------------------------
// utils

func newOperandFp12(circuit *frontend.CS, s string) Fp12Elmt {
	component := make([]frontend.Variable, 12)
	for i := 0; i < 12; i++ {
		component[i] = circuit.SECRET_INPUT(s + strconv.Itoa(i))
	}
	res := NewFp12Elmt(circuit,
		component[0],
		component[1],
		component[2],
		component[3],
		component[4],
		component[5],
		component[6],
		component[7],
		component[8],
		component[9],
		component[10],
		component[11])
	return res
}

func tagFp12Elmt(cs *frontend.CS, e Fp12Elmt, s string) {
	cs.Tag(e.C0.B0.X, s+"0")
	cs.Tag(e.C0.B0.Y, s+"1")
	cs.Tag(e.C0.B1.X, s+"2")
	cs.Tag(e.C0.B1.Y, s+"3")
	cs.Tag(e.C0.B2.X, s+"4")
	cs.Tag(e.C0.B2.Y, s+"5")
	cs.Tag(e.C1.B0.X, s+"6")
	cs.Tag(e.C1.B0.Y, s+"7")
	cs.Tag(e.C1.B1.X, s+"8")
	cs.Tag(e.C1.B1.Y, s+"9")
	cs.Tag(e.C1.B2.X, s+"10")
	cs.Tag(e.C1.B2.Y, s+"11")
}

func assignOperandFp12(inputs map[string]interface{}, s string, w bls377.E12) {
	// TODO using String() here is dirty.
	inputs[s+"0"] = w.C0.B0.A0.String()
	inputs[s+"1"] = w.C0.B0.A1.String()
	inputs[s+"2"] = w.C0.B1.A0.String()
	inputs[s+"3"] = w.C0.B1.A1.String()
	inputs[s+"4"] = w.C0.B2.A0.String()
	inputs[s+"5"] = w.C0.B2.A1.String()
	inputs[s+"6"] = w.C1.B0.A0.String()
	inputs[s+"7"] = w.C1.B0.A1.String()
	inputs[s+"8"] = w.C1.B1.A0.String()
	inputs[s+"9"] = w.C1.B1.A1.String()
	inputs[s+"10"] = w.C1.B2.A0.String()
	inputs[s+"11"] = w.C1.B2.A1.String()
}

func getExpectedValuesFp12(m map[string]*fp.Element, s string, w bls377.E12) {
	m[s+"0"] = &w.C0.B0.A0
	m[s+"1"] = &w.C0.B0.A1
	m[s+"2"] = &w.C0.B1.A0
	m[s+"3"] = &w.C0.B1.A1
	m[s+"4"] = &w.C0.B2.A0
	m[s+"5"] = &w.C0.B2.A1
	m[s+"6"] = &w.C1.B0.A0
	m[s+"7"] = &w.C1.B0.A1
	m[s+"8"] = &w.C1.B1.A0
	m[s+"9"] = &w.C1.B1.A1
	m[s+"10"] = &w.C1.B2.A0
	m[s+"11"] = &w.C1.B2.A1
}

//--------------------------------------------------------------------
// test
func TestAddFp12(t *testing.T) {

	circuit := frontend.NewConstraintSystem()

	// witness values
	var a, b, c bls377.E12
	a.SetRandom()
	b.SetRandom()
	c.Add(&a, &b)

	// circuit values
	fp12a := newOperandFp12(&circuit, "a")
	fp12b := newOperandFp12(&circuit, "b")
	fp12c := NewFp12ElmtNil(&circuit)
	fp12c.Add(&circuit, &fp12a, &fp12b)
	tagFp12Elmt(&circuit, fp12c, "c")

	// assign the inputs
	inputs := make(map[string]interface{})
	assignOperandFp12(inputs, "a", a)
	assignOperandFp12(inputs, "b", b)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := circuit.ToR1CS().ToR1CS(gurvy.BW761)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	var _v fp.Element
	for k, v := range res {
		_v.SetInterface(v)
		if !expectedValues[k].Equal(&_v) {
			t.Fatal("error AddFp12")
		}
	}
}

func TestSubFp12(t *testing.T) {

	circuit := frontend.NewConstraintSystem()

	// witness values
	var a, b, c bls377.E12
	a.SetRandom()
	b.SetRandom()
	c.Sub(&a, &b)

	// circuit values
	fp12a := newOperandFp12(&circuit, "a")
	fp12b := newOperandFp12(&circuit, "b")
	fp12c := NewFp12ElmtNil(&circuit)
	fp12c.Sub(&circuit, &fp12a, &fp12b)
	tagFp12Elmt(&circuit, fp12c, "c")

	// assign the inputs
	inputs := make(map[string]interface{})
	assignOperandFp12(inputs, "a", a)
	assignOperandFp12(inputs, "b", b)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := circuit.ToR1CS().ToR1CS(gurvy.BW761)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		var _v fp.Element
		_v.SetInterface(v)
		if !expectedValues[k].Equal(&_v) {
			t.Fatal("error SubFp12")
		}
	}
}

func TestMulFp12(t *testing.T) {

	circuit := frontend.NewConstraintSystem()

	ext := GetBLS377ExtensionFp12(&circuit)

	// witness values
	var a, b, c bls377.E12
	a.SetRandom()
	b.SetRandom()
	c.Mul(&a, &b)

	// circuit values
	fp12a := newOperandFp12(&circuit, "a")
	fp12b := newOperandFp12(&circuit, "b")
	fp12c := NewFp12ElmtNil(&circuit)
	fp12c.Mul(&circuit, &fp12a, &fp12b, ext)
	tagFp12Elmt(&circuit, fp12c, "c")

	// assign the inputs
	inputs := make(map[string]interface{})
	assignOperandFp12(inputs, "a", a)
	assignOperandFp12(inputs, "b", b)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := circuit.ToR1CS().ToR1CS(gurvy.BW761)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		var _v fp.Element
		_v.SetInterface(v)
		if !expectedValues[k].Equal(&_v) {
			t.Fatal("error MulFp12")
		}
	}
}

func TestConjugateFp12(t *testing.T) {

	circuit := frontend.NewConstraintSystem()

	// witness values
	var a, c bls377.E12
	a.SetRandom()
	c.Conjugate(&a)

	// circuit values
	fp12a := newOperandFp12(&circuit, "a")
	fp12c := NewFp12ElmtNil(&circuit)
	fp12c.Conjugate(&circuit, &fp12a)
	tagFp12Elmt(&circuit, fp12c, "c")

	// assign the inputs
	inputs := make(map[string]interface{})
	assignOperandFp12(inputs, "a", a)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := circuit.ToR1CS().ToR1CS(gurvy.BW761)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		var _v fp.Element
		_v.SetInterface(v)
		if !expectedValues[k].Equal(&_v) {
			t.Fatal("error ConjugateFp12")
		}
	}
}

func TestMulByVFp12(t *testing.T) {

	circuit := frontend.NewConstraintSystem()

	ext := GetBLS377ExtensionFp12(&circuit)

	// witness values
	var a, c bls377.E12
	var b bls377.E2
	a.SetRandom()
	b.SetRandom()
	c.MulByV(&a, &b)

	// circuit values
	fp12a := newOperandFp12(&circuit, "a")
	fp2b := newOperandFp2(&circuit, "b")
	fp12c := NewFp12ElmtNil(&circuit)
	fp12c.MulByV(&circuit, &fp12a, &fp2b, ext)
	tagFp12Elmt(&circuit, fp12c, "c")

	// assign the inputs
	inputs := make(map[string]interface{})
	assignOperandFp2(inputs, "b", b)
	assignOperandFp12(inputs, "a", a)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := circuit.ToR1CS().ToR1CS(gurvy.BW761)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		var _v fp.Element
		_v.SetInterface(v)
		if !expectedValues[k].Equal(&_v) {
			t.Fatal("error MulByVFp12")
		}
	}
}

func TestMulByVWFp12(t *testing.T) {

	circuit := frontend.NewConstraintSystem()

	ext := GetBLS377ExtensionFp12(&circuit)

	// witness values
	var a, c bls377.E12
	var b bls377.E2
	a.SetRandom()
	b.SetRandom()
	c.MulByVW(&a, &b)

	// circuit values
	fp12a := newOperandFp12(&circuit, "a")
	fp2b := newOperandFp2(&circuit, "b")
	fp12c := NewFp12ElmtNil(&circuit)
	fp12c.MulByVW(&circuit, &fp12a, &fp2b, ext)
	tagFp12Elmt(&circuit, fp12c, "c")

	// assign the inputs
	inputs := make(map[string]interface{})
	assignOperandFp2(inputs, "b", b)
	assignOperandFp12(inputs, "a", a)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := circuit.ToR1CS().ToR1CS(gurvy.BW761)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		var _v fp.Element
		_v.SetInterface(v)
		if !expectedValues[k].Equal(&_v) {
			t.Fatal("error MulByVFp12")
		}
	}
}

func TestMulByV2WFp12(t *testing.T) {

	circuit := frontend.NewConstraintSystem()

	ext := GetBLS377ExtensionFp12(&circuit)

	// witness values
	var a, c bls377.E12
	var b bls377.E2
	a.SetRandom()
	b.SetRandom()
	c.MulByV2W(&a, &b)

	// circuit values
	fp12a := newOperandFp12(&circuit, "a")
	fp2b := newOperandFp2(&circuit, "b")
	fp12c := NewFp12ElmtNil(&circuit)
	fp12c.MulByV2W(&circuit, &fp12a, &fp2b, ext)
	tagFp12Elmt(&circuit, fp12c, "c")

	// assign the inputs
	inputs := make(map[string]interface{})
	assignOperandFp2(inputs, "b", b)
	assignOperandFp12(inputs, "a", a)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := circuit.ToR1CS().ToR1CS(gurvy.BW761)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		var _v fp.Element
		_v.SetInterface(v)
		if !expectedValues[k].Equal(&_v) {
			t.Fatal("error MulByVFp12")
		}
	}
}

func TestFrobeniusFp12(t *testing.T) {

	circuit := frontend.NewConstraintSystem()

	ext := GetBLS377ExtensionFp12(&circuit)

	// witness values
	var a, c bls377.E12
	a.SetRandom()
	c.Frobenius(&a)

	// circuit values
	fp12a := newOperandFp12(&circuit, "a")
	fp12c := NewFp12ElmtNil(&circuit)
	fp12c.Frobenius(&circuit, &fp12a, ext)
	tagFp12Elmt(&circuit, fp12c, "c")

	// assign the inputs
	inputs := make(map[string]interface{})
	assignOperandFp12(inputs, "a", a)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := circuit.ToR1CS().ToR1CS(gurvy.BW761)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		var _v fp.Element
		_v.SetInterface(v)
		if !expectedValues[k].Equal(&_v) {
			t.Fatal("error FrobeniusFp12")
		}
	}
}

func TestFrobeniusSquareFp12(t *testing.T) {

	circuit := frontend.NewConstraintSystem()

	ext := GetBLS377ExtensionFp12(&circuit)

	// witness values
	var a, c bls377.E12
	a.SetRandom()
	c.FrobeniusSquare(&a)

	// circuit values
	fp12a := newOperandFp12(&circuit, "a")
	fp12c := NewFp12ElmtNil(&circuit)
	fp12c.FrobeniusSquare(&circuit, &fp12a, ext)
	tagFp12Elmt(&circuit, fp12c, "c")

	// assign the inputs
	inputs := make(map[string]interface{})
	assignOperandFp12(inputs, "a", a)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := circuit.ToR1CS().ToR1CS(gurvy.BW761)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		var _v fp.Element
		_v.SetInterface(v)
		if !expectedValues[k].Equal(&_v) {
			t.Fatal("error FrobeniusSquareFp12")
		}
	}
}

func TestFrobeniusCubeFp12(t *testing.T) {

	circuit := frontend.NewConstraintSystem()

	ext := GetBLS377ExtensionFp12(&circuit)

	// witness values
	var a, c bls377.E12
	a.SetRandom()
	c.FrobeniusCube(&a)

	// circuit values
	fp12a := newOperandFp12(&circuit, "a")
	fp12c := NewFp12ElmtNil(&circuit)
	fp12c.FrobeniusCube(&circuit, &fp12a, ext)
	tagFp12Elmt(&circuit, fp12c, "c")

	// assign the inputs
	inputs := make(map[string]interface{})
	assignOperandFp12(inputs, "a", a)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := circuit.ToR1CS().ToR1CS(gurvy.BW761)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		var _v fp.Element
		_v.SetInterface(v)
		if !expectedValues[k].Equal(&_v) {
			t.Fatal("error FrobeniusSquareFp12")
		}
	}
}

func TestInverseFp12(t *testing.T) {

	circuit := frontend.NewConstraintSystem()

	ext := GetBLS377ExtensionFp12(&circuit)

	// witness values
	var a, c bls377.E12
	a.SetRandom()
	c.Inverse(&a)

	// circuit values
	fp12a := newOperandFp12(&circuit, "a")
	fp12c := NewFp12ElmtNil(&circuit)
	fp12c.Inverse(&circuit, &fp12a, ext)
	tagFp12Elmt(&circuit, fp12c, "c")

	// assign the inputs
	inputs := make(map[string]interface{})
	assignOperandFp12(inputs, "a", a)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := circuit.ToR1CS().ToR1CS(gurvy.BW761)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		var _v fp.Element
		_v.SetInterface(v)
		if !expectedValues[k].Equal(&_v) {
			t.Fatal("error FrobeniusSquareFp12")
		}
	}
}

func TestFixExpoFp12(t *testing.T) {

	circuit := frontend.NewConstraintSystem()

	ext := GetBLS377ExtensionFp12(&circuit)

	// witness values
	expo := uint64(9586122913090633729)

	var a, c bls377.E12
	a.SetRandom()
	c.Exp(&a, *new(big.Int).SetUint64(expo))

	// circuit values
	fp12a := newOperandFp12(&circuit, "a")
	fp12c := NewFp12ElmtNil(&circuit)
	fp12c.FixedExponentiation(&circuit, &fp12a, expo, ext)
	tagFp12Elmt(&circuit, fp12c, "c")

	// assign the inputs
	inputs := make(map[string]interface{})
	assignOperandFp12(inputs, "a", a)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := circuit.ToR1CS().ToR1CS(gurvy.BW761)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		var _v fp.Element
		_v.SetInterface(v)
		if !expectedValues[k].Equal(&_v) {
			t.Fatal("error Final exponentiation bls")
		}
	}
}

func TestFinalExpoBLSFp12(t *testing.T) {

	circuit := frontend.NewConstraintSystem()

	ext := GetBLS377ExtensionFp12(&circuit)
	ateLoop := uint64(9586122913090633729)

	// witness values
	var a, c bls377.E12
	a.SetRandom()
	c.FinalExponentiation(&a)

	// circuit values
	fp12a := newOperandFp12(&circuit, "a")
	fp12c := NewFp12ElmtNil(&circuit)
	fp12c.FinalExpoBLS(&circuit, &fp12a, ateLoop, ext)
	tagFp12Elmt(&circuit, fp12c, "c")

	// assign the inputs
	inputs := make(map[string]interface{})
	assignOperandFp12(inputs, "a", a)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := circuit.ToR1CS().ToR1CS(gurvy.BW761)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		var _v fp.Element
		_v.SetInterface(v)
		if !expectedValues[k].Equal(&_v) {
			t.Fatal("error ExponentiationFp12")
		}
	}
}
