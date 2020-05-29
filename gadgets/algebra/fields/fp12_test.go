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
	"strconv"
	"testing"

	"github.com/consensys/gnark/backend"
	backend_bw6 "github.com/consensys/gnark/backend/bw6"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy/bls377"
	"github.com/consensys/gurvy/bls377/fp"
)

//--------------------------------------------------------------------
// utils

func newOperandFp12(circuit *frontend.CS, s string) Fp12Elmt {
	component := make([]*frontend.Constraint, 12)
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

func tagFp12Elmt(e Fp12Elmt, s string) {
	e.C0.B0.X.Tag(s + "0")
	e.C0.B0.Y.Tag(s + "1")
	e.C0.B1.X.Tag(s + "2")
	e.C0.B1.Y.Tag(s + "3")
	e.C0.B2.X.Tag(s + "4")
	e.C0.B2.Y.Tag(s + "5")
	e.C1.B0.X.Tag(s + "6")
	e.C1.B0.Y.Tag(s + "7")
	e.C1.B1.X.Tag(s + "8")
	e.C1.B1.Y.Tag(s + "9")
	e.C1.B2.X.Tag(s + "10")
	e.C1.B2.Y.Tag(s + "11")
}

func assignOperandFp12(inputs backend.Assignments, s string, w bls377.E12) {
	inputs.Assign(backend.Secret, s+"0", w.C0.B0.A0)
	inputs.Assign(backend.Secret, s+"1", w.C0.B0.A1)
	inputs.Assign(backend.Secret, s+"2", w.C0.B1.A0)
	inputs.Assign(backend.Secret, s+"3", w.C0.B1.A1)
	inputs.Assign(backend.Secret, s+"4", w.C0.B2.A0)
	inputs.Assign(backend.Secret, s+"5", w.C0.B2.A1)
	inputs.Assign(backend.Secret, s+"6", w.C1.B0.A0)
	inputs.Assign(backend.Secret, s+"7", w.C1.B0.A1)
	inputs.Assign(backend.Secret, s+"8", w.C1.B1.A0)
	inputs.Assign(backend.Secret, s+"9", w.C1.B1.A1)
	inputs.Assign(backend.Secret, s+"10", w.C1.B2.A0)
	inputs.Assign(backend.Secret, s+"11", w.C1.B2.A1)
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

	circuit := frontend.New()

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
	tagFp12Elmt(fp12c, "c")

	// assign the inputs
	inputs := backend.NewAssignment()
	assignOperandFp12(inputs, "a", a)
	assignOperandFp12(inputs, "b", b)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := backend_bw6.New(&circuit)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		if expectedValues[k].String() != v.String() {
			t.Fatal("error AddFp12")
		}
	}
}

func TestSubFp12(t *testing.T) {

	circuit := frontend.New()

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
	tagFp12Elmt(fp12c, "c")

	// assign the inputs
	inputs := backend.NewAssignment()
	assignOperandFp12(inputs, "a", a)
	assignOperandFp12(inputs, "b", b)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := backend_bw6.New(&circuit)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		if expectedValues[k].String() != v.String() {
			t.Fatal("error SubFp12")
		}
	}
}

func TestMulFp12(t *testing.T) {

	circuit := frontend.New()

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
	tagFp12Elmt(fp12c, "c")

	// assign the inputs
	inputs := backend.NewAssignment()
	assignOperandFp12(inputs, "a", a)
	assignOperandFp12(inputs, "b", b)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := backend_bw6.New(&circuit)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		if expectedValues[k].String() != v.String() {
			t.Fatal("error MulFp12")
		}
	}
}

func TestConjugateFp12(t *testing.T) {

	circuit := frontend.New()

	// witness values
	var a, c bls377.E12
	a.SetRandom()
	c.Conjugate(&a)

	// circuit values
	fp12a := newOperandFp12(&circuit, "a")
	fp12c := NewFp12ElmtNil(&circuit)
	fp12c.Conjugate(&circuit, &fp12a)
	tagFp12Elmt(fp12c, "c")

	// assign the inputs
	inputs := backend.NewAssignment()
	assignOperandFp12(inputs, "a", a)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := backend_bw6.New(&circuit)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		if expectedValues[k].String() != v.String() {
			t.Fatal("error ConjugateFp12")
		}
	}
}

func TestMulByVFp12(t *testing.T) {

	circuit := frontend.New()

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
	tagFp12Elmt(fp12c, "c")

	// assign the inputs
	inputs := backend.NewAssignment()
	assignOperandFp2(inputs, "b", b)
	assignOperandFp12(inputs, "a", a)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := backend_bw6.New(&circuit)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		if expectedValues[k].String() != v.String() {
			t.Fatal("error MulByVFp12")
		}
	}
}

func TestMulByVWFp12(t *testing.T) {

	circuit := frontend.New()

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
	tagFp12Elmt(fp12c, "c")

	// assign the inputs
	inputs := backend.NewAssignment()
	assignOperandFp2(inputs, "b", b)
	assignOperandFp12(inputs, "a", a)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := backend_bw6.New(&circuit)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		if expectedValues[k].String() != v.String() {
			t.Fatal("error MulByVFp12")
		}
	}
}

func TestMulByV2WFp12(t *testing.T) {

	circuit := frontend.New()

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
	tagFp12Elmt(fp12c, "c")

	// assign the inputs
	inputs := backend.NewAssignment()
	assignOperandFp2(inputs, "b", b)
	assignOperandFp12(inputs, "a", a)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := backend_bw6.New(&circuit)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		if expectedValues[k].String() != v.String() {
			t.Fatal("error MulByVFp12")
		}
	}
}

func TestFrobeniusFp12(t *testing.T) {

	circuit := frontend.New()

	ext := GetBLS377ExtensionFp12(&circuit)

	// witness values
	var a, c bls377.E12
	a.SetRandom()
	c.Frobenius(&a)

	// circuit values
	fp12a := newOperandFp12(&circuit, "a")
	fp12c := NewFp12ElmtNil(&circuit)
	fp12c.Frobenius(&circuit, &fp12a, ext)
	tagFp12Elmt(fp12c, "c")

	// assign the inputs
	inputs := backend.NewAssignment()
	assignOperandFp12(inputs, "a", a)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := backend_bw6.New(&circuit)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		if expectedValues[k].String() != v.String() {
			t.Fatal("error FrobeniusFp12")
		}
	}
}

func TestFrobeniusSquareFp12(t *testing.T) {

	circuit := frontend.New()

	ext := GetBLS377ExtensionFp12(&circuit)

	// witness values
	var a, c bls377.E12
	a.SetRandom()
	c.FrobeniusSquare(&a)

	// circuit values
	fp12a := newOperandFp12(&circuit, "a")
	fp12c := NewFp12ElmtNil(&circuit)
	fp12c.FrobeniusSquare(&circuit, &fp12a, ext)
	tagFp12Elmt(fp12c, "c")

	// assign the inputs
	inputs := backend.NewAssignment()
	assignOperandFp12(inputs, "a", a)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := backend_bw6.New(&circuit)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		if expectedValues[k].String() != v.String() {
			t.Fatal("error FrobeniusSquareFp12")
		}
	}
}

func TestFrobeniusCubeFp12(t *testing.T) {

	circuit := frontend.New()

	ext := GetBLS377ExtensionFp12(&circuit)

	// witness values
	var a, c bls377.E12
	a.SetRandom()
	c.FrobeniusCube(&a)

	// circuit values
	fp12a := newOperandFp12(&circuit, "a")
	fp12c := NewFp12ElmtNil(&circuit)
	fp12c.FrobeniusCube(&circuit, &fp12a, ext)
	tagFp12Elmt(fp12c, "c")

	// assign the inputs
	inputs := backend.NewAssignment()
	assignOperandFp12(inputs, "a", a)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := backend_bw6.New(&circuit)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		if expectedValues[k].String() != v.String() {
			t.Fatal("error FrobeniusSquareFp12")
		}
	}
}

func TestInverseFp12(t *testing.T) {

	circuit := frontend.New()

	ext := GetBLS377ExtensionFp12(&circuit)

	// witness values
	var a, c bls377.E12
	a.SetRandom()
	c.Inverse(&a)

	// circuit values
	fp12a := newOperandFp12(&circuit, "a")
	fp12c := NewFp12ElmtNil(&circuit)
	fp12c.Inverse(&circuit, &fp12a, ext)
	tagFp12Elmt(fp12c, "c")

	// assign the inputs
	inputs := backend.NewAssignment()
	assignOperandFp12(inputs, "a", a)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp12(expectedValues, "c", c)

	r1cs := backend_bw6.New(&circuit)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		if expectedValues[k].String() != v.String() {
			t.Fatal("error InverseFp12")
		}
	}
}
