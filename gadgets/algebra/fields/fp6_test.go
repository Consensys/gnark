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

func newOperandFp6(circuit *frontend.CS, s string) Fp6Elmt {
	component := make([]*frontend.Constraint, 6)
	for i := 0; i < 6; i++ {
		component[i] = circuit.SECRET_INPUT(s + strconv.Itoa(i))
	}
	res := NewFp6Elmt(circuit,
		component[0],
		component[1],
		component[2],
		component[3],
		component[4],
		component[5])
	return res
}

func tagFp6Elmt(e Fp6Elmt, s string) {
	e.b0.x.Tag(s + "0")
	e.b0.y.Tag(s + "1")
	e.b1.x.Tag(s + "2")
	e.b1.y.Tag(s + "3")
	e.b2.x.Tag(s + "4")
	e.b2.y.Tag(s + "5")
}

func assignOperandFp6(inputs backend.Assignments, s string, w bls377.E6) {
	inputs.Assign(backend.Secret, s+"0", w.B0.A0)
	inputs.Assign(backend.Secret, s+"1", w.B0.A1)
	inputs.Assign(backend.Secret, s+"2", w.B1.A0)
	inputs.Assign(backend.Secret, s+"3", w.B1.A1)
	inputs.Assign(backend.Secret, s+"4", w.B2.A0)
	inputs.Assign(backend.Secret, s+"5", w.B2.A1)
}

func getExpectedValuesFp6(m map[string]*fp.Element, s string, w bls377.E6) {
	m[s+"0"] = &w.B0.A0
	m[s+"1"] = &w.B0.A1
	m[s+"2"] = &w.B1.A0
	m[s+"3"] = &w.B1.A1
	m[s+"4"] = &w.B2.A0
	m[s+"5"] = &w.B2.A1
}

func getBLS377ExtensionFp6(circuit *frontend.CS) Extension {
	res := Extension{}
	res.uSquare = 5
	res.vCube = &Fp2Elmt{x: circuit.ALLOCATE(0), y: circuit.ALLOCATE(1)}
	return res
}

//--------------------------------------------------------------------
// test
func TestAddFp6(t *testing.T) {

	circuit := frontend.New()

	// witness values
	var a, b, c bls377.E6
	a.SetRandom()
	b.SetRandom()
	c.Add(&a, &b)

	// circuit values
	fp6a := newOperandFp6(&circuit, "a")
	fp6b := newOperandFp6(&circuit, "b")
	fp6c := NewFp6Elmt(&circuit, nil, nil, nil, nil, nil, nil)
	fp6c.Add(&circuit, &fp6a, &fp6b)
	tagFp6Elmt(fp6c, "c")

	// assign the inputs
	inputs := backend.NewAssignment()
	assignOperandFp6(inputs, "a", a)
	assignOperandFp6(inputs, "b", b)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp6(expectedValues, "c", c)

	r1cs := backend_bw6.New(&circuit)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		if expectedValues[k].String() != v.String() {
			t.Fatal("error AddFp6")
		}
	}
}

func TestSubFp6(t *testing.T) {

	circuit := frontend.New()

	// witness values
	var a, b, c bls377.E6
	a.SetRandom()
	b.SetRandom()
	c.Sub(&a, &b)

	// circuit values
	fp6a := newOperandFp6(&circuit, "a")
	fp6b := newOperandFp6(&circuit, "b")
	fp6c := NewFp6Elmt(&circuit, nil, nil, nil, nil, nil, nil)
	fp6c.Sub(&circuit, &fp6a, &fp6b)
	tagFp6Elmt(fp6c, "c")

	// assign the inputs
	inputs := backend.NewAssignment()
	assignOperandFp6(inputs, "a", a)
	assignOperandFp6(inputs, "b", b)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp6(expectedValues, "c", c)

	r1cs := backend_bw6.New(&circuit)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		if expectedValues[k].String() != v.String() {
			t.Fatal("error SubFp6")
		}
	}
}

func TestMulFp6(t *testing.T) {

	circuit := frontend.New()

	ext := getBLS377ExtensionFp6(&circuit)

	// witness values
	var a, b, c bls377.E6
	a.SetRandom()
	b.SetRandom()
	c.Mul(&a, &b)

	// circuit values
	fp6a := newOperandFp6(&circuit, "a")
	fp6b := newOperandFp6(&circuit, "b")
	fp6c := NewFp6Elmt(&circuit, nil, nil, nil, nil, nil, nil)
	fp6c.Mul(&circuit, &fp6a, &fp6b, ext)
	tagFp6Elmt(fp6c, "c")

	// assign the inputs
	inputs := backend.NewAssignment()
	assignOperandFp6(inputs, "a", a)
	assignOperandFp6(inputs, "b", b)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp6(expectedValues, "c", c)

	r1cs := backend_bw6.New(&circuit)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		if expectedValues[k].String() != v.String() {
			t.Fatal("error MulFp6")
		}
	}
}

func TestMulByFp2Fp6(t *testing.T) {

	circuit := frontend.New()

	ext := getBLS377ExtensionFp6(&circuit)

	// witness values
	var a, c bls377.E6
	var b bls377.E2
	a.SetRandom()
	b.SetRandom()
	c.MulByE2(&a, &b)

	// circuit values
	fp6a := newOperandFp6(&circuit, "a")
	fp2b := newOperandFp2(&circuit, "b")
	fp6c := NewFp6Elmt(&circuit, nil, nil, nil, nil, nil, nil)
	fp6c.MulByFp2(&circuit, &fp6a, &fp2b, ext)
	tagFp6Elmt(fp6c, "c")

	// assign the inputs
	inputs := backend.NewAssignment()
	assignOperandFp6(inputs, "a", a)
	assignOperandFp2(inputs, "b", b)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp6(expectedValues, "c", c)

	r1cs := backend_bw6.New(&circuit)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		if expectedValues[k].String() != v.String() {
			t.Fatal("error MulByFp2Fp6")
		}
	}
}

func TestMulByVFp6(t *testing.T) {

	circuit := frontend.New()

	ext := getBLS377ExtensionFp6(&circuit)

	// witness values
	var a, c bls377.E6
	a.SetRandom()
	c.MulByNonResidue(&a)

	// circuit values
	fp6a := newOperandFp6(&circuit, "a")
	fp6c := NewFp6Elmt(&circuit, nil, nil, nil, nil, nil, nil)
	fp6c.MulByV(&circuit, &fp6a, ext)
	tagFp6Elmt(fp6c, "c")

	// assign the inputs
	inputs := backend.NewAssignment()
	assignOperandFp6(inputs, "a", a)

	// assign the exepcted values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesFp6(expectedValues, "c", c)

	r1cs := backend_bw6.New(&circuit)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		if expectedValues[k].String() != v.String() {
			t.Fatal("error MulByVFp6")
		}
	}
}
