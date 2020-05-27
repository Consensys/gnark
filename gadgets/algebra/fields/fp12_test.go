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
	e.c0.b0.x.Tag(s + "0")
	e.c0.b0.y.Tag(s + "1")
	e.c0.b1.x.Tag(s + "2")
	e.c0.b1.y.Tag(s + "3")
	e.c0.b2.x.Tag(s + "4")
	e.c0.b2.y.Tag(s + "5")
	e.c1.b0.x.Tag(s + "6")
	e.c1.b0.y.Tag(s + "7")
	e.c1.b1.x.Tag(s + "8")
	e.c1.b1.y.Tag(s + "9")
	e.c1.b2.x.Tag(s + "10")
	e.c1.b2.y.Tag(s + "11")
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
			t.Fatal("error AddFp6")
		}
	}
}
