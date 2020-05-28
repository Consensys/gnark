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

package sw

import (
	"testing"

	"github.com/consensys/gnark/backend"
	backend_bw6 "github.com/consensys/gnark/backend/bw6"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy/bls377/fp"
	"github.com/consensys/gurvy/bls377/fr"

	"github.com/consensys/gurvy/bls377"
)

//--------------------------------------------------------------------
// utils

func randomPoints() (bls377.G1Jac, bls377.G1Jac) {

	curve := bls377.BLS377()

	var p1, p2 bls377.G1Jac

	p1.X.SetString("68333130937826953018162399284085925021577172705782285525244777453303237942212457240213897533859360921141590695983")
	p1.Y.SetString("243386584320553125968203959498080829207604143167922579970841210259134422887279629198736754149500839244552761526603")
	p1.Z.SetString("1")

	var r1, r2 fr.Element
	r1.SetRandom()
	r2.SetRandom()

	p1.ScalarMul(curve, &p1, r1)
	p2.ScalarMul(curve, &p1, r2)

	return p1, p2
}

func newPointCircuit(circuit *frontend.CS, s string) *G1Jac {
	return NewPointG1(circuit,
		circuit.SECRET_INPUT(s+"0"),
		circuit.SECRET_INPUT(s+"1"),
		circuit.SECRET_INPUT(s+"2"),
	)
}

func tagPoint(g *G1Jac, s string) {
	g.x.Tag(s + "0")
	g.y.Tag(s + "1")
	g.z.Tag(s + "2")
}

func assignPointG1(inputs backend.Assignments, g bls377.G1Jac, s string) {
	inputs.Assign(backend.Secret, s+"0", g.X)
	inputs.Assign(backend.Secret, s+"1", g.Y)
	inputs.Assign(backend.Secret, s+"2", g.Z)

}

func getExpectedValuesG1(m map[string]*fp.Element, s string, g bls377.G1Jac) {
	m[s+"0"] = &g.X
	m[s+"1"] = &g.Y
	m[s+"2"] = &g.Z
}

//--------------------------------------------------------------------
// test

func TestAddAssignG1(t *testing.T) {

	t.Skip("wip")

	curve := bls377.BLS377()

	// sample 2 random points
	g1, g2 := randomPoints()

	// create the circuit
	circuit := frontend.New()

	gc1 := newPointCircuit(&circuit, "a")
	gc2 := newPointCircuit(&circuit, "b")
	gc1.AddAssign(&circuit, gc2)
	tagPoint(gc1, "c")

	// assign the inputs
	inputs := backend.NewAssignment()
	assignPointG1(inputs, g1, "a")
	assignPointG1(inputs, g2, "b")

	// compute the result
	g1.Add(curve, &g2)

	// assign the exepected values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesG1(expectedValues, "c", g1)

	// check expected result
	r1cs := backend_bw6.New(&circuit)
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		if expectedValues[k].String() != v.String() {
			t.Fatal("error add g1")
		}
	}

}
