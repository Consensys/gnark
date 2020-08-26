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
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gadgets/algebra/fields"
	"github.com/consensys/gurvy"
	"github.com/consensys/gurvy/bls377/fp"
	"github.com/consensys/gurvy/bls377/fr"

	"github.com/consensys/gurvy/bls377"
)

//--------------------------------------------------------------------
// utils

func randomPointG2() bls377.G2Jac {

	var p2 bls377.G2Jac
	var _p2 bls377.G2Affine

	p2.X.A0.SetString("129200027147742761118726589615458929865665635908074731940673005072449785691019374448547048953080140429883331266310")
	p2.X.A1.SetString("218164455698855406745723400799886985937129266327098023241324696183914328661520330195732120783615155502387891913936")
	p2.Y.A0.SetString("178797786102020318006939402153521323286173305074858025240458924050651930669327663166574060567346617543016897467207")
	p2.Y.A1.SetString("246194676937700783734853490842104812127151341609821057456393698060154678349106147660301543343243364716364400889778")
	p2.Z.A0.SetString("1")
	p2.Z.A1.SetString("0")

	var r1 fr.Element
	var b big.Int
	r1.SetRandom()
	_p2.FromJacobian(&p2)
	p2.ScalarMultiplication(&_p2, r1.ToBigIntRegular(&b))

	return p2
}

func newPointCircuitG2(circuit *frontend.CS, s string) *G2Jac {
	x := fields.NewFp2Elmt(circuit, circuit.SECRET_INPUT(s+"x0"), circuit.SECRET_INPUT(s+"x1"))
	y := fields.NewFp2Elmt(circuit, circuit.SECRET_INPUT(s+"y0"), circuit.SECRET_INPUT(s+"y1"))
	z := fields.NewFp2Elmt(circuit, circuit.SECRET_INPUT(s+"z0"), circuit.SECRET_INPUT(s+"z1"))
	return NewPointG2(circuit, x, y, z)
}

func newPointAffineCircuitG2(circuit *frontend.CS, s string) *G2Aff {
	x := fields.NewFp2Elmt(circuit, circuit.SECRET_INPUT(s+"x0"), circuit.SECRET_INPUT(s+"x1"))
	y := fields.NewFp2Elmt(circuit, circuit.SECRET_INPUT(s+"y0"), circuit.SECRET_INPUT(s+"y1"))
	return NewPointG2Aff(circuit, x, y)
}

func tagPointG2(cs *frontend.CS, g *G2Jac, s string) {
	cs.Tag(g.X.X, s+"x0")
	cs.Tag(g.X.Y, s+"x1")
	cs.Tag(g.Y.X, s+"y0")
	cs.Tag(g.Y.Y, s+"y1")
	cs.Tag(g.Z.X, s+"z0")
	cs.Tag(g.Z.Y, s+"z1")
}

func tagPointAffineG2(cs *frontend.CS, g *G2Aff, s string) {
	cs.Tag(g.X.X, s+"x0")
	cs.Tag(g.X.Y, s+"x1")
	cs.Tag(g.Y.X, s+"y0")
	cs.Tag(g.Y.Y, s+"y1")
}

func assignPointG2(inputs map[string]interface{}, g bls377.G2Jac, s string) {
	inputs[s+"x0"] = g.X.A0.String()
	inputs[s+"x1"] = g.X.A1.String()
	inputs[s+"y0"] = g.Y.A0.String()
	inputs[s+"y1"] = g.Y.A1.String()
	inputs[s+"z0"] = g.Z.A0.String()
	inputs[s+"z1"] = g.Z.A1.String()
}

func assignPointAffineG2(inputs map[string]interface{}, g bls377.G2Affine, s string) {
	inputs[s+"x0"] = g.X.A0.String()
	inputs[s+"x1"] = g.X.A1.String()
	inputs[s+"y0"] = g.Y.A0.String()
	inputs[s+"y1"] = g.Y.A1.String()
}

func getExpectedValuesG2(m map[string]*fp.Element, s string, g bls377.G2Jac) {
	m[s+"x0"] = &g.X.A0
	m[s+"x1"] = &g.X.A1
	m[s+"y0"] = &g.Y.A0
	m[s+"y1"] = &g.Y.A1
	m[s+"z0"] = &g.Z.A0
	m[s+"z1"] = &g.Z.A1
}

func getExpectedValuesAffineG2(m map[string]*fp.Element, s string, g bls377.G2Affine) {
	m[s+"x0"] = &g.X.A0
	m[s+"x1"] = &g.X.A1
	m[s+"y0"] = &g.Y.A0
	m[s+"y1"] = &g.Y.A1
}

//--------------------------------------------------------------------
// test

func TestAddAssignG2(t *testing.T) {

	// sample 2 random points
	g1 := randomPointG2()
	g2 := randomPointG2()

	// create the circuit
	circuit := frontend.NewConstraintSystem()
	ext := fields.GetBLS377ExtensionFp12(&circuit)

	gc1 := newPointCircuitG2(&circuit, "a")
	gc2 := newPointCircuitG2(&circuit, "b")
	gc1.AddAssign(&circuit, gc2, ext)
	tagPointG2(&circuit, gc1, "c")

	// assign the inputs
	inputs := make(map[string]interface{})
	assignPointG2(inputs, g1, "a")
	assignPointG2(inputs, g2, "b")

	// compute the result
	g1.AddAssign(&g2)

	// assign the exepected values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesG2(expectedValues, "c", g1)

	// check expected result
	r1cs := circuit.ToR1CS().ToR1CS(gurvy.BW761)

	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		var _v fp.Element
		_v.SetInterface(v)
		if !expectedValues[k].Equal(&_v) {
			t.Fatal("error add g1")
		}
	}
}

func TestAddAffAssignG2(t *testing.T) {

	// sample 2 random points
	var _g1, _g2 bls377.G2Affine
	g1 := randomPointG2()
	g2 := randomPointG2()
	_g1.FromJacobian(&g1)
	_g2.FromJacobian(&g2)

	// create the circuit
	circuit := frontend.NewConstraintSystem()
	ext := fields.GetBLS377ExtensionFp12(&circuit)

	gc1 := newPointAffineCircuitG2(&circuit, "a")
	gc2 := newPointAffineCircuitG2(&circuit, "b")
	gc1.AddAssign(&circuit, gc2, ext)
	tagPointAffineG2(&circuit, gc1, "c")

	// assign the inputs
	inputs := make(map[string]interface{})
	assignPointAffineG2(inputs, _g1, "a")
	assignPointAffineG2(inputs, _g2, "b")

	// compute the result
	g1.AddAssign(&g2)
	_g1.FromJacobian(&g1)

	// assign the exepected values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesAffineG2(expectedValues, "c", _g1)

	// check expected result
	r1cs := circuit.ToR1CS().ToR1CS(gurvy.BW761)

	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		var _v fp.Element
		_v.SetInterface(v)
		if !expectedValues[k].Equal(&_v) {
			t.Fatal("error add affine g1")
		}
	}
}

func TestDoubleAffAssignG2(t *testing.T) {

	// sample 2 random points
	var _g1 bls377.G2Affine
	g1 := randomPointG2()
	_g1.FromJacobian(&g1)

	// create the circuit
	circuit := frontend.NewConstraintSystem()
	ext := fields.GetBLS377ExtensionFp12(&circuit)

	gc1 := newPointAffineCircuitG2(&circuit, "a")
	gc1.Double(&circuit, gc1, ext)
	tagPointAffineG2(&circuit, gc1, "c")

	// assign the inputs
	inputs := make(map[string]interface{})
	assignPointAffineG2(inputs, _g1, "a")

	// compute the result
	g1.DoubleAssign()
	_g1.FromJacobian(&g1)

	// assign the exepected values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesAffineG2(expectedValues, "c", _g1)

	// check expected result
	r1cs := circuit.ToR1CS().ToR1CS(gurvy.BW761)

	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		var _v fp.Element
		_v.SetInterface(v)
		if !expectedValues[k].Equal(&_v) {
			t.Fatal("error add affine g1")
		}
	}
}

func TestDoubleG2(t *testing.T) {

	// sample 2 random points
	g1 := randomPointG2()

	// create the circuit
	circuit := frontend.NewConstraintSystem()
	ext := fields.GetBLS377ExtensionFp12(&circuit)

	gc1 := newPointCircuitG2(&circuit, "a")
	gc1.Double(&circuit, gc1, ext)
	tagPointG2(&circuit, gc1, "c")

	// assign the inputs
	inputs := make(map[string]interface{})
	assignPointG2(inputs, g1, "a")

	// compute the result
	g1.DoubleAssign()

	// assign the exepected values
	expectedValues := make(map[string]*fp.Element)
	getExpectedValuesG2(expectedValues, "c", g1)

	// check expected result
	r1cs := circuit.ToR1CS().ToR1CS(gurvy.BW761)

	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		var _v fp.Element
		_v.SetInterface(v)
		if !expectedValues[k].Equal(&_v) {
			t.Fatal("error add g1")
		}
	}
}
