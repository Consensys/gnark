// +build bls381

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

package twistededwards

import (
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/curve/fr"
	"github.com/consensys/gnark/frontend"
	twistededwards "github.com/consensys/gnark/frontend/std/reference/algebra/twisted_edwards"
)

func TestAdd(t *testing.T) {

	s := frontend.New()

	assert := frontend.NewAssert(t)

	// get curve parameters
	ed := twistededwards.GetEdwardsCurve()

	// set the Snark point
	pointSnark := NewPoint(&s, s.SECRET_INPUT("x"), s.SECRET_INPUT("y"))

	// add points in circuit (the method updates the underlying plain points as well)
	resPointSnark := pointSnark.Add(&pointSnark, &ed.Base, ed)
	resPointSnark.X.Tag("xg")
	resPointSnark.Y.Tag("yg")

	inputs := backend.NewAssignment()
	inputs.Assign(backend.Secret, "x", "21793328330329971148710654283888115697962123987759099803244199498744022094670")
	inputs.Assign(backend.Secret, "y", "2101040637884652362150023747029283466236613497763786920682459476507158507058")

	expectedValues := make(map[string]interface{})
	var expectedu, expectedv fr.Element
	expectedu.SetString("2533524241621305345285734729686329955348757412587574960245868173345809049635")
	expectedv.SetString("42409967057463448917138434597972431415053095930787202051479921551234370983529")
	expectedValues["xg"] = expectedu
	expectedValues["yg"] = expectedv

	assert.Solved(s, inputs, expectedValues)
}

func TestAddGeneric(t *testing.T) {

	s := frontend.New()

	assert := frontend.NewAssert(t)

	pointSnark1 := NewPoint(&s, s.SECRET_INPUT("x1"), s.SECRET_INPUT("y1"))
	pointSnark2 := NewPoint(&s, s.SECRET_INPUT("x2"), s.SECRET_INPUT("y2"))

	// set curve parameters
	ed := twistededwards.GetEdwardsCurve()

	// add points in circuit (the method updates the underlying plain points as well)
	pointSnark1.AddGeneric(&pointSnark1, &pointSnark2, ed)
	pointSnark1.X.Tag("xg")
	pointSnark1.Y.Tag("yg")

	//r1cs := frontend.NewR1CS(&s)

	inputs := backend.NewAssignment()
	inputs.Assign(backend.Secret, "x1", "21793328330329971148710654283888115697962123987759099803244199498744022094670")
	inputs.Assign(backend.Secret, "y1", "2101040637884652362150023747029283466236613497763786920682459476507158507058")
	inputs.Assign(backend.Secret, "x2", "50629843885093813360334764484465489653158679010834922765195739220081842003850")
	inputs.Assign(backend.Secret, "y2", "39525475875082628301311747912064089490877815436253076910246067124459956047086")

	expectedValues := make(map[string]interface{})
	var expectedu, expectedv fr.Element
	expectedu.SetString("35199665011228459549784465709909589656817343715952606097903780358611765544262")
	expectedv.SetString("35317228978363680085508213497002527319878195549272460436820924737513178285870")
	expectedValues["xg"] = expectedu
	expectedValues["yg"] = expectedv

	assert.Solved(s, inputs, expectedValues)

}

func TestDouble(t *testing.T) {

	s := frontend.New()

	assert := frontend.NewAssert(t)

	pointSnark := NewPoint(&s, s.SECRET_INPUT("x"), s.SECRET_INPUT("y"))

	// set curve parameters
	ed := twistededwards.GetEdwardsCurve()

	// add points in circuit (the method updates the underlying plain points as well)
	pointSnark.Double(&pointSnark, ed)
	pointSnark.X.Tag("xg")
	pointSnark.Y.Tag("yg")

	inputs := backend.NewAssignment()
	inputs.Assign(backend.Secret, "x", "23426137002068529236790192115758361610982344002369094106619281483467893291614")
	inputs.Assign(backend.Secret, "y", "39325435222430376843701388596190331198052476467368316772266670064146548432123")

	expectedValues := make(map[string]interface{})
	var expectedu, expectedv fr.Element
	expectedu.SetString("51974064954906533666496091627071179705233333606733681005590705257300104702890")
	expectedv.SetString("50544520877185042664614914770414299746332988052510540984445210988959219538329")
	expectedValues["xg"] = expectedu
	expectedValues["yg"] = expectedv

	assert.Solved(s, inputs, expectedValues)

}

func TestScalarMulFixedBase(t *testing.T) {

	s := frontend.New()

	assert := frontend.NewAssert(t)

	// set curve parameters
	ed := twistededwards.GetEdwardsCurve()

	// set point in the circuit
	// TODO here we want a constructor that needs only the circuit
	pointSnark := Point{circuit: &s}

	// set scalar
	scalar := s.SECRET_INPUT("scalar")

	inputs := backend.NewAssignment()
	inputs.Assign(backend.Secret, "scalar", "28242048")

	// add points in circuit (the method updates the underlying plain points as well)
	pointSnark.scalarMulFixedBase(&ed.Base, ed, scalar, 25)
	pointSnark.X.Tag("xg")
	pointSnark.Y.Tag("yg")

	expectedValues := make(map[string]interface{})
	var expectedu, expectedv fr.Element
	expectedu.SetString("41219514559180903813234691537787707319466612367446320200474631050001556953343")
	expectedv.SetString("36528743687860298147244557954756268404118125957573115342278522894659264614911")
	expectedValues["xg"] = expectedu
	expectedValues["yg"] = expectedv

	assert.Solved(s, inputs, expectedValues)
}

func TestScalarMulNonFixedBase(t *testing.T) {

	s := frontend.New()

	assert := frontend.NewAssert(t)

	// set curve parameters
	ed := twistededwards.GetEdwardsCurve()

	// set point in the circuit
	pointSnark := NewPoint(&s, s.SECRET_INPUT("x"), s.SECRET_INPUT("y"))

	// set scalar
	scalar := s.ALLOCATE("28242048")

	inputs := backend.NewAssignment()
	inputs.Assign(backend.Secret, "x", "23426137002068529236790192115758361610982344002369094106619281483467893291614")
	inputs.Assign(backend.Secret, "y", "39325435222430376843701388596190331198052476467368316772266670064146548432123")

	// add points in circuit (the method updates the underlying plain points as well)
	pointSnark.scalarMulNonFixedBase(&pointSnark, scalar, ed, 25)
	pointSnark.X.Tag("xg")
	pointSnark.Y.Tag("yg")

	expectedValues := make(map[string]interface{})
	var expectedu, expectedv fr.Element
	expectedu.SetString("41219514559180903813234691537787707319466612367446320200474631050001556953343")
	expectedv.SetString("36528743687860298147244557954756268404118125957573115342278522894659264614911")
	assert.Solved(s, inputs, expectedValues)

}
