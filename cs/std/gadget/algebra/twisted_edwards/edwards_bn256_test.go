// +build bn256

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

	"github.com/consensys/gnark/cs"
	"github.com/consensys/gnark/cs/internal/curve"
	twistededwards "github.com/consensys/gnark/cs/std/reference/algebra/twisted_edwards"
)

func TestAdd(t *testing.T) {

	s := cs.New()

	assert := cs.NewAssert(t)

	// get curve parameters
	ed := twistededwards.GetEdwardsCurve()

	// set the Snark point
	pointSnark := NewPoint(&s, s.SECRET_INPUT("x"), s.SECRET_INPUT("y"))

	// add points in circuit (the method updates the underlying plain points as well)
	resPointSnark := pointSnark.Add(&pointSnark, &ed.Base, ed)
	resPointSnark.X.Tag("xg")
	resPointSnark.Y.Tag("yg")

	inputs := cs.NewAssignment()
	inputs.Assign(cs.Secret, "x", "15132049151119024294202596478829150741889300374007672163496852915064138587014")
	inputs.Assign(cs.Secret, "y", "11523897191511824241384532572407048303306774918928882376450136656947192273193")

	expectedValues := make(map[string]interface{})
	var expectedu, expectedv curve.Element
	expectedu.SetString("4966531224162673480738068143298314346828081427171102366578720605707900725483")
	expectedv.SetString("18072205942244039714668938595243139985382136665954711533267729308917439031819")
	expectedValues["xg"] = expectedu
	expectedValues["yg"] = expectedv

	assert.Solved(s, inputs, expectedValues)
}

func TestAddGeneric(t *testing.T) {

	s := cs.New()

	assert := cs.NewAssert(t)

	pointSnark1 := NewPoint(&s, s.SECRET_INPUT("x1"), s.SECRET_INPUT("y1"))
	pointSnark2 := NewPoint(&s, s.SECRET_INPUT("x2"), s.SECRET_INPUT("y2"))

	// set curve parameters
	ed := twistededwards.GetEdwardsCurve()

	// add points in circuit (the method updates the underlying plain points as well)
	pointSnark1.AddGeneric(&pointSnark1, &pointSnark2, ed)
	pointSnark1.X.Tag("xg")
	pointSnark1.Y.Tag("yg")

	inputs := cs.NewAssignment()
	inputs.Assign(cs.Secret, "x1", "5299619240641551281634865583518297030282874472190772894086521144482721001553")
	inputs.Assign(cs.Secret, "y1", "16950150798460657717958625567821834550301663161624707787222815936182638968203")
	inputs.Assign(cs.Secret, "x2", "15132049151119024294202596478829150741889300374007672163496852915064138587014")
	inputs.Assign(cs.Secret, "y2", "11523897191511824241384532572407048303306774918928882376450136656947192273193")

	expectedValues := make(map[string]interface{})
	var expectedu, expectedv curve.Element
	expectedu.SetString("4966531224162673480738068143298314346828081427171102366578720605707900725483")
	expectedv.SetString("18072205942244039714668938595243139985382136665954711533267729308917439031819")
	expectedValues["xg"] = expectedu
	expectedValues["yg"] = expectedv

	assert.Solved(s, inputs, expectedValues)
}

func TestDouble(t *testing.T) {

	s := cs.New()

	assert := cs.NewAssert(t)

	pointSnark := NewPoint(&s, s.SECRET_INPUT("x"), s.SECRET_INPUT("y"))

	// set curve parameters
	ed := twistededwards.GetEdwardsCurve()

	// add points in circuit (the method updates the underlying plain points as well)
	pointSnark.Double(&pointSnark, ed)
	pointSnark.X.Tag("xg")
	pointSnark.Y.Tag("yg")

	inputs := cs.NewAssignment()
	inputs.Assign(cs.Secret, "x", "5299619240641551281634865583518297030282874472190772894086521144482721001553")
	inputs.Assign(cs.Secret, "y", "16950150798460657717958625567821834550301663161624707787222815936182638968203")

	expectedValues := make(map[string]interface{})
	var expectedu, expectedv curve.Element
	expectedu.SetString("10031262171927540148667355526369034398030886437092045105752248699557385197826")
	expectedv.SetString("633281375905621697187330766174974863687049529291089048651929454608812697683")
	expectedValues["xg"] = expectedu
	expectedValues["yg"] = expectedv

	assert.Solved(s, inputs, expectedValues)
}

func TestScalarMulFixedBase(t *testing.T) {

	s := cs.New()

	assert := cs.NewAssert(t)

	// set curve parameters
	ed := twistededwards.GetEdwardsCurve()

	// set point in the circuit
	pointSnark := NewPoint(&s, s.SECRET_INPUT("x"), s.SECRET_INPUT("y"))

	// set scalar
	scalar := s.ALLOCATE("28242048")

	inputs := cs.NewAssignment()
	inputs.Assign(cs.Secret, "x", "5299619240641551281634865583518297030282874472190772894086521144482721001553")
	inputs.Assign(cs.Secret, "y", "16950150798460657717958625567821834550301663161624707787222815936182638968203")

	// add points in circuit (the method updates the underlying plain points as well)
	pointSnark.scalarMulFixedBase(&ed.Base, ed, scalar, 25)
	pointSnark.X.Tag("xg")
	pointSnark.Y.Tag("yg")

	expectedValues := make(map[string]interface{})
	var expectedu, expectedv curve.Element
	expectedu.SetString("10190477835300927557649934238820360529458681672073866116232821892325659279502")
	expectedv.SetString("7969140283216448215269095418467361784159407896899334866715345504515077887397")
	expectedValues["xg"] = expectedu
	expectedValues["yg"] = expectedv

	assert.Solved(s, inputs, expectedValues)

}

func TestScalarMulNonFixedBase(t *testing.T) {

	s := cs.New()

	assert := cs.NewAssert(t)

	// set curve parameters
	ed := twistededwards.GetEdwardsCurve()

	// set point in the circuit
	pointSnark := NewPoint(&s, s.SECRET_INPUT("x"), s.SECRET_INPUT("y"))

	// set scalar
	scalar := s.ALLOCATE("28242048")

	inputs := cs.NewAssignment()
	inputs.Assign(cs.Secret, "x", "5299619240641551281634865583518297030282874472190772894086521144482721001553")
	inputs.Assign(cs.Secret, "y", "16950150798460657717958625567821834550301663161624707787222815936182638968203")

	// add points in circuit (the method updates the underlying plain points as well)
	pointSnark.scalarMulNonFixedBase(&pointSnark, scalar, ed, 25)
	pointSnark.X.Tag("xg")
	pointSnark.Y.Tag("yg")

	expectedValues := make(map[string]interface{})
	var expectedu, expectedv curve.Element
	expectedu.SetString("10190477835300927557649934238820360529458681672073866116232821892325659279502")
	expectedv.SetString("7969140283216448215269095418467361784159407896899334866715345504515077887397")
	expectedValues["xg"] = expectedu
	expectedValues["yg"] = expectedv

	assert.Solved(s, inputs, expectedValues)

}
