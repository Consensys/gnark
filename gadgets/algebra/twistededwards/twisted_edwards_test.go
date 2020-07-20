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

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

func TestIsOnCurve(t *testing.T) {
	assert := groth16.NewAssert(t)
	circuit := frontend.NewConstraintSystem()

	// get edwards curve gadget
	params, err := NewEdCurve(gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}

	// set the Snark point
	pointSnark := NewPoint(&circuit, circuit.SECRET_INPUT("x"), circuit.SECRET_INPUT("y"))

	pointSnark.MustBeOnCurve(&circuit, params)

	inputs := make(map[string]interface{})
	inputs["x"] = params.BaseX
	inputs["y"] = params.BaseY

	// creates r1cs
	r1csbn256 := circuit.ToR1CS().ToR1CS(gurvy.BN256)

	assert.CorrectExecution(r1csbn256, inputs, nil)

}

func TestAdd(t *testing.T) {

	circuit := frontend.NewConstraintSystem()

	assertbn256 := groth16.NewAssert(t)

	// get edwards curve gadget
	params, err := NewEdCurve(gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}

	// set the Snark point
	pointSnark := NewPoint(&circuit, circuit.SECRET_INPUT("x"), circuit.SECRET_INPUT("y"))

	// add points in circuit (the method updates the underlying plain points as well)
	resPointSnark := pointSnark.AddFixedPoint(&circuit, &pointSnark, params.BaseX, params.BaseY, params)
	circuit.Tag(resPointSnark.X, "xg")
	circuit.Tag(resPointSnark.Y, "yg")

	inputs := make(map[string]interface{})
	inputs["x"] = "15132049151119024294202596478829150741889300374007672163496852915064138587014"
	inputs["y"] = "11523897191511824241384532572407048303306774918928882376450136656947192273193"

	expectedValues := make(map[string]interface{})
	expectedValues["xg"] = "4966531224162673480738068143298314346828081427171102366578720605707900725483"
	expectedValues["yg"] = "18072205942244039714668938595243139985382136665954711533267729308917439031819"

	// creates r1cs
	r1csbn256 := circuit.ToR1CS().ToR1CS(gurvy.BN256)

	assertbn256.CorrectExecution(r1csbn256, inputs, expectedValues)
}

func TestAddGeneric(t *testing.T) {

	circuit := frontend.NewConstraintSystem()

	assertbn256 := groth16.NewAssert(t)

	// get edwards curve gadget
	params, err := NewEdCurve(gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}

	// set the Snark points
	pointSnark1 := NewPoint(&circuit, circuit.SECRET_INPUT("x1"), circuit.SECRET_INPUT("y1"))
	pointSnark2 := NewPoint(&circuit, circuit.SECRET_INPUT("x2"), circuit.SECRET_INPUT("y2"))

	// add points in circuit (the method updates the underlying plain points as well)
	pointSnark1.AddGeneric(&circuit, &pointSnark1, &pointSnark2, params)
	circuit.Tag(pointSnark1.X, "xg")
	circuit.Tag(pointSnark1.Y, "yg")

	inputs := make(map[string]interface{})
	inputs["x1"] = "5299619240641551281634865583518297030282874472190772894086521144482721001553"
	inputs["y1"] = "16950150798460657717958625567821834550301663161624707787222815936182638968203"
	inputs["x2"] = "15132049151119024294202596478829150741889300374007672163496852915064138587014"
	inputs["y2"] = "11523897191511824241384532572407048303306774918928882376450136656947192273193"

	expectedValues := make(map[string]interface{})
	expectedValues["xg"] = "4966531224162673480738068143298314346828081427171102366578720605707900725483"
	expectedValues["yg"] = "18072205942244039714668938595243139985382136665954711533267729308917439031819"

	// creates r1cs
	r1csbn256 := circuit.ToR1CS().ToR1CS(gurvy.BN256)

	assertbn256.CorrectExecution(r1csbn256, inputs, expectedValues)
}

func TestDouble(t *testing.T) {

	circuit := frontend.NewConstraintSystem()

	assertbn256 := groth16.NewAssert(t)

	pointSnark := NewPoint(&circuit, circuit.SECRET_INPUT("x"), circuit.SECRET_INPUT("y"))

	// set curve parameters
	params, err := NewEdCurve(gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}

	// add points in circuit (the method updates the underlying plain points as well)
	pointSnark.Double(&circuit, &pointSnark, params)
	circuit.Tag(pointSnark.X, "xg")
	circuit.Tag(pointSnark.Y, "yg")

	inputs := make(map[string]interface{})
	inputs["x"] = "5299619240641551281634865583518297030282874472190772894086521144482721001553"
	inputs["y"] = "16950150798460657717958625567821834550301663161624707787222815936182638968203"

	expectedValues := make(map[string]interface{})
	expectedValues["xg"] = "10031262171927540148667355526369034398030886437092045105752248699557385197826"
	expectedValues["yg"] = "633281375905621697187330766174974863687049529291089048651929454608812697683"

	// creates r1cs
	r1csbn256 := circuit.ToR1CS().ToR1CS(gurvy.BN256)

	assertbn256.CorrectExecution(r1csbn256, inputs, expectedValues)
}

func TestScalarMulFixedBase(t *testing.T) {

	circuit := frontend.NewConstraintSystem()

	assertbn256 := groth16.NewAssert(t)

	// set curve parameters
	params, err := NewEdCurve(gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}

	// set point in the circuit
	pointSnark := NewPoint(&circuit, circuit.SECRET_INPUT("x"), circuit.SECRET_INPUT("y"))

	// set scalar
	scalar := circuit.ALLOCATE("28242048")

	inputs := make(map[string]interface{})
	inputs["x"] = "5299619240641551281634865583518297030282874472190772894086521144482721001553"
	inputs["y"] = "16950150798460657717958625567821834550301663161624707787222815936182638968203"

	// add points in circuit (the method updates the underlying plain points as well)
	pointSnark.ScalarMulFixedBase(&circuit, params.BaseX, params.BaseY, scalar, params)
	circuit.Tag(pointSnark.X, "xg")
	circuit.Tag(pointSnark.Y, "yg")

	expectedValues := make(map[string]interface{})
	expectedValues["xg"] = "10190477835300927557649934238820360529458681672073866116232821892325659279502"
	expectedValues["yg"] = "7969140283216448215269095418467361784159407896899334866715345504515077887397"

	// creates r1cs
	r1csbn256 := circuit.ToR1CS().ToR1CS(gurvy.BN256)

	assertbn256.CorrectExecution(r1csbn256, inputs, expectedValues)
}

func TestScalarMulNonFixedBase(t *testing.T) {

	circuit := frontend.NewConstraintSystem()

	assertbn256 := groth16.NewAssert(t)

	// set curve parameters
	params, err := NewEdCurve(gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}

	// set point in the circuit
	pointSnark := NewPoint(&circuit, circuit.SECRET_INPUT("x"), circuit.SECRET_INPUT("y"))

	// set scalar
	scalar := circuit.ALLOCATE("28242048")

	inputs := make(map[string]interface{})
	inputs["x"] = "5299619240641551281634865583518297030282874472190772894086521144482721001553"
	inputs["y"] = "16950150798460657717958625567821834550301663161624707787222815936182638968203"

	// add points in circuit (the method updates the underlying plain points as well)
	pointSnark.ScalarMulNonFixedBase(&circuit, &pointSnark, scalar, params)
	circuit.Tag(pointSnark.X, "xg")
	circuit.Tag(pointSnark.Y, "yg")

	expectedValues := make(map[string]interface{})
	expectedValues["xg"] = "10190477835300927557649934238820360529458681672073866116232821892325659279502"
	expectedValues["yg"] = "7969140283216448215269095418467361784159407896899334866715345504515077887397"

	// creates r1cs
	r1csbn256 := circuit.ToR1CS().ToR1CS(gurvy.BN256)

	assertbn256.CorrectExecution(r1csbn256, inputs, expectedValues)
}
