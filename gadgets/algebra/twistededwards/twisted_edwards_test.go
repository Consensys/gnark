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

	backend_bn256 "github.com/consensys/gnark/backend/bn256"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
	fr_bn256 "github.com/consensys/gurvy/bn256/fr"
)

func TestIsOnCurve(t *testing.T) {

	circuit := frontend.New()

	assertbn256 := groth16.NewAssert(t)

	// get edwards curve gadget
	edgadget, err := NewEdCurveGadget(gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}

	// set the Snark point
	pointSnark := NewPointGadget(&circuit, circuit.SECRET_INPUT("x"), circuit.SECRET_INPUT("y"))

	pointSnark.MustBeOnCurveGadget(&circuit, edgadget)

	inputs := make(map[string]interface{})
	inputs["x"] = edgadget.BaseX
	inputs["y"] = edgadget.BaseY

	// creates r1cs
	r1csbn256 := circuit.ToR1CS().ToR1CS(gurvy.BN256).(*backend_bn256.R1CS)

	assertbn256.CorrectExecution(r1csbn256, inputs, nil)

}

func TestAdd(t *testing.T) {

	circuit := frontend.New()

	assertbn256 := groth16.NewAssert(t)

	// get edwards curve gadget
	edgadget, err := NewEdCurveGadget(gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}

	// set the Snark point
	pointSnark := NewPointGadget(&circuit, circuit.SECRET_INPUT("x"), circuit.SECRET_INPUT("y"))

	// add points in circuit (the method updates the underlying plain points as well)
	resPointSnark := pointSnark.AddFixedPoint(&circuit, &pointSnark, edgadget.BaseX, edgadget.BaseY, edgadget)
	resPointSnark.X.Tag("xg")
	resPointSnark.Y.Tag("yg")

	inputs := make(map[string]interface{})
	inputs["x"] = "15132049151119024294202596478829150741889300374007672163496852915064138587014"
	inputs["y"] = "11523897191511824241384532572407048303306774918928882376450136656947192273193"

	expectedValues := make(map[string]interface{})
	var expectedu, expectedv fr_bn256.Element
	expectedu.SetString("4966531224162673480738068143298314346828081427171102366578720605707900725483")
	expectedv.SetString("18072205942244039714668938595243139985382136665954711533267729308917439031819")
	expectedValues["xg"] = expectedu
	expectedValues["yg"] = expectedv

	// creates r1cs
	r1csbn256 := circuit.ToR1CS().ToR1CS(gurvy.BN256).(*backend_bn256.R1CS)

	assertbn256.CorrectExecution(r1csbn256, inputs, expectedValues)
}

func TestAddGeneric(t *testing.T) {

	circuit := frontend.New()

	assertbn256 := groth16.NewAssert(t)

	// get edwards curve gadget
	edgadget, err := NewEdCurveGadget(gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}

	// set the Snark points
	pointSnark1 := NewPointGadget(&circuit, circuit.SECRET_INPUT("x1"), circuit.SECRET_INPUT("y1"))
	pointSnark2 := NewPointGadget(&circuit, circuit.SECRET_INPUT("x2"), circuit.SECRET_INPUT("y2"))

	// add points in circuit (the method updates the underlying plain points as well)
	pointSnark1.AddGeneric(&circuit, &pointSnark1, &pointSnark2, edgadget)
	pointSnark1.X.Tag("xg")
	pointSnark1.Y.Tag("yg")

	inputs := make(map[string]interface{})
	inputs["x1"] = "5299619240641551281634865583518297030282874472190772894086521144482721001553"
	inputs["y1"] = "16950150798460657717958625567821834550301663161624707787222815936182638968203"
	inputs["x2"] = "15132049151119024294202596478829150741889300374007672163496852915064138587014"
	inputs["y2"] = "11523897191511824241384532572407048303306774918928882376450136656947192273193"

	expectedValues := make(map[string]interface{})
	var expectedu, expectedv fr_bn256.Element
	expectedu.SetString("4966531224162673480738068143298314346828081427171102366578720605707900725483")
	expectedv.SetString("18072205942244039714668938595243139985382136665954711533267729308917439031819")
	expectedValues["xg"] = expectedu
	expectedValues["yg"] = expectedv

	// creates r1cs
	r1csbn256 := circuit.ToR1CS().ToR1CS(gurvy.BN256).(*backend_bn256.R1CS)

	assertbn256.CorrectExecution(r1csbn256, inputs, expectedValues)
}

func TestDouble(t *testing.T) {

	circuit := frontend.New()

	assertbn256 := groth16.NewAssert(t)

	pointSnark := NewPointGadget(&circuit, circuit.SECRET_INPUT("x"), circuit.SECRET_INPUT("y"))

	// set curve parameters
	edgadget, err := NewEdCurveGadget(gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}

	// add points in circuit (the method updates the underlying plain points as well)
	pointSnark.Double(&circuit, &pointSnark, edgadget)
	pointSnark.X.Tag("xg")
	pointSnark.Y.Tag("yg")

	inputs := make(map[string]interface{})
	inputs["x"] = "5299619240641551281634865583518297030282874472190772894086521144482721001553"
	inputs["y"] = "16950150798460657717958625567821834550301663161624707787222815936182638968203"

	expectedValues := make(map[string]interface{})
	var expectedu, expectedv fr_bn256.Element
	expectedu.SetString("10031262171927540148667355526369034398030886437092045105752248699557385197826")
	expectedv.SetString("633281375905621697187330766174974863687049529291089048651929454608812697683")
	expectedValues["xg"] = expectedu
	expectedValues["yg"] = expectedv

	// creates r1cs
	r1csbn256 := circuit.ToR1CS().ToR1CS(gurvy.BN256).(*backend_bn256.R1CS)

	assertbn256.CorrectExecution(r1csbn256, inputs, expectedValues)
}

func TestScalarMulFixedBase(t *testing.T) {

	circuit := frontend.New()

	assertbn256 := groth16.NewAssert(t)

	// set curve parameters
	edgadget, err := NewEdCurveGadget(gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}

	// set point in the circuit
	pointSnark := NewPointGadget(&circuit, circuit.SECRET_INPUT("x"), circuit.SECRET_INPUT("y"))

	// set scalar
	scalar := circuit.ALLOCATE("28242048")

	inputs := make(map[string]interface{})
	inputs["x"] = "5299619240641551281634865583518297030282874472190772894086521144482721001553"
	inputs["y"] = "16950150798460657717958625567821834550301663161624707787222815936182638968203"

	// add points in circuit (the method updates the underlying plain points as well)
	pointSnark.ScalarMulFixedBase(&circuit, edgadget.BaseX, edgadget.BaseY, scalar, edgadget)
	pointSnark.X.Tag("xg")
	pointSnark.Y.Tag("yg")

	expectedValues := make(map[string]interface{})
	var expectedu, expectedv fr_bn256.Element
	expectedu.SetString("10190477835300927557649934238820360529458681672073866116232821892325659279502")
	expectedv.SetString("7969140283216448215269095418467361784159407896899334866715345504515077887397")
	expectedValues["xg"] = expectedu
	expectedValues["yg"] = expectedv

	// creates r1cs
	r1csbn256 := circuit.ToR1CS().ToR1CS(gurvy.BN256).(*backend_bn256.R1CS)

	assertbn256.CorrectExecution(r1csbn256, inputs, expectedValues)
}

func TestScalarMulNonFixedBase(t *testing.T) {

	circuit := frontend.New()

	assertbn256 := groth16.NewAssert(t)

	// set curve parameters
	edgadget, err := NewEdCurveGadget(gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}

	// set point in the circuit
	pointSnark := NewPointGadget(&circuit, circuit.SECRET_INPUT("x"), circuit.SECRET_INPUT("y"))

	// set scalar
	scalar := circuit.ALLOCATE("28242048")

	inputs := make(map[string]interface{})
	inputs["x"] = "5299619240641551281634865583518297030282874472190772894086521144482721001553"
	inputs["y"] = "16950150798460657717958625567821834550301663161624707787222815936182638968203"

	// add points in circuit (the method updates the underlying plain points as well)
	pointSnark.ScalarMulNonFixedBase(&circuit, &pointSnark, scalar, edgadget)
	pointSnark.X.Tag("xg")
	pointSnark.Y.Tag("yg")

	expectedValues := make(map[string]interface{})
	var expectedu, expectedv fr_bn256.Element
	expectedu.SetString("10190477835300927557649934238820360529458681672073866116232821892325659279502")
	expectedv.SetString("7969140283216448215269095418467361784159407896899334866715345504515077887397")
	expectedValues["xg"] = expectedu
	expectedValues["yg"] = expectedv

	// creates r1cs
	r1csbn256 := circuit.ToR1CS().ToR1CS(gurvy.BN256).(*backend_bn256.R1CS)

	assertbn256.CorrectExecution(r1csbn256, inputs, expectedValues)
}
