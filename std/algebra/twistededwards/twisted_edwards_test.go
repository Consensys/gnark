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

type mustBeOnCurve struct {
	P Point
}

func (circuit *mustBeOnCurve) Define(curveID gurvy.ID, cs *frontend.CS) error {
	// get edwards curve params
	params, err := NewEdCurve(curveID)
	if err != nil {
		return err
	}

	circuit.P.MustBeOnCurve(cs, params)

	return nil
}

func TestIsOnCurve(t *testing.T) {
	assert := groth16.NewAssert(t)
	var circuit, witness mustBeOnCurve
	r1cs, err := frontend.Compile(gurvy.BN256, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	params, err := NewEdCurve(gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}

	witness.P.X.Assign(params.BaseX)
	witness.P.Y.Assign(params.BaseY)

	good, err := frontend.ToAssignment(&witness)
	if err != nil {
		t.Fatal(err)
	}
	// creates r1cs
	assert.CorrectExecution(r1cs, good, nil)

}

type add struct {
	P Point
}

func (circuit *add) Define(curveID gurvy.ID, cs *frontend.CS) error {
	// get edwards curve params
	params, err := NewEdCurve(curveID)
	if err != nil {
		return err
	}

	res := circuit.P.AddFixedPoint(cs, &circuit.P, params.BaseX, params.BaseY, params)

	cs.MustBeEqual(res.X, "4966531224162673480738068143298314346828081427171102366578720605707900725483")
	cs.MustBeEqual(res.Y, "18072205942244039714668938595243139985382136665954711533267729308917439031819")

	return nil
}

func TestAdd(t *testing.T) {
	assert := groth16.NewAssert(t)
	var circuit, witness add
	r1cs, err := frontend.Compile(gurvy.BN256, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	witness.P.X.Assign("15132049151119024294202596478829150741889300374007672163496852915064138587014")
	witness.P.Y.Assign("11523897191511824241384532572407048303306774918928882376450136656947192273193")

	good, err := frontend.ToAssignment(&witness)
	if err != nil {
		t.Fatal(err)
	}
	// creates r1cs
	assert.CorrectExecution(r1cs, good, nil)

}

type addGeneric struct {
	P1, P2 Point
}

func (circuit *addGeneric) Define(curveID gurvy.ID, cs *frontend.CS) error {
	// get edwards curve params
	params, err := NewEdCurve(curveID)
	if err != nil {
		return err
	}

	res := circuit.P1.AddGeneric(cs, &circuit.P1, &circuit.P2, params)

	cs.MustBeEqual(res.X, "4966531224162673480738068143298314346828081427171102366578720605707900725483")
	cs.MustBeEqual(res.Y, "18072205942244039714668938595243139985382136665954711533267729308917439031819")

	return nil
}

func TestAddGeneric(t *testing.T) {
	assert := groth16.NewAssert(t)
	var circuit, witness addGeneric
	r1cs, err := frontend.Compile(gurvy.BN256, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	witness.P1.X.Assign("15132049151119024294202596478829150741889300374007672163496852915064138587014")
	witness.P1.Y.Assign("11523897191511824241384532572407048303306774918928882376450136656947192273193")

	witness.P2.X.Assign("5299619240641551281634865583518297030282874472190772894086521144482721001553")
	witness.P2.Y.Assign("16950150798460657717958625567821834550301663161624707787222815936182638968203")
	good, err := frontend.ToAssignment(&witness)
	if err != nil {
		t.Fatal(err)
	}
	// creates r1cs
	assert.CorrectExecution(r1cs, good, nil)

}

type double struct {
	P Point
}

func (circuit *double) Define(curveID gurvy.ID, cs *frontend.CS) error {
	// get edwards curve params
	params, err := NewEdCurve(curveID)
	if err != nil {
		return err
	}

	res := circuit.P.Double(cs, &circuit.P, params)

	cs.MustBeEqual(res.X, "10031262171927540148667355526369034398030886437092045105752248699557385197826")
	cs.MustBeEqual(res.Y, "633281375905621697187330766174974863687049529291089048651929454608812697683")
	return nil
}

func TestDouble(t *testing.T) {
	assert := groth16.NewAssert(t)
	var circuit, witness double
	r1cs, err := frontend.Compile(gurvy.BN256, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	witness.P.X.Assign("5299619240641551281634865583518297030282874472190772894086521144482721001553")
	witness.P.Y.Assign("16950150798460657717958625567821834550301663161624707787222815936182638968203")

	good, err := frontend.ToAssignment(&witness)
	if err != nil {
		t.Fatal(err)
	}
	// creates r1cs
	assert.CorrectExecution(r1cs, good, nil)

}

type scalarMul struct {
	P Point
}

func (circuit *scalarMul) Define(curveID gurvy.ID, cs *frontend.CS) error {
	// get edwards curve params
	params, err := NewEdCurve(curveID)
	if err != nil {
		return err
	}
	scalar := cs.Allocate("28242048")
	nonFixed := circuit.P.ScalarMulNonFixedBase(cs, &circuit.P, scalar, params)
	res := circuit.P.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, scalar, params)
	cs.MustBeEqual(res.X, "10190477835300927557649934238820360529458681672073866116232821892325659279502")
	cs.MustBeEqual(res.Y, "7969140283216448215269095418467361784159407896899334866715345504515077887397")
	cs.MustBeEqual(nonFixed.X, "10190477835300927557649934238820360529458681672073866116232821892325659279502")
	cs.MustBeEqual(nonFixed.Y, "7969140283216448215269095418467361784159407896899334866715345504515077887397")
	return nil
}

func TestScalarMul(t *testing.T) {
	assert := groth16.NewAssert(t)
	var circuit, witness scalarMul
	r1cs, err := frontend.Compile(gurvy.BN256, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	witness.P.X.Assign("5299619240641551281634865583518297030282874472190772894086521144482721001553")
	witness.P.Y.Assign("16950150798460657717958625567821834550301663161624707787222815936182638968203")

	good, err := frontend.ToAssignment(&witness)
	if err != nil {
		t.Fatal(err)
	}
	// creates r1cs
	assert.CorrectExecution(r1cs, good, nil)

}
