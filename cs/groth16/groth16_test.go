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

package groth16_test

import (
	"testing"

	"github.com/consensys/gnark/cs"
	"github.com/consensys/gnark/cs/groth16"
	"github.com/consensys/gnark/cs/internal/curve"
)

func TestExpoCircuit(t *testing.T) {
	assert := groth16.NewAssert(t)
	circuit := cs.New()

	x := circuit.SECRET_INPUT("x")
	e := circuit.SECRET_INPUT("e")
	y := circuit.PUBLIC_INPUT("y")

	o := circuit.ALLOCATE(1)
	b := circuit.TO_BINARY(e, 4)

	var i int
	for i < len(b) {
		o = circuit.MUL(o, o)
		mu := circuit.MUL(o, x)
		o = circuit.SELECT(b[len(b)-1-i], mu, o)
		i++
	}

	circuit.MUSTBE_EQ(y, o)

	good := cs.NewAssignment()
	good.Assign(cs.Secret, "x", 2)
	good.Assign(cs.Secret, "e", 12)
	good.Assign(cs.Public, "y", 4096)

	bad := cs.NewAssignment()
	bad.Assign(cs.Secret, "x", 2)
	bad.Assign(cs.Secret, "e", 12)
	bad.Assign(cs.Public, "y", 4095)

	assert.NotSolved(circuit, bad)
	assert.Solved(circuit, good, nil)

}

// func TestMimcCircuit(t *testing.T) {

// 	assert := groth16.NewAssert(t)
// circuit := cs.New()

// 	x := circuit.SECRET_INPUT("x")
// 	y := circuit.PUBLIC_INPUT("y")

// 	xl := hash.MIMC_INV(&circuit, x)

// 	circuit.MUSTBE_EQ(xl, y)

// 	good := cs.NewAssignment()
// 	good.Assign(cs.Secret, "x", "29827247284")
// 	good.Assign(cs.Public, "y", "4135445068682257674980835457060179120392794172455748655106635499667893875001")

// 	bad := cs.NewAssignment()
// 	bad.Assign(cs.Secret, "x", "29827247284")
// 	bad.Assign(cs.Public, "y", "4135445068682257674980835457060179120392794172455748655106635499667893875000")

// 	assert.NotSolved(circuit, bad)
// assert.Solved(circuit, good, nil)

// }

func TestRangeCircuit(t *testing.T) {

	assert := groth16.NewAssert(t)
	circuit := cs.New()

	x := circuit.SECRET_INPUT("x")
	y := circuit.PUBLIC_INPUT("y")

	c1 := circuit.MUL(x, y)
	c2 := circuit.MUL(c1, y)

	circuit.MUSTBE_LESS_OR_EQ(c2, 161)

	good := cs.NewAssignment()
	good.Assign(cs.Secret, "x", 10)
	good.Assign(cs.Public, "y", 4)

	bad := cs.NewAssignment()
	bad.Assign(cs.Secret, "x", 10)
	bad.Assign(cs.Public, "y", 5)

	assert.NotSolved(circuit, bad)
	assert.Solved(circuit, good, nil)

}

func TestCircuitConstantOps(t *testing.T) {

	assert := groth16.NewAssert(t)
	circuit := cs.New()

	x := circuit.SECRET_INPUT("x")
	y := circuit.PUBLIC_INPUT("y")

	elmts := make([]curve.Element, 3)
	for i := 0; i < 3; i++ {
		elmts[i].SetUint64(uint64(i) + 10)
	}
	c := circuit.ADD(x, elmts[0])
	c = circuit.MUL(c, elmts[1])
	c = circuit.SUB(c, elmts[2])
	circuit.MUSTBE_EQ(c, y)

	good := cs.NewAssignment()
	good.Assign(cs.Secret, "x", 12)
	good.Assign(cs.Public, "y", 230)

	bad := cs.NewAssignment()
	bad.Assign(cs.Secret, "x", 12)
	bad.Assign(cs.Public, "y", 228)

	assert.NotSolved(circuit, bad)
	assert.Solved(circuit, good, nil)
}

func TestInvCircuit(t *testing.T) {

	assert := groth16.NewAssert(t)
	circuit := cs.New()

	x := circuit.SECRET_INPUT("x")
	y := circuit.PUBLIC_INPUT("y")
	m := circuit.MUL(x, x)
	z := circuit.INV(m)
	circuit.MUSTBE_EQ(y, z)

	// expected z
	expectedY := curve.Element{}
	expectedY.SetUint64(4)
	expectedY.MulAssign(&expectedY).Inverse(&expectedY)

	good := cs.NewAssignment()
	good.Assign(cs.Secret, "x", 4)
	good.Assign(cs.Public, "y", expectedY)

	bad := cs.NewAssignment()
	bad.Assign(cs.Secret, "x", 4)
	bad.Assign(cs.Public, "y", 42)

	assert.NotSolved(circuit, bad)
	assert.Solved(circuit, good, nil)

}

func TestDivCircuit(t *testing.T) {

	assert := groth16.NewAssert(t)
	circuit := cs.New()

	x := circuit.SECRET_INPUT("x")
	y := circuit.SECRET_INPUT("y")
	z := circuit.PUBLIC_INPUT("z")
	m := circuit.MUL(x, x)
	d := circuit.DIV(m, y)
	circuit.MUSTBE_EQ(d, z)

	// expected z
	expectedZ := curve.Element{}
	expectedY := curve.Element{}
	expectedY.SetUint64(10)
	expectedZ.SetUint64(4)
	expectedZ.MulAssign(&expectedZ).Div(&expectedZ, &expectedY)

	good := cs.NewAssignment()
	good.Assign(cs.Secret, "x", 4)
	good.Assign(cs.Secret, "y", 10)
	good.Assign(cs.Public, "z", expectedZ)

	bad := cs.NewAssignment()
	bad.Assign(cs.Secret, "x", 4)
	bad.Assign(cs.Secret, "y", 10)
	bad.Assign(cs.Public, "z", 42)

	assert.NotSolved(circuit, bad)
	assert.Solved(circuit, good, nil)

}

func TestXor00Circuit(t *testing.T) {

	assert := groth16.NewAssert(t)
	circuit := cs.New()

	b0 := circuit.SECRET_INPUT("b0")
	b1 := circuit.SECRET_INPUT("b1")

	y0 := circuit.PUBLIC_INPUT("y0")

	circuit.MUSTBE_BOOLEAN(b0)
	circuit.MUSTBE_BOOLEAN(b1)

	z0 := circuit.XOR(b0, b1)

	circuit.MUSTBE_EQ(z0, y0)

	good := cs.NewAssignment()
	good.Assign(cs.Secret, "b0", 0)
	good.Assign(cs.Secret, "b1", 0)
	good.Assign(cs.Public, "y0", 0)

	bad := cs.NewAssignment()
	bad.Assign(cs.Secret, "b0", 0)
	bad.Assign(cs.Secret, "b1", 0)
	bad.Assign(cs.Public, "y0", 1)

	assert.NotSolved(circuit, bad)
	assert.Solved(circuit, good, nil)
}

func TestXor01Circuit(t *testing.T) {

	assert := groth16.NewAssert(t)
	circuit := cs.New()

	b0 := circuit.SECRET_INPUT("b0")
	b1 := circuit.SECRET_INPUT("b1")

	y0 := circuit.PUBLIC_INPUT("y0")

	circuit.MUSTBE_BOOLEAN(b0)
	circuit.MUSTBE_BOOLEAN(b1)

	z0 := circuit.XOR(b0, b1)

	circuit.MUSTBE_EQ(z0, y0)

	good := cs.NewAssignment()
	good.Assign(cs.Secret, "b0", 0)
	good.Assign(cs.Secret, "b1", 1)
	good.Assign(cs.Public, "y0", 1)

	bad := cs.NewAssignment()
	bad.Assign(cs.Secret, "b0", 0)
	bad.Assign(cs.Secret, "b1", 1)
	bad.Assign(cs.Public, "y0", 0)

	assert.NotSolved(circuit, bad)
	assert.Solved(circuit, good, nil)
}

func TestXor10Circuit(t *testing.T) {

	assert := groth16.NewAssert(t)
	circuit := cs.New()

	b0 := circuit.SECRET_INPUT("b0")
	b1 := circuit.SECRET_INPUT("b1")

	y0 := circuit.PUBLIC_INPUT("y0")

	circuit.MUSTBE_BOOLEAN(b0)
	circuit.MUSTBE_BOOLEAN(b1)

	z0 := circuit.XOR(b0, b1)

	circuit.MUSTBE_EQ(z0, y0)

	good := cs.NewAssignment()
	good.Assign(cs.Secret, "b0", 1)
	good.Assign(cs.Secret, "b1", 0)
	good.Assign(cs.Public, "y0", 1)

	bad := cs.NewAssignment()
	bad.Assign(cs.Secret, "b0", 1)
	bad.Assign(cs.Secret, "b1", 0)
	bad.Assign(cs.Public, "y0", 0)

	assert.NotSolved(circuit, bad)
	assert.Solved(circuit, good, nil)
}

func TestXor11Circuit(t *testing.T) {

	assert := groth16.NewAssert(t)
	circuit := cs.New()

	b0 := circuit.SECRET_INPUT("b0")
	b1 := circuit.SECRET_INPUT("b1")

	y0 := circuit.PUBLIC_INPUT("y0")

	circuit.MUSTBE_BOOLEAN(b0)
	circuit.MUSTBE_BOOLEAN(b1)

	z0 := circuit.XOR(b0, b1)

	circuit.MUSTBE_EQ(z0, y0)

	good := cs.NewAssignment()
	good.Assign(cs.Secret, "b0", 1)
	good.Assign(cs.Secret, "b1", 1)
	good.Assign(cs.Public, "y0", 0)

	bad := cs.NewAssignment()
	bad.Assign(cs.Secret, "b0", 1)
	bad.Assign(cs.Secret, "b1", 1)
	bad.Assign(cs.Public, "y0", 1)

	assert.NotSolved(circuit, bad)
	assert.Solved(circuit, good, nil)
}

func TestLookupTableCircuit00(t *testing.T) {

	assert := groth16.NewAssert(t)
	circuit := cs.New()

	b0 := circuit.SECRET_INPUT("b0")
	b1 := circuit.SECRET_INPUT("b1")

	z := circuit.PUBLIC_INPUT("z")

	circuit.MUSTBE_BOOLEAN(b0)
	circuit.MUSTBE_BOOLEAN(b1)

	var lookuptable [4]curve.Element

	lookuptable[0].SetUint64(10)
	lookuptable[1].SetUint64(12)
	lookuptable[2].SetUint64(22)
	lookuptable[3].SetUint64(7)

	r := circuit.SELECT_LUT(b1, b0, lookuptable)

	circuit.MUSTBE_EQ(r, z)

	good := cs.NewAssignment()
	good.Assign(cs.Secret, "b0", 0)
	good.Assign(cs.Secret, "b1", 0)
	good.Assign(cs.Public, "z", 10)

	bad := cs.NewAssignment()
	bad.Assign(cs.Secret, "b0", 0)
	bad.Assign(cs.Secret, "b1", 0)
	bad.Assign(cs.Public, "z", 11)

	assert.NotSolved(circuit, bad)
	assert.Solved(circuit, good, nil)
}

func TestLookupTableCircuit01(t *testing.T) {

	assert := groth16.NewAssert(t)
	circuit := cs.New()

	b0 := circuit.SECRET_INPUT("b0")
	b1 := circuit.SECRET_INPUT("b1")

	z := circuit.PUBLIC_INPUT("z")

	circuit.MUSTBE_BOOLEAN(b0)
	circuit.MUSTBE_BOOLEAN(b1)

	var lookuptable [4]curve.Element

	lookuptable[0].SetUint64(10)
	lookuptable[1].SetUint64(12)
	lookuptable[2].SetUint64(22)
	lookuptable[3].SetUint64(7)

	r := circuit.SELECT_LUT(b1, b0, lookuptable)

	circuit.MUSTBE_EQ(r, z)

	good := cs.NewAssignment()
	good.Assign(cs.Secret, "b0", 1)
	good.Assign(cs.Secret, "b1", 0)
	good.Assign(cs.Public, "z", 12)

	bad := cs.NewAssignment()
	bad.Assign(cs.Secret, "b0", 1)
	bad.Assign(cs.Secret, "b1", 0)
	bad.Assign(cs.Public, "z", 10)

	assert.NotSolved(circuit, bad)
	assert.Solved(circuit, good, nil)
}

func TestLookupTableCircuit10(t *testing.T) {

	assert := groth16.NewAssert(t)
	circuit := cs.New()

	b0 := circuit.SECRET_INPUT("b0")
	b1 := circuit.SECRET_INPUT("b1")

	z := circuit.PUBLIC_INPUT("z")

	circuit.MUSTBE_BOOLEAN(b0)
	circuit.MUSTBE_BOOLEAN(b1)

	var lookuptable [4]curve.Element

	lookuptable[0].SetUint64(10)
	lookuptable[1].SetUint64(12)
	lookuptable[2].SetUint64(22)
	lookuptable[3].SetUint64(7)

	r := circuit.SELECT_LUT(b1, b0, lookuptable)

	circuit.MUSTBE_EQ(r, z)

	good := cs.NewAssignment()
	good.Assign(cs.Secret, "b0", 0)
	good.Assign(cs.Secret, "b1", 1)
	good.Assign(cs.Public, "z", 22)

	bad := cs.NewAssignment()
	bad.Assign(cs.Secret, "b0", 0)
	bad.Assign(cs.Secret, "b1", 1)
	bad.Assign(cs.Public, "z", 11)

	assert.NotSolved(circuit, bad)
	assert.Solved(circuit, good, nil)
}

func TestLookupTableCircuit11(t *testing.T) {

	assert := groth16.NewAssert(t)
	circuit := cs.New()

	b0 := circuit.SECRET_INPUT("b0")
	b1 := circuit.SECRET_INPUT("b1")

	z := circuit.PUBLIC_INPUT("z")

	circuit.MUSTBE_BOOLEAN(b0)
	circuit.MUSTBE_BOOLEAN(b1)

	var lookuptable [4]curve.Element

	lookuptable[0].SetUint64(10)
	lookuptable[1].SetUint64(12)
	lookuptable[2].SetUint64(22)
	lookuptable[3].SetUint64(7)

	r := circuit.SELECT_LUT(b1, b0, lookuptable)

	circuit.MUSTBE_EQ(r, z)

	good := cs.NewAssignment()
	good.Assign(cs.Secret, "b0", 1)
	good.Assign(cs.Secret, "b1", 1)
	good.Assign(cs.Public, "z", 7)

	bad := cs.NewAssignment()
	bad.Assign(cs.Secret, "b0", 1)
	bad.Assign(cs.Secret, "b1", 1)
	bad.Assign(cs.Public, "z", 9)

	assert.NotSolved(circuit, bad)
	assert.Solved(circuit, good, nil)
}

func TestFromBinaryCircuit(t *testing.T) {

	assert := groth16.NewAssert(t)
	circuit := cs.New()

	b0 := circuit.SECRET_INPUT("b0")
	b1 := circuit.SECRET_INPUT("b1")
	b2 := circuit.SECRET_INPUT("b2")
	b3 := circuit.SECRET_INPUT("b3")

	circuit.MUSTBE_BOOLEAN(b0)
	circuit.MUSTBE_BOOLEAN(b1)
	circuit.MUSTBE_BOOLEAN(b2)
	circuit.MUSTBE_BOOLEAN(b3)

	y := circuit.PUBLIC_INPUT("y")

	r := circuit.FROM_BINARY(b0, b1, b2, b3)

	circuit.MUSTBE_EQ(y, r)

	good := cs.NewAssignment()
	good.Assign(cs.Secret, "b0", 1)
	good.Assign(cs.Secret, "b1", 0)
	good.Assign(cs.Secret, "b2", 1)
	good.Assign(cs.Secret, "b3", 1)
	good.Assign(cs.Public, "y", 13)

	bad := cs.NewAssignment()
	bad.Assign(cs.Secret, "b0", 1)
	bad.Assign(cs.Secret, "b1", 0)
	bad.Assign(cs.Secret, "b2", 1)
	bad.Assign(cs.Secret, "b3", 1)
	bad.Assign(cs.Public, "y", 12)

	assert.NotSolved(circuit, bad)
	assert.Solved(circuit, good, nil)
}

// test input
func TestParsePublicInput(t *testing.T) {

	expectedNames := [2]string{"data", "ONE_WIRE"}

	inputOneWire := cs.NewAssignment()
	inputOneWire.Assign(cs.Public, "ONE_WIRE", 3)
	_, errOneWire := groth16.ParsePublicInput(expectedNames[:], inputOneWire)
	if errOneWire == nil {
		t.Fatal("expected ErrGotOneWire error")
	}

	inputPrivate := cs.NewAssignment()
	inputPrivate.Assign(cs.Secret, "data", 3)
	_, errPrivate := groth16.ParsePublicInput(expectedNames[:], inputPrivate)
	if errPrivate == nil {
		t.Fatal("expected ErrGotPrivateInput error")
	}

	missingInput := cs.NewAssignment()
	_, errMissing := groth16.ParsePublicInput(expectedNames[:], missingInput)
	if errMissing == nil {
		t.Fatal("expected ErrMissingAssigment")
	}

	correctInput := cs.NewAssignment()
	correctInput.Assign(cs.Public, "data", 3)
	got, err := groth16.ParsePublicInput(expectedNames[:], correctInput)
	if err != nil {
		t.Fatal(err)
	}

	expected := make([]curve.Element, 2)
	expected[0].SetUint64(3).FromMont()
	expected[1].SetUint64(1).FromMont()
	if len(got) != len(expected) {
		t.Fatal("Unexpected length for assignment")
	}
	for i := 0; i < len(got); i++ {
		if !got[i].Equal(&expected[i]) {
			t.Fatal("error public assignment")
		}
	}

}

//--------------------//
//     benches		  //
//--------------------//

func referenceCircuit(nbConstraints int) (cs.CS, cs.Assignments, cs.Assignments) {

	circuit := cs.New()

	// declare inputs
	x := circuit.SECRET_INPUT("x")
	y := circuit.PUBLIC_INPUT("y")

	for i := 0; i < nbConstraints; i++ {
		x = circuit.MUL(x, x)
	}
	circuit.MUSTBE_EQ(x, y)

	good := cs.NewAssignment()
	good.Assign(cs.Secret, "x", 2)

	// compute expected Y
	expectedY := curve.Element{}
	expectedY.SetUint64(2)

	for i := 0; i < nbConstraints; i++ {
		expectedY.MulAssign(&expectedY)
	}

	good.Assign(cs.Public, "y", expectedY)

	bad := cs.NewAssignment()
	bad.Assign(cs.Secret, "x", 2)
	bad.Assign(cs.Public, "y", 0)

	return circuit, good, bad
}

const nbBenchmarkedConstraints = 2000

func TestBenchmarkCircuit(t *testing.T) {
	assert := groth16.NewAssert(t)
	circuit, good, bad := referenceCircuit(nbBenchmarkedConstraints)

	assert.NotSolved(circuit, bad)
	assert.Solved(circuit, good, nil)
}

func BenchmarkSetup(b *testing.B) {
	circuit, _, _ := referenceCircuit(nbBenchmarkedConstraints)
	groth16.BenchmarkSetup(b, circuit)
}

func BenchmarkProver(b *testing.B) {
	circuit, good, _ := referenceCircuit(nbBenchmarkedConstraints)
	groth16.BenchmarkProver(b, circuit, good)
}

func BenchmarkVerifier(b *testing.B) {
	circuit, good, _ := referenceCircuit(nbBenchmarkedConstraints)
	groth16.BenchmarkVerifier(b, circuit, good)
}
