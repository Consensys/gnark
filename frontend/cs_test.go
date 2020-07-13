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

package frontend

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/stretchr/testify/require"
)

func TestDuplicateSecretInput(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("declaring same name twice for private input, code should panic")
		}
	}()

	circuit := New()

	circuit.SECRET_INPUT("x")
	circuit.SECRET_INPUT("x")
}

func TestDuplicatePublicInput(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("declaring same name twice for public input, code should panic")
		}
	}()

	circuit := New()

	circuit.PUBLIC_INPUT("x")
	circuit.PUBLIC_INPUT("x")
}

func TestInconsistantConstraints1(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("user input 1 == user input 2 is pointless")
		}
	}()

	circuit := New()

	x := circuit.PUBLIC_INPUT("x")
	y := circuit.PUBLIC_INPUT("y")

	circuit.MUSTBE_EQ(x, y)
}

func TestInconsistantConstraints2(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("user input 1 == user input 1 is pointless")
		}
	}()

	circuit := New()

	x := circuit.PUBLIC_INPUT("x")

	circuit.MUSTBE_EQ(x, x)
}

func TestInconsistantConstraints3(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("user input == 3 is pointless")
		}
	}()

	circuit := New()

	x := circuit.PUBLIC_INPUT("x")

	circuit.MUSTBE_EQ(x, 3)
}

// checks if creation of constraint system works
func TestOneWireConstraint(t *testing.T) {
	assert := require.New(t)
	circuit := New()
	nbWires := circuit.countWires()

	assert.Equal(1, nbWires, "Newly created constraint system should have 1 wire")
	assert.Equal(1, int(circuit.nbConstraints), "Newly created constraint system should have 1 constraint")

	val, ok := circuit.Constraints[0]
	assert.True(ok, "constraint map should contain ONE_WIRE")
	assert.Equal(backend.OneWire, val.getOutputWire().Name, "constraint map should contain ONE_WIRE")

	_ = circuit.ALLOCATE(1)
	assert.Equal(1, int(circuit.nbConstraints), "ALLOCATE(1) should return existing ONEWIRE")
}

func TestADD(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	circuit := New()

	var val big.Int
	val.SetUint64(4)

	x := circuit.PUBLIC_INPUT("x")

	circuit.ADD(x, x).Tag("x+x")
	circuit.ADD(x, val).Tag("x+4")
	circuit.ADD(val, x).Tag("4+x")

	// tests CS
	assert.csIsCorrect(circuit, expectedCS{
		nbWires:         5,
		nbConstraints:   5,
		nbMOConstraints: 0,
		nbNOConstraints: 0,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(circuit, expectedR1CS{
		nbWires:                    5,
		nbComputationalConstraints: 3,
		nbConstraints:              3,
		nbPrivateWires:             0,
		nbPublicWires:              2,
	})

	// bad := make(map[string]interface{})
	// good := make(map[string]interface{})
	// expectedValues := make(map[string]interface{})

	// // good solution
	// good[ "x", 42)

	// // expected values
	// expectedValues["x"] = 42
	// expectedValues["x+x"] = 42 + 42
	// expectedValues["x+4"] = 42 + 4
	// expectedValues["4+x"] = 4 + 42

	// assert.NotSolved(circuit, bad)
	// assert.Solved(circuit, good, expectedValues)
}

func TestSUB(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	circuit := New()

	var val big.Int
	val.SetUint64(4)

	x := circuit.PUBLIC_INPUT("x")

	circuit.SUB(x, x).Tag("x-x")
	circuit.SUB(x, val).Tag("x-4")
	circuit.SUB(val, x).Tag("4-x")

	// tests CS
	assert.csIsCorrect(circuit, expectedCS{
		nbWires:         5,
		nbConstraints:   5,
		nbMOConstraints: 0,
		nbNOConstraints: 0,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(circuit, expectedR1CS{
		nbWires:                    5,
		nbComputationalConstraints: 3,
		nbConstraints:              3,
		nbPrivateWires:             0,
		nbPublicWires:              2,
	})

	// bad := make(map[string]interface{})
	// good := make(map[string]interface{})
	// expectedValues := make(map[string]interface{})

	// // good solution
	// good[ "x", 42)

	// // expected values
	// expectedValues["x"] = 42
	// expectedValues["x-x"] = 0
	// expectedValues["x-4"] = 42 - 4
	// fourMinus42 := backend.FromInterface(42)
	// fourMinus42.Sub(&val, &fourMinus42)
	// expectedValues["4-x"] = fourMinus42

	// assert.NotSolved(circuit, bad)
	// assert.Solved(circuit, good, expectedValues)
}

func TestMUL(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	circuit := New()

	var val big.Int
	val.SetUint64(4)

	x := circuit.PUBLIC_INPUT("x")

	circuit.MUL(x, x).Tag("x^2")
	circuit.MUL(x, val).Tag("x*4")
	circuit.MUL(val, x).Tag("4*x")

	// tests CS
	assert.csIsCorrect(circuit, expectedCS{
		nbWires:         5,
		nbConstraints:   5,
		nbMOConstraints: 0,
		nbNOConstraints: 0,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(circuit, expectedR1CS{
		nbWires:                    5,
		nbComputationalConstraints: 3,
		nbConstraints:              3,
		nbPrivateWires:             0,
		nbPublicWires:              2,
	})

	// bad := make(map[string]interface{})
	// good := make(map[string]interface{})
	// expectedValues := make(map[string]interface{})

	// // good solution
	// good[ "x", 42)

	// // expected values
	// expectedValues["x"] = 42
	// expectedValues["x^2"] = 42 * 42
	// expectedValues["x*4"] = 42 * 4
	// expectedValues["4*x"] = 4 * 42

	// assert.NotSolved(circuit, bad)
	// assert.Solved(circuit, good, expectedValues)
}

func TestDIV(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	circuit := New()

	x := circuit.PUBLIC_INPUT("x")
	y := circuit.PUBLIC_INPUT("y")

	circuit.DIV(x, y).Tag("x/y")

	// tests CS
	assert.csIsCorrect(circuit, expectedCS{
		nbWires:         4,
		nbConstraints:   4,
		nbMOConstraints: 0,
		nbNOConstraints: 0,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(circuit, expectedR1CS{
		nbWires:                    4,
		nbComputationalConstraints: 1,
		nbConstraints:              1,
		nbPrivateWires:             0,
		nbPublicWires:              3,
	})

	// bad := make(map[string]interface{})
	// good := make(map[string]interface{})
	// expectedValues := make(map[string]interface{})

	// // good solution
	// good[ "x", 42)
	// good[ "y", 142)

	// // expected values
	// xVal := backend.FromInterface(42)
	// xDiv := backend.FromInterface(142)
	// xDiv.Div(&xVal, &xDiv)
	// expectedValues["x"] = xVal
	// expectedValues["x/y"] = xDiv

	// assert.NotSolved(circuit, bad)
	// assert.Solved(circuit, good, expectedValues)
}

func TestDIVLC(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	circuit := New()

	x := circuit.PUBLIC_INPUT("x")
	y := circuit.PUBLIC_INPUT("y")

	two := backend.FromInterface(2)

	l1 := LinearCombination{Term{Variable: x, Coeff: two}}
	l2 := LinearCombination{Term{Variable: y, Coeff: two}}

	circuit.DIV(l1, l2).Tag("res")

	// tests CS
	assert.csIsCorrect(circuit, expectedCS{
		nbWires:         4,
		nbConstraints:   4,
		nbMOConstraints: 0,
		nbNOConstraints: 0,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(circuit, expectedR1CS{
		nbWires:                    4,
		nbComputationalConstraints: 1,
		nbConstraints:              1,
		nbPrivateWires:             0,
		nbPublicWires:              3,
	})

	// bad := make(map[string]interface{})
	// good := make(map[string]interface{})
	// expectedValues := make(map[string]interface{})

	// // good solution
	// good[ "x", 8000)
	// good[ "y", 80)

	// // expected values
	// expectedValues["x"] = 8000
	// expectedValues["y"] = 80
	// expectedValues["res"] = (8000 * 2) / (80 * 2)

	// assert.NotSolved(circuit, bad)
	// assert.Solved(circuit, good, expectedValues)
}

func TestMULLC(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	circuit := New()

	x := circuit.PUBLIC_INPUT("x")
	y := circuit.PUBLIC_INPUT("y")

	two := backend.FromInterface(2)

	l1 := LinearCombination{Term{Variable: x, Coeff: two}}
	l2 := LinearCombination{Term{Variable: y, Coeff: two}}

	circuit.MUL(l1, l2).Tag("res")

	// tests CS
	assert.csIsCorrect(circuit, expectedCS{
		nbWires:         4,
		nbConstraints:   4,
		nbMOConstraints: 0,
		nbNOConstraints: 0,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(circuit, expectedR1CS{
		nbWires:                    4,
		nbComputationalConstraints: 1,
		nbConstraints:              1,
		nbPrivateWires:             0,
		nbPublicWires:              3,
	})

	// bad := make(map[string]interface{})
	// good := make(map[string]interface{})
	// expectedValues := make(map[string]interface{})

	// // good solution
	// good[ "x", 8000)
	// good[ "y", 80)

	// // expected values
	// expectedValues["x"] = 8000
	// expectedValues["y"] = 80
	// expectedValues["res"] = (8000 * 2) * (80 * 2)

	// assert.NotSolved(circuit, bad)
	// assert.Solved(circuit, good, expectedValues)
}

func TestSELECT(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	circuit := New()

	x := circuit.PUBLIC_INPUT("x")
	y := circuit.PUBLIC_INPUT("y")
	z := circuit.PUBLIC_INPUT("z")

	circuit.SELECT(x, y, z).Tag("res")

	// tests CS
	assert.csIsCorrect(circuit, expectedCS{
		nbWires:         5,
		nbConstraints:   5,
		nbMOConstraints: 0,
		nbNOConstraints: 1, // x must be boolean constrained
	})

	// tests solving R1CS
	assert.r1csIsCorrect(circuit, expectedR1CS{
		nbWires:                    5,
		nbComputationalConstraints: 1,
		nbConstraints:              2,
		nbPrivateWires:             0,
		nbPublicWires:              4,
	})

	// bad := make(map[string]interface{})
	// good := make(map[string]interface{})
	// expectedValues := make(map[string]interface{})

	// // bad solution (x is not a boolean)
	// bad[ "x", 10)
	// bad[ "y", 42)
	// bad[ "z", 8000)

	// // good solution
	// good[ "x", 0)
	// good[ "y", 42)
	// good[ "z", 8000)

	// // expected values
	// expectedValues["x"] = 0
	// expectedValues["y"] = 42
	// expectedValues["z"] = 8000
	// expectedValues["res"] = 8000

	// assert.NotSolved(circuit, bad)
	// assert.Solved(circuit, good, expectedValues)
}

func TestFROM_BINARY(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	circuit := New()

	b0 := circuit.PUBLIC_INPUT("b0")
	b1 := circuit.PUBLIC_INPUT("b1")
	b2 := circuit.PUBLIC_INPUT("b2")
	b3 := circuit.PUBLIC_INPUT("b3")
	b4 := circuit.PUBLIC_INPUT("b4")

	circuit.FROM_BINARY(b0, b1, b2, b3, b4).Tag("res")

	// tests CS
	assert.csIsCorrect(circuit, expectedCS{
		nbWires:         7,
		nbConstraints:   7,
		nbMOConstraints: 0,
		nbNOConstraints: 5, //b0..b4 are boolean constrained
	})

	// tests solving R1CS
	assert.r1csIsCorrect(circuit, expectedR1CS{
		nbWires:                    7,
		nbComputationalConstraints: 1,
		nbConstraints:              6,
		nbPrivateWires:             0,
		nbPublicWires:              6,
	})

	// bad := make(map[string]interface{})
	// good := make(map[string]interface{})
	// expectedValues := make(map[string]interface{})

	// // bad solution (b0 == 3, not a bit)
	// bad[ "b0", 3)
	// bad[ "b1", 0)
	// bad[ "b2", 1)
	// bad[ "b3", 1)
	// bad[ "b4", 0)

	// // good solution
	// good[ "b0", 1)
	// good[ "b1", 0)
	// good[ "b2", 1)
	// good[ "b3", 0)
	// good[ "b4", 1)

	// // expected values
	// expectedValues["b0"] = 1
	// expectedValues["b1"] = 0
	// expectedValues["b2"] = 1
	// expectedValues["b3"] = 0
	// expectedValues["b4"] = 1

	// expectedValues["res"] = 1 + 2*0 + 4*1 + 8*0 + 16*1

	// assert.NotSolved(circuit, bad)
	// assert.Solved(circuit, good, expectedValues)
}

func TestTO_BINARY(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	circuit := New()

	x := circuit.PUBLIC_INPUT("x")

	res := circuit.TO_BINARY(x, 5)
	for i, r := range res {
		r.Tag(fmt.Sprintf("res%d", i))
	}

	// tests CS
	assert.csIsCorrect(circuit, expectedCS{
		nbWires:         7,
		nbConstraints:   7,
		nbMOConstraints: 1,
		nbNOConstraints: 5,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(circuit, expectedR1CS{
		nbWires:                    7,
		nbComputationalConstraints: 5,
		nbConstraints:              10,
		nbPrivateWires:             0,
		nbPublicWires:              2,
	})

	// bad := make(map[string]interface{})
	// good := make(map[string]interface{})
	// expectedValues := make(map[string]interface{})

	// bad solution
	// bad[ "x", 64) // TODO doesn't fit on 5 bits

	// good solution
	// good[ "x", 17)

	// // expected values
	// expectedValues["x"] = 17
	// expectedValues["res0"] = 1
	// expectedValues["res1"] = 0
	// expectedValues["res2"] = 0
	// expectedValues["res3"] = 0
	// expectedValues["res4"] = 1

	// assert.NotSolved(circuit, bad)
	// assert.Solved(circuit, good, expectedValues)
}

func TestSELECT_LUT(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	circuit := New()

	b0 := circuit.SECRET_INPUT("b0")
	b1 := circuit.SECRET_INPUT("b1")

	var lut [4]big.Int
	lut[0] = backend.FromInterface(42)
	lut[2] = backend.FromInterface(8000)

	circuit.SELECT_LUT(b0, b1, lut).Tag(("res"))

	// tests CS
	assert.csIsCorrect(circuit, expectedCS{
		nbWires:         4,
		nbConstraints:   4,
		nbMOConstraints: 0,
		nbNOConstraints: 2,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(circuit, expectedR1CS{
		nbWires:                    4,
		nbComputationalConstraints: 1,
		nbConstraints:              3,
		nbPrivateWires:             2,
		nbPublicWires:              1,
	})

	// bad := make(map[string]interface{})
	// good := make(map[string]interface{})
	// expectedValues := make(map[string]interface{})

	// // bad solution (non boolean inputs)
	// bad[ "b0", 22)
	// bad[ "b1", 22)

	// // good solution
	// good[ "b0", 1)
	// good[ "b1", 0)

	// // expected values
	// expectedValues["b0"] = 1
	// expectedValues["b1"] = 0
	// expectedValues["res"] = 8000

	// assert.NotSolved(circuit, bad)
	// assert.Solved(circuit, good, expectedValues)
}

func TestXOR(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	circuit := New()

	x := circuit.PUBLIC_INPUT("x")
	y := circuit.PUBLIC_INPUT("y")
	z := circuit.PUBLIC_INPUT("z")

	r0 := circuit.XOR(x, y)
	r1 := circuit.XOR(x, r0)
	r2 := circuit.XOR(y, z)

	r0.Tag("r0")
	r1.Tag("r1")
	r2.Tag("r2")

	// tests CS
	assert.csIsCorrect(circuit, expectedCS{
		nbWires:         7,
		nbConstraints:   7,
		nbMOConstraints: 0,
		nbNOConstraints: 3,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(circuit, expectedR1CS{
		nbWires:                    7,
		nbComputationalConstraints: 3,
		nbConstraints:              6,
		nbPrivateWires:             0,
		nbPublicWires:              4,
	})

	// bad := make(map[string]interface{})
	// good := make(map[string]interface{})
	// expectedValues := make(map[string]interface{})

	// // bad solution (non boolean inputs)
	// bad[ "x", 22)
	// bad[ "y", 22)
	// bad[ "z", 22)

	// // good solution
	// good[ "x", 1)
	// good[ "y", 0)
	// good[ "z", 0)

	// // expected values
	// expectedValues["x"] = 1
	// expectedValues["y"] = 0
	// expectedValues["z"] = 0
	// expectedValues["r0"] = 1
	// expectedValues["r1"] = 0
	// expectedValues["r2"] = 0

	// assert.NotSolved(circuit, bad)
	// assert.Solved(circuit, good, expectedValues)
}
func TestALLOC(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	circuit := New()

	x := circuit.ALLOCATE(4)
	x.Tag("x")

	// tests CS
	assert.csIsCorrect(circuit, expectedCS{
		nbWires:         2,
		nbConstraints:   2,
		nbMOConstraints: 0,
		nbNOConstraints: 0,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(circuit, expectedR1CS{
		nbWires:                    2,
		nbComputationalConstraints: 1,
		nbConstraints:              1,
		nbPrivateWires:             0,
		nbPublicWires:              1,
	})

	// bad := make(map[string]interface{})
	// good := make(map[string]interface{})
	// expectedValues := make(map[string]interface{})

	// expectedValues["x"] = 4

	// // assert.NotSolved(circuit, bad)
	// assert.Solved(circuit, good, expectedValues)
}

func TestMUSTBE_BOOL(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	circuit := New()

	x := circuit.PUBLIC_INPUT("x")

	circuit.MUSTBE_BOOLEAN(x)
	// TODO add back this test
	// xx := *x
	// xx := &
	// circuit.MUSTBE_BOOLEAN(&xx) // calling MUSTBE_BOOLEAN twice should not add a duplicate constraint

	// tests CS
	assert.csIsCorrect(circuit, expectedCS{
		nbWires:         2,
		nbConstraints:   2,
		nbMOConstraints: 0,
		nbNOConstraints: 1,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(circuit, expectedR1CS{
		nbWires:                    2,
		nbComputationalConstraints: 0,
		nbConstraints:              1,
		nbPrivateWires:             0,
		nbPublicWires:              2,
	})

	// bad := make(map[string]interface{})
	// good := make(map[string]interface{})
	// expectedValues := make(map[string]interface{})

	// // bad solution
	// bad[ "x", 12)

	// // good solution
	// good[ "x", 1)

	// // expected values
	// expectedValues["x"] = 1

	// assert.NotSolved(circuit, bad)
	// assert.Solved(circuit, good, expectedValues)
}

func TestXtimes2EqualsY(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	circuit := New()

	x := circuit.PUBLIC_INPUT("x")
	y := circuit.SECRET_INPUT("y")
	cst := circuit.ALLOCATE(2)
	cst.Tag("cst")

	circuit.MUSTBE_EQ(circuit.MUL(x, cst), y)

	// tests CS
	assert.csIsCorrect(circuit, expectedCS{
		nbWires:         4,
		nbConstraints:   5,
		nbMOConstraints: 0,
		nbNOConstraints: 0,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(circuit, expectedR1CS{
		nbWires:                    4, // TODO why 1 wire for cst?
		nbComputationalConstraints: 1,
		nbConstraints:              2,
		nbPrivateWires:             1,
		nbPublicWires:              2,
	})

	// bad := make(map[string]interface{})
	// good := make(map[string]interface{})
	// expectedValues := make(map[string]interface{})

	// // bad solution
	// bad[ "x", 42)
	// bad[ "y", 42*42)

	// // good solution
	// good[ "x", 42)
	// good[ "y", 42*2)

	// // expected values
	// expectedValues["x"] = 42
	// expectedValues["y"] = 42 * 2
	// expectedValues["cst"] = 2

	// assert.NotSolved(circuit, bad)
	// assert.Solved(circuit, good, expectedValues)
}

func TestINV(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	circuit := New()

	x := circuit.PUBLIC_INPUT("x")

	circuit.INV(x).Tag("x^-1")

	// tests CS
	assert.csIsCorrect(circuit, expectedCS{
		nbWires:         3,
		nbConstraints:   3,
		nbMOConstraints: 0,
		nbNOConstraints: 0,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(circuit, expectedR1CS{
		nbWires:                    3,
		nbComputationalConstraints: 1,
		nbConstraints:              1,
		nbPrivateWires:             0,
		nbPublicWires:              2,
	})

	// bad := make(map[string]interface{})
	// good := make(map[string]interface{})
	// expectedValues := make(map[string]interface{})

	// // bad solution
	// // no input

	// // good solution
	// good[ "x", 42)

	// expected values
	// t.Skip("TODO INVERSE")
	// TODO inverse
	// xVal := backend.FromInterface(42)
	// var xInvVal big.Int

	// xInvVal.Inverse(&xVal)
	// expectedValues["x"] = 42
	// expectedValues["x^-1"] = xInvVal

	// assert.NotSolved(circuit, bad)
	// assert.Solved(circuit, good, expectedValues)
}

func TestMerge(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	circuit := New()

	u := circuit.SECRET_INPUT("u")
	v := circuit.SECRET_INPUT("v")
	w := circuit.PUBLIC_INPUT("w")

	a0 := circuit.INV(u)
	a0.Tag("a0")
	a1 := circuit.MUL(a0, v)
	a1.Tag("a1")
	circuit.MUSTBE_EQ(w, a1)

	// tests CS
	assert.csIsCorrect(circuit, expectedCS{
		nbWires:         5,
		nbConstraints:   6,
		nbMOConstraints: 0,
		nbNOConstraints: 0,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(circuit, expectedR1CS{
		nbWires:                    5,
		nbComputationalConstraints: 1,
		nbConstraints:              2,
		nbPrivateWires:             2,
		nbPublicWires:              2,
	})
	// TODO missing inverse
	// t.Skip("missing inverse TODO")

	// bad := make(map[string]interface{})
	// good := make(map[string]interface{})
	// expectedValues := make(map[string]interface{})

	// // bad solution
	// bad[ "u", 42)
	// bad[ "v", 8000)
	// bad[ "w", 42)

	// good solution
	// uVal := backend.FromInterface(2)
	// var uInvVal big.Int
	// uInvVal.Inverse(&uVal)
	// wWal := backend.FromInterface(65536)
	// wWal.Mul(&wWal, &uInvVal)

	// good[ "u", 2)
	// good[ "v", 65536)
	// // good[ "w", wWal)

	// expectedValues["u"] = 2
	// expectedValues["v"] = 65536
	// expectedValues["w"] = wWal
	// // expectedValues["a0"] = uInvVal
	// expectedValues["a1"] = wWal

	// assert.NotSolved(circuit, bad)
	// assert.Solved(circuit, good, expectedValues)
}

func TestMergeMoeNoe(t *testing.T) {

	// test helper
	assert := NewAssert(t)

	// circuit definition
	circuit := New()

	u := circuit.SECRET_INPUT("u")
	w := circuit.PUBLIC_INPUT("w")

	b := circuit.TO_BINARY(w, 3)
	b[0].Tag("b0")
	b[1].Tag("b1")
	b[2].Tag("b2")

	circuit.MUSTBE_EQ(b[0], u)

	// tests CS
	assert.csIsCorrect(circuit, expectedCS{
		nbWires:         5,
		nbConstraints:   6,
		nbMOConstraints: 1,
		nbNOConstraints: 3,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(circuit, expectedR1CS{
		nbWires:                    5,
		nbComputationalConstraints: 2,
		nbConstraints:              5,
		nbPrivateWires:             1,
		nbPublicWires:              2,
	})

	// bad := make(map[string]interface{})
	// good := make(map[string]interface{})
	// expectedValues := make(map[string]interface{})

	// // bad solution
	// bad[ "u", 0)
	// bad[ "w", 5)

	// // good solution
	// good[ "u", 1)
	// good[ "w", 5)

	// expectedValues["u"] = 1
	// expectedValues["w"] = 5
	// expectedValues["b0"] = 1
	// expectedValues["b1"] = 0
	// expectedValues["b2"] = 1

	// assert.NotSolved(circuit, bad)
	// assert.Solved(circuit, good, expectedValues)
}
