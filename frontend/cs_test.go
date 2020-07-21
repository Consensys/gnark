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

	cs := NewConstraintSystem()

	cs.SECRET_INPUT("x")
	cs.SECRET_INPUT("x")
}

func TestDuplicatePublicInput(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("declaring same name twice for public input, code should panic")
		}
	}()

	cs := NewConstraintSystem()

	cs.PUBLIC_INPUT("x")
	cs.PUBLIC_INPUT("x")
}

func TestInconsistantConstraints1(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("user input 1 == user input 2 is pointless")
		}
	}()

	cs := NewConstraintSystem()

	x := cs.PUBLIC_INPUT("x")
	y := cs.PUBLIC_INPUT("y")

	cs.MUSTBE_EQ(x, y)
}

func TestInconsistantConstraints2(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("user input 1 == user input 1 is pointless")
		}
	}()

	cs := NewConstraintSystem()

	x := cs.PUBLIC_INPUT("x")

	cs.MUSTBE_EQ(x, x)
}

func TestInconsistantConstraints3(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("user input == 3 is pointless")
		}
	}()

	cs := NewConstraintSystem()

	x := cs.PUBLIC_INPUT("x")

	cs.MUSTBE_EQ(x, 3)
}

// checks if creation of constraint system works
func TestOneWireConstraint(t *testing.T) {
	assert := require.New(t)
	cs := NewConstraintSystem()
	nbWires := cs.countWires()

	assert.Equal(1, nbWires, "Newly created constraint system should have 1 wire")
	assert.Equal(1, int(cs.nbConstraints()), "Newly created constraint system should have 1 constraint")

	val := cs.constraints[oneWireID]
	oneWire := cs.publicWireNames[val.ID]
	assert.Equal(backend.OneWire, oneWire, "constraint map should contain ONE_WIRE")

	_ = cs.ALLOCATE(1)
	assert.Equal(1, int(cs.nbConstraints()), "ALLOCATE(1) should return existing ONEWIRE")
}

func TestADD(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	cs := NewConstraintSystem()

	var val big.Int
	val.SetUint64(4)

	x := cs.PUBLIC_INPUT("x")

	cs.ADD(x, x)
	cs.ADD(x, val)
	cs.ADD(val, x)

	// tests CS
	assert.csIsCorrect(cs, expectedCS{
		nbWires:         5,
		nbConstraints:   5,
		nbMOConstraints: 0,
		nbNOConstraints: 0,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(cs, expectedR1CS{
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

	// assert.NotSolved(cs, bad)
	// assert.Solved(cs, good, expectedValues)
}

func TestSUB(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	cs := NewConstraintSystem()

	var val big.Int
	val.SetUint64(4)

	x := cs.PUBLIC_INPUT("x")

	cs.SUB(x, x)
	cs.SUB(x, val)
	cs.SUB(val, x)

	// tests CS
	assert.csIsCorrect(cs, expectedCS{
		nbWires:         5,
		nbConstraints:   5,
		nbMOConstraints: 0,
		nbNOConstraints: 0,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(cs, expectedR1CS{
		nbWires:                    5,
		nbComputationalConstraints: 3,
		nbConstraints:              3,
		nbPrivateWires:             0,
		nbPublicWires:              2,
	})

}

func TestMUL(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	cs := NewConstraintSystem()

	var val big.Int
	val.SetUint64(4)

	x := cs.PUBLIC_INPUT("x")

	cs.MUL(x, x)
	cs.MUL(x, val)
	cs.MUL(val, x)

	// tests CS
	assert.csIsCorrect(cs, expectedCS{
		nbWires:         5,
		nbConstraints:   5,
		nbMOConstraints: 0,
		nbNOConstraints: 0,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(cs, expectedR1CS{
		nbWires:                    5,
		nbComputationalConstraints: 3,
		nbConstraints:              3,
		nbPrivateWires:             0,
		nbPublicWires:              2,
	})

}

func TestDIV(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	cs := NewConstraintSystem()

	x := cs.PUBLIC_INPUT("x")
	y := cs.PUBLIC_INPUT("y")

	cs.DIV(x, y)

	// tests CS
	assert.csIsCorrect(cs, expectedCS{
		nbWires:         4,
		nbConstraints:   4,
		nbMOConstraints: 0,
		nbNOConstraints: 0,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(cs, expectedR1CS{
		nbWires:                    4,
		nbComputationalConstraints: 1,
		nbConstraints:              1,
		nbPrivateWires:             0,
		nbPublicWires:              3,
	})

}

func TestDIVLC(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	cs := NewConstraintSystem()

	x := cs.PUBLIC_INPUT("x")
	y := cs.PUBLIC_INPUT("y")

	two := backend.FromInterface(2)

	l1 := LinearCombination{Term{Variable: x, Coeff: two}}
	l2 := LinearCombination{Term{Variable: y, Coeff: two}}

	cs.DIV(l1, l2)

	// tests CS
	assert.csIsCorrect(cs, expectedCS{
		nbWires:         4,
		nbConstraints:   4,
		nbMOConstraints: 0,
		nbNOConstraints: 0,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(cs, expectedR1CS{
		nbWires:                    4,
		nbComputationalConstraints: 1,
		nbConstraints:              1,
		nbPrivateWires:             0,
		nbPublicWires:              3,
	})

}

func TestMULLC(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	cs := NewConstraintSystem()

	x := cs.PUBLIC_INPUT("x")
	y := cs.PUBLIC_INPUT("y")

	two := backend.FromInterface(2)

	l1 := LinearCombination{Term{Variable: x, Coeff: two}}
	l2 := LinearCombination{Term{Variable: y, Coeff: two}}

	cs.MUL(l1, l2)

	// tests CS
	assert.csIsCorrect(cs, expectedCS{
		nbWires:         4,
		nbConstraints:   4,
		nbMOConstraints: 0,
		nbNOConstraints: 0,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(cs, expectedR1CS{
		nbWires:                    4,
		nbComputationalConstraints: 1,
		nbConstraints:              1,
		nbPrivateWires:             0,
		nbPublicWires:              3,
	})

}

func TestSELECT(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	cs := NewConstraintSystem()

	x := cs.PUBLIC_INPUT("x")
	y := cs.PUBLIC_INPUT("y")
	z := cs.PUBLIC_INPUT("z")

	cs.SELECT(x, y, z)

	// tests CS
	assert.csIsCorrect(cs, expectedCS{
		nbWires:         5,
		nbConstraints:   5,
		nbMOConstraints: 0,
		nbNOConstraints: 1, // x must be boolean constrained
	})

	// tests solving R1CS
	assert.r1csIsCorrect(cs, expectedR1CS{
		nbWires:                    5,
		nbComputationalConstraints: 1,
		nbConstraints:              2,
		nbPrivateWires:             0,
		nbPublicWires:              4,
	})

}

func TestFROM_BINARY(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	cs := NewConstraintSystem()

	b0 := cs.PUBLIC_INPUT("b0")
	b1 := cs.PUBLIC_INPUT("b1")
	b2 := cs.PUBLIC_INPUT("b2")
	b3 := cs.PUBLIC_INPUT("b3")
	b4 := cs.PUBLIC_INPUT("b4")

	cs.FROM_BINARY(b0, b1, b2, b3, b4)

	// tests CS
	assert.csIsCorrect(cs, expectedCS{
		nbWires:         7,
		nbConstraints:   7,
		nbMOConstraints: 0,
		nbNOConstraints: 5, //b0..b4 are boolean constrained
	})

	// tests solving R1CS
	assert.r1csIsCorrect(cs, expectedR1CS{
		nbWires:                    7,
		nbComputationalConstraints: 1,
		nbConstraints:              6,
		nbPrivateWires:             0,
		nbPublicWires:              6,
	})

}

func TestTO_BINARY(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	cs := NewConstraintSystem()

	x := cs.PUBLIC_INPUT("x")

	cs.TO_BINARY(x, 5)

	// tests CS
	assert.csIsCorrect(cs, expectedCS{
		nbWires:         7,
		nbConstraints:   7,
		nbMOConstraints: 1,
		nbNOConstraints: 5,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(cs, expectedR1CS{
		nbWires:                    7,
		nbComputationalConstraints: 5,
		nbConstraints:              10,
		nbPrivateWires:             0,
		nbPublicWires:              2,
	})

}

func TestSELECT_LUT(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	cs := NewConstraintSystem()

	b0 := cs.SECRET_INPUT("b0")
	b1 := cs.SECRET_INPUT("b1")

	var lut [4]big.Int
	lut[0] = backend.FromInterface(42)
	lut[2] = backend.FromInterface(8000)

	cs.SELECT_LUT(b0, b1, lut)

	// tests CS
	assert.csIsCorrect(cs, expectedCS{
		nbWires:         4,
		nbConstraints:   4,
		nbMOConstraints: 0,
		nbNOConstraints: 2,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(cs, expectedR1CS{
		nbWires:                    4,
		nbComputationalConstraints: 1,
		nbConstraints:              3,
		nbPrivateWires:             2,
		nbPublicWires:              1,
	})

}

func TestXOR(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	cs := NewConstraintSystem()

	x := cs.PUBLIC_INPUT("x")
	y := cs.PUBLIC_INPUT("y")
	z := cs.PUBLIC_INPUT("z")

	r0 := cs.XOR(x, y)
	_ = cs.XOR(x, r0)
	_ = cs.XOR(y, z)

	// tests CS
	assert.csIsCorrect(cs, expectedCS{
		nbWires:         7,
		nbConstraints:   7,
		nbMOConstraints: 0,
		nbNOConstraints: 3,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(cs, expectedR1CS{
		nbWires:                    7,
		nbComputationalConstraints: 3,
		nbConstraints:              6,
		nbPrivateWires:             0,
		nbPublicWires:              4,
	})

}
func TestALLOC(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	cs := NewConstraintSystem()

	_ = cs.ALLOCATE(4)

	// tests CS
	assert.csIsCorrect(cs, expectedCS{
		nbWires:         2,
		nbConstraints:   2,
		nbMOConstraints: 0,
		nbNOConstraints: 0,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(cs, expectedR1CS{
		nbWires:                    2,
		nbComputationalConstraints: 1,
		nbConstraints:              1,
		nbPrivateWires:             0,
		nbPublicWires:              1,
	})

}

func TestMUSTBE_BOOL(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	cs := NewConstraintSystem()

	x := cs.PUBLIC_INPUT("x")

	cs.MUSTBE_BOOLEAN(x)
	// TODO add back this test
	// xx := *x
	// xx := &
	// cs.MUSTBE_BOOLEAN(&xx) // calling MUSTBE_BOOLEAN twice should not add a duplicate constraint

	// tests CS
	assert.csIsCorrect(cs, expectedCS{
		nbWires:         2,
		nbConstraints:   2,
		nbMOConstraints: 0,
		nbNOConstraints: 1,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(cs, expectedR1CS{
		nbWires:                    2,
		nbComputationalConstraints: 0,
		nbConstraints:              1,
		nbPrivateWires:             0,
		nbPublicWires:              2,
	})

}

func TestXtimes2EqualsY(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	cs := NewConstraintSystem()

	x := cs.PUBLIC_INPUT("x")
	y := cs.SECRET_INPUT("y")
	cst := cs.ALLOCATE(2)

	cs.MUSTBE_EQ(cs.MUL(x, cst), y)

	// tests CS
	assert.csIsCorrect(cs, expectedCS{
		nbWires:         5,
		nbConstraints:   5,
		nbMOConstraints: 0,
		nbNOConstraints: 1,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(cs, expectedR1CS{
		nbWires:                    5,
		nbComputationalConstraints: 2,
		nbConstraints:              3,
		nbPrivateWires:             1,
		nbPublicWires:              2,
	})

}

func TestINV(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	cs := NewConstraintSystem()

	x := cs.PUBLIC_INPUT("x")

	cs.INV(x)

	// tests CS
	assert.csIsCorrect(cs, expectedCS{
		nbWires:         3,
		nbConstraints:   3,
		nbMOConstraints: 0,
		nbNOConstraints: 0,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(cs, expectedR1CS{
		nbWires:                    3,
		nbComputationalConstraints: 1,
		nbConstraints:              1,
		nbPrivateWires:             0,
		nbPublicWires:              2,
	})

}

func TestMerge(t *testing.T) {
	// test helper
	assert := NewAssert(t)

	// circuit definition
	cs := NewConstraintSystem()

	u := cs.SECRET_INPUT("u")
	v := cs.SECRET_INPUT("v")
	w := cs.PUBLIC_INPUT("w")

	a0 := cs.INV(u)
	a1 := cs.MUL(a0, v)
	cs.MUSTBE_EQ(w, a1)

	// tests CS
	assert.csIsCorrect(cs, expectedCS{
		nbWires:         6,
		nbConstraints:   6,
		nbMOConstraints: 0,
		nbNOConstraints: 1,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(cs, expectedR1CS{
		nbWires:                    6,
		nbComputationalConstraints: 2,
		nbConstraints:              3,
		nbPrivateWires:             2,
		nbPublicWires:              2,
	})

}

func TestMergeMoeNoe(t *testing.T) {

	// test helper
	assert := NewAssert(t)

	// circuit definition
	cs := NewConstraintSystem()

	u := cs.SECRET_INPUT("u")
	w := cs.PUBLIC_INPUT("w")

	b := cs.TO_BINARY(w, 3)

	cs.MUSTBE_EQ(b[0], u)

	// tests CS
	assert.csIsCorrect(cs, expectedCS{
		nbWires:         6,
		nbConstraints:   6,
		nbMOConstraints: 1,
		nbNOConstraints: 4,
	})

	// tests solving R1CS
	assert.r1csIsCorrect(cs, expectedR1CS{
		nbWires:                    6,
		nbComputationalConstraints: 3,
		nbConstraints:              7,
		nbPrivateWires:             1,
		nbPublicWires:              2,
	})

}
