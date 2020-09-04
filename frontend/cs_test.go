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

	cs := newConstraintSystem()

	cs.SecretInput("x")
	cs.SecretInput("x")
}

func TestDuplicatePublicInput(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("declaring same name twice for public input, code should panic")
		}
	}()

	cs := newConstraintSystem()

	cs.PublicInput("x")
	cs.PublicInput("x")
}

func TestInconsistantConstraints2(t *testing.T) {
	cs := newConstraintSystem()

	x := cs.PublicInput("x")

	cs.MustBeEqual(x, x)
	if cs.nbConstraints() != 2 { // one wire and x
		t.Fatal("x == x shouldn't add a constraint")
	}
}

// checks if creation of constraint system works
func TestOneWireConstraint(t *testing.T) {
	assert := require.New(t)
	cs := newConstraintSystem()
	nbWires := cs.countWires()

	assert.Equal(1, nbWires, "Newly created constraint system should have 1 wire")
	assert.Equal(1, int(cs.nbConstraints()), "Newly created constraint system should have 1 constraint")

	val := cs.constraints[oneWireID]
	oneWire := cs.publicWireNames[val.ID]
	assert.Equal(backend.OneWire, oneWire, "constraint map should contain ONE_WIRE")

	_ = cs.Allocate(1)
	assert.Equal(1, int(cs.nbConstraints()), "ALLOCATE(1) should return existing ONEWIRE")
}

func TestADD(t *testing.T) {
	// test helper
	assert := newAssert(t)

	// circuit definition
	cs := newConstraintSystem()

	var val big.Int
	val.SetUint64(4)

	x := cs.PublicInput("x")

	cs.Add(x, x)
	cs.Add(x, val)
	cs.Add(val, x)

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
		nbSecretWires:              0,
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
	assert := newAssert(t)

	// circuit definition
	cs := newConstraintSystem()

	var val big.Int
	val.SetUint64(4)

	x := cs.PublicInput("x")

	cs.Sub(x, x)
	cs.Sub(x, val)
	cs.Sub(val, x)

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
		nbSecretWires:              0,
		nbPublicWires:              2,
	})

}

func TestMUL(t *testing.T) {
	// test helper
	assert := newAssert(t)

	// circuit definition
	cs := newConstraintSystem()

	var val big.Int
	val.SetUint64(4)

	x := cs.PublicInput("x")

	cs.Mul(x, x)
	cs.Mul(x, val)
	cs.Mul(val, x)

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
		nbSecretWires:              0,
		nbPublicWires:              2,
	})

}

func TestDIV(t *testing.T) {
	// test helper
	assert := newAssert(t)

	// circuit definition
	cs := newConstraintSystem()

	x := cs.PublicInput("x")
	y := cs.PublicInput("y")

	cs.Div(x, y)

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
		nbSecretWires:              0,
		nbPublicWires:              3,
	})

}

func TestDIVLC(t *testing.T) {
	// test helper
	assert := newAssert(t)

	// circuit definition
	cs := newConstraintSystem()

	x := cs.PublicInput("x")
	y := cs.PublicInput("y")

	two := backend.FromInterface(2)

	l1 := LinearCombination{Term{Variable: x, Coeff: two}}
	l2 := LinearCombination{Term{Variable: y, Coeff: two}}

	cs.Div(l1, l2)

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
		nbSecretWires:              0,
		nbPublicWires:              3,
	})

}

func TestMULLC(t *testing.T) {
	// test helper
	assert := newAssert(t)

	// circuit definition
	cs := newConstraintSystem()

	x := cs.PublicInput("x")
	y := cs.PublicInput("y")

	two := backend.FromInterface(2)

	l1 := LinearCombination{Term{Variable: x, Coeff: two}}
	l2 := LinearCombination{Term{Variable: y, Coeff: two}}

	cs.Mul(l1, l2)

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
		nbSecretWires:              0,
		nbPublicWires:              3,
	})

}

func TestSELECT(t *testing.T) {
	// test helper
	assert := newAssert(t)

	// circuit definition
	cs := newConstraintSystem()

	x := cs.PublicInput("x")
	y := cs.PublicInput("y")
	z := cs.PublicInput("z")

	cs.Select(x, y, z)

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
		nbSecretWires:              0,
		nbPublicWires:              4,
	})

}

func TestFROM_BINARY(t *testing.T) {
	// test helper
	assert := newAssert(t)

	// circuit definition
	cs := newConstraintSystem()

	b0 := cs.PublicInput("b0")
	b1 := cs.PublicInput("b1")
	b2 := cs.PublicInput("b2")
	b3 := cs.PublicInput("b3")
	b4 := cs.PublicInput("b4")

	cs.FromBinary(b0, b1, b2, b3, b4)

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
		nbSecretWires:              0,
		nbPublicWires:              6,
	})

}

func TestTO_BINARY(t *testing.T) {
	// test helper
	assert := newAssert(t)

	// circuit definition
	cs := newConstraintSystem()

	x := cs.PublicInput("x")

	cs.ToBinary(x, 5)

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
		nbSecretWires:              0,
		nbPublicWires:              2,
	})

}

func TestSELECT_LUT(t *testing.T) {
	// test helper
	assert := newAssert(t)

	// circuit definition
	cs := newConstraintSystem()

	b0 := cs.SecretInput("b0")
	b1 := cs.SecretInput("b1")

	var lut [4]big.Int
	lut[0] = backend.FromInterface(42)
	lut[2] = backend.FromInterface(8000)

	cs.SelectLUT(b0, b1, lut)

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
		nbSecretWires:              2,
		nbPublicWires:              1,
	})

}

func TestXOR(t *testing.T) {
	// test helper
	assert := newAssert(t)

	// circuit definition
	cs := newConstraintSystem()

	x := cs.PublicInput("x")
	y := cs.PublicInput("y")
	z := cs.PublicInput("z")

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
		nbSecretWires:              0,
		nbPublicWires:              4,
	})

}
func TestALLOC(t *testing.T) {
	// test helper
	assert := newAssert(t)

	// circuit definition
	cs := newConstraintSystem()

	_ = cs.Allocate(4)

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
		nbSecretWires:              0,
		nbPublicWires:              1,
	})

}

func TestMUSTBE_BOOL(t *testing.T) {
	// test helper
	assert := newAssert(t)

	// circuit definition
	cs := newConstraintSystem()

	x := cs.PublicInput("x")

	cs.MustBeBoolean(x)
	cs.MustBeBoolean(x)
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
		nbSecretWires:              0,
		nbPublicWires:              2,
	})

}

func TestXtimes2EqualsY(t *testing.T) {
	// test helper
	assert := newAssert(t)

	// circuit definition
	cs := newConstraintSystem()

	x := cs.PublicInput("x")
	y := cs.SecretInput("y")
	cst := cs.Allocate(2)

	cs.MustBeEqual(cs.Mul(x, cst), y)

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
		nbSecretWires:              1,
		nbPublicWires:              2,
	})

}

func TestINV(t *testing.T) {
	// test helper
	assert := newAssert(t)

	// circuit definition
	cs := newConstraintSystem()

	x := cs.PublicInput("x")

	cs.Inverse(x)

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
		nbSecretWires:              0,
		nbPublicWires:              2,
	})

}

func TestMerge(t *testing.T) {
	// test helper
	assert := newAssert(t)

	// circuit definition
	cs := newConstraintSystem()

	u := cs.SecretInput("u")
	v := cs.SecretInput("v")
	w := cs.PublicInput("w")

	a0 := cs.Inverse(u)
	a1 := cs.Mul(a0, v)
	cs.MustBeEqual(w, a1)

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
		nbSecretWires:              2,
		nbPublicWires:              2,
	})

}

func TestMergeMoeNoe(t *testing.T) {

	// test helper
	assert := newAssert(t)

	// circuit definition
	cs := newConstraintSystem()

	u := cs.SecretInput("u")
	w := cs.PublicInput("w")

	b := cs.ToBinary(w, 3)

	cs.MustBeEqual(b[0], u)

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
		nbSecretWires:              1,
		nbPublicWires:              2,
	})

}

func TestConstraintTag(t *testing.T) {
	assert := require.New(t)

	cs := newConstraintSystem()

	tagLen := func(cs *CS, v Variable) int {
		return len(cs.wireTags[v.id()])
	}

	a := cs.Allocate(12)
	assert.True(tagLen(&cs, a) == 0, "untagged constraint shouldn't have tags")
	cs.Tag(a, "a")
	assert.True(tagLen(&cs, a) == 1, "a should have 1 tag")
	cs.Tag(a, "b")
	assert.True(tagLen(&cs, a) == 2, "a should have 2 tag")

	x := cs.PublicInput("x")
	assert.True(tagLen(&cs, x) == 0, "a secret/public is not tagged by default")

}

func TestDuplicateTag(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("declaring same tag name, code should panic")
		}
	}()

	assert := require.New(t)

	cs := newConstraintSystem()

	tagLen := func(cs *CS, v Variable) int {
		return len(cs.wireTags[v.id()])
	}

	a := cs.Allocate(12)
	assert.True(tagLen(&cs, a) == 0, "untagged constraint shouldn't have tags")
	cs.Tag(a, "a")
	assert.True(tagLen(&cs, a) == 1, "a should have 1 tag")
	cs.Tag(a, "b")
	assert.True(tagLen(&cs, a) == 2, "a should have 2 tag")
	cs.Tag(a, "b") // duplicate

}
