/*
Copyright © 2021 ConsenSys Software Inc.

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

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/hint"
)

// API represents the available functions to circuit developers
type API interface {
	// ---------------------------------------------------------------------------------------------
	// Arithmetic

	// Add returns res = i1+i2+...in
	Add(i1, i2 interface{}, in ...interface{}) Variable

	// Sub returns res = i1 - i2 - ...in
	Sub(i1, i2 interface{}, in ...interface{}) Variable

	// Neg returns -i
	Neg(i1 interface{}) Variable

	// Mul returns res = i1 * i2 * ... in
	Mul(i1, i2 interface{}, in ...interface{}) Variable

	// DivUnchecked returns i1 / i2 . if i1 == i2 == 0, returns 0
	DivUnchecked(i1, i2 interface{}) Variable

	// Div returns i1 / i2
	Div(i1, i2 interface{}) Variable

	// Inverse returns res = 1 / i1
	Inverse(i1 interface{}) Variable

	// ---------------------------------------------------------------------------------------------
	// Bit operations

	// ToBinary unpacks a Variable in binary,
	// n is the number of bits to select (starting from lsb)
	// n default value is fr.Bits the number of bits needed to represent a field element
	//
	// The result in in little endian (first bit= lsb)
	ToBinary(i1 interface{}, n ...int) []Variable

	// FromBinary packs b, seen as a fr.Element in little endian
	FromBinary(b ...interface{}) Variable

	// Xor returns a ^ b
	// a and b must be 0 or 1
	Xor(a, b Variable) Variable

	// Or returns a | b
	// a and b must be 0 or 1
	Or(a, b Variable) Variable

	// Or returns a & b
	// a and b must be 0 or 1
	And(a, b Variable) Variable

	// ---------------------------------------------------------------------------------------------
	// Conditionals

	// Select if b is true, yields i1 else yields i2
	Select(b interface{}, i1, i2 interface{}) Variable

	// Lookup2 performs a 2-bit lookup between i1, i2, i3, i4 based on bits b0
	// and b1. Returns i0 if b0=b1=0, i1 if b0=1 and b1=0, i2 if b0=0 and b1=1
	// and i3 if b0=b1=1.
	Lookup2(b0, b1 interface{}, i0, i1, i2, i3 interface{}) Variable

	// IsZero returns 1 if a is zero, 0 otherwise
	IsZero(i1 interface{}) Variable

	// ---------------------------------------------------------------------------------------------
	// Assertions

	// AssertIsEqual fails if i1 != i2
	AssertIsEqual(i1, i2 interface{})

	// AssertIsDifferent fails if i1 == i2
	AssertIsDifferent(i1, i2 interface{})

	// AssertIsBoolean fails if v != 0 || v != 1
	AssertIsBoolean(i1 interface{})

	// AssertIsLessOrEqual fails if  v > bound
	AssertIsLessOrEqual(v Variable, bound interface{})

	// Println behaves like fmt.Println but accepts frontend.Variable as parameter
	// whose value will be resolved at runtime when computed by the solver
	Println(a ...interface{})

	// NewHint initializes an internal variable whose value will be evaluated
	// using the provided hint function at run time from the inputs. Inputs must
	// be either variables or convertible to *big.Int.
	//
	// The hint function is provided at the proof creation time and is not
	// embedded into the circuit. From the backend point of view, the variable
	// returned by the hint function is equivalent to the user-supplied witness,
	// but its actual value is assigned by the solver, not the caller.
	//
	// No new constraints are added to the newly created wire and must be added
	// manually in the circuit. Failing to do so leads to solver failure.
	NewHint(f hint.Function, inputs ...interface{}) Variable

	// Tag creates a tag at a given place in a circuit. The state of the tag may contain informations needed to
	// measure constraints, variables and coefficients creations through AddCounter
	Tag(name string) Tag

	// AddCounter measures the number of constraints, variables and coefficients created between two tags
	// note that the PlonK statistics are contextual since there is a post-compile phase where linear expressions
	// are factorized. That is, measuring 2 times the "repeating" piece of circuit may give less constraints the second time
	AddCounter(from, to Tag)

	// IsConstant returns true if v is a constant known at compile time
	IsConstant(v Variable) bool

	// ConstantValue returns the big.Int value of v. It
	// panics if v.IsConstant() == false
	ConstantValue(v Variable) *big.Int

	// CurveID returns the ecc.ID injected by the compiler
	CurveID() ecc.ID

	// Backend returns the backend.ID injected by the compiler
	Backend() backend.ID
}
