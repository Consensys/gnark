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
	Add(i1, i2 Variable, in ...Variable) Variable

	// Neg returns -i
	Neg(i1 Variable) Variable

	// Sub returns res = i1 - i2 - ...in
	Sub(i1, i2 Variable, in ...Variable) Variable

	// Mul returns res = i1 * i2 * ... in
	Mul(i1, i2 Variable, in ...Variable) Variable

	// DivUnchecked returns i1 / i2 . if i1 == i2 == 0, returns 0
	DivUnchecked(i1, i2 Variable) Variable

	// Div returns i1 / i2
	Div(i1, i2 Variable) Variable

	// Inverse returns res = 1 / i1
	Inverse(i1 Variable) Variable

	// ---------------------------------------------------------------------------------------------
	// Bit operations
	// TODO @gbotrel move bit operations in std/math/bits

	// ToBinary unpacks a Variable in binary,
	// n is the number of bits to select (starting from lsb)
	// n default value is fr.Bits the number of bits needed to represent a field element
	//
	// The result in in little endian (first bit= lsb)
	ToBinary(i1 Variable, n ...int) []Variable

	// FromBinary packs b, seen as a fr.Element in little endian
	FromBinary(b ...Variable) Variable

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
	Select(b Variable, i1, i2 Variable) Variable

	// Lookup2 performs a 2-bit lookup between i1, i2, i3, i4 based on bits b0
	// and b1. Returns i0 if b0=b1=0, i1 if b0=1 and b1=0, i2 if b0=0 and b1=1
	// and i3 if b0=b1=1.
	Lookup2(b0, b1 Variable, i0, i1, i2, i3 Variable) Variable

	// IsZero returns 1 if a is zero, 0 otherwise
	IsZero(i1 Variable) Variable

	// Cmp returns 1 if i1>i2, 0 if i1=i2, -1 if i1<i2
	Cmp(i1, i2 Variable) Variable

	// ---------------------------------------------------------------------------------------------
	// Assertions

	// AssertIsEqual fails if i1 != i2
	AssertIsEqual(i1, i2 Variable)

	// AssertIsDifferent fails if i1 == i2
	AssertIsDifferent(i1, i2 Variable)

	// AssertIsBoolean fails if v != 0 ∥ v != 1
	AssertIsBoolean(i1 Variable)

	// AssertIsLessOrEqual fails if  v > bound
	AssertIsLessOrEqual(v Variable, bound Variable)

	// Println behaves like fmt.Println but accepts cd.Variable as parameter
	// whose value will be resolved at runtime when computed by the solver
	Println(a ...Variable)

	// Compiler returns the compiler object for advanced circuit development
	Compiler() Compiler

	// Deprecated APIs

	// NewHint is a shorcut to api.Compiler().NewHint()
	// Deprecated: use api.Compiler().NewHint() instead
	NewHint(f hint.Function, nbOutputs int, inputs ...Variable) ([]Variable, error)

	// Tag is a shorcut to api.Compiler().Tag()
	// Deprecated: use api.Compiler().Tag() instead
	Tag(name string) Tag

	// AddCounter is a shorcut to api.Compiler().AddCounter()
	// Deprecated: use api.Compiler().AddCounter() instead
	AddCounter(from, to Tag)

	// ConstantValue is a shorcut to api.Compiler().ConstantValue()
	// Deprecated: use api.Compiler().ConstantValue() instead
	ConstantValue(v Variable) (*big.Int, bool)

	// Curve is a shorcut to api.Compiler().Curve()
	// Deprecated: use api.Compiler().Curve() instead
	Curve() ecc.ID

	// Backend is a shorcut to api.Compiler().Backend()
	// Deprecated: use api.Compiler().Backend() instead
	Backend() backend.ID
}
