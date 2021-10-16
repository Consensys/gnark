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

// API represents the available functions to circuit developers
type API interface {
	// ---------------------------------------------------------------------------------------------
	// Arithmetic

	// Add returns res = i1+i2+...in
	Add(i1, i2 interface{}, in ...interface{}) Variable

	// Sub returns res = i1 - i2
	Sub(i1, i2 interface{}) Variable

	// Neg returns -i
	Neg(i1 interface{}) Variable

	// Mul returns res = i1 * i2 * ... in
	Mul(i1, i2 interface{}, in ...interface{}) Variable

	// Div returns i1 / i2
	Div(i1, i2 interface{}) Variable

	// Inverse returns res = 1 / v
	Inverse(v Variable) Variable

	// ---------------------------------------------------------------------------------------------
	// Bit operations

	// ToBinary unpacks a variable in binary,
	// n is the number of bits to select (starting from lsb)
	// n default value is fr.Bits the number of bits needed to represent a field element
	//
	// The result in in little endian (first bit= lsb)
	ToBinary(a Variable, n ...int) []Variable

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
	Select(b Variable, i1, i2 interface{}) Variable

	// IsZero returns 1 if a is zero, 0 otherwise
	IsZero(a Variable) Variable

	// ---------------------------------------------------------------------------------------------
	// Assertions

	// AssertIsEqual fails if i1 != i2
	AssertIsEqual(i1, i2 interface{})

	// AssertIsDifferent fails if i1 == i2
	AssertIsDifferent(i1, i2 interface{})

	// AssertIsBoolean fails if v != 0 || v != 1
	AssertIsBoolean(v Variable)

	// AssertIsLessOrEqual adds assertion in constraint system  (v <= bound)
	//
	// bound can be a constant or a Variable
	AssertIsLessOrEqual(v Variable, bound interface{})

	// Println behaves like fmt.Println but accepts frontend.Variable as parameter
	// whose value will be resolved at runtime when computed by the solver
	Println(a ...interface{})

	// Constant returns a frontend.Variable representing a known value at compile time
	Constant(input interface{}) Variable
}
