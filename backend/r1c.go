// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package backend

// LinearExpression represent a linear expression of variables
type LinearExpression []Term

// R1C used to compute the wires
type R1C struct {
	L      LinearExpression
	R      LinearExpression
	O      LinearExpression
	Solver SolvingMethod
}

// SolvingMethod is used by the R1CS solver
// note: it is not in backend/r1cs to avoid an import cycle
type SolvingMethod uint8

// SingleOuput and BinaryDec are types of solving method for rank-1 constraints
const (
	SingleOutput SolvingMethod = iota
	BinaryDec
)
