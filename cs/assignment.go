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

package cs

import (
	"github.com/consensys/gnark/cs/internal/curve"
)

// Visibility type alias on string to define circuit input's visibility
type Visibility string

// Possible Visibility attributes for circuit inputs
const (
	Secret Visibility = "secret"
	Public Visibility = "public"
)

// Assignment is used to specify inputs to the Prove and Verify functions
type Assignment struct {
	Value    curve.Element
	IsPublic bool // default == false (assignemnt is private)
}

// Assignments is used to specify inputs to the Prove and Verify functions
type Assignments map[string]Assignment

// NewAssignment returns an empty Assigments object
func NewAssignment() Assignments {
	return make(Assignments)
}

// Assign assign a value to a Secret/Public input identified by its name
func (a Assignments) Assign(visibility Visibility, name string, v interface{}) {
	if _, ok := a[name]; ok {
		panic(name + " already assigned")
	}
	switch visibility {
	case Secret:
		a[name] = newPrivateAssignment(v)
	case Public:
		a[name] = newPublicAssignment(v)
	default:
		panic("supported visibility attributes are SECRET and PUBLIC")
	}
}

// newPrivateAssignment returns a new private Assignment from provided values
// allowed interface types: curve.Element, uint64, int, string
// if v is uint64, int, or string, it must be in regular (non-montgomery) form
func newPrivateAssignment(v interface{}) Assignment {
	return Assignment{Value: elementFromInterface(v)}
}

// newPublicAssignment returns a new public Assignment from provided values
// allowed interface types: curve.Element, uint64, int, string
// if v is uint64, int, or string, it must be in regular (non-montgomery) form
func newPublicAssignment(v interface{}) Assignment {
	toReturn := Assignment{
		Value:    elementFromInterface(v),
		IsPublic: true,
	}
	return toReturn
}
