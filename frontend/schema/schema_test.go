/*
Copyright © 2022 ConsenSys Software Inc.

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

package schema

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

type variable interface{}

type Circuit struct {
	X variable `gnark:"x"`
	Y variable `gnark:",public"`
	Z []variable
	G circuitChild
	H circuitGrandChild `gnark:",secret"`
	I [2]circuitGrandChild
}

type circuitChild struct {
	A variable          `gnark:",public"`
	B circuitGrandChild `gnark:",public"`
	C [2]variable       `gnark:"super"`
}

type circuitGrandChild struct {
	E variable
	F [2]variable
	N circuitGrandGrandChildWithoutVariables
	O circuitGrandGrandChildWithVariables
	P [1]circuitGrandGrandChildWithVariables
}

type circuitGrandGrandChildWithoutVariables struct {
	L int
}

type circuitGrandGrandChildWithVariables struct {
	M variable
}

type expected struct {
	X int `gnark:"x,secret" json:"x"`
	Y int `gnark:",public"`
	Z [3]int
	G struct {
		A int `gnark:",public"`
		B struct {
			E int
			F [2]int
			O struct {
				M int
			}
			P [1]struct {
				M int
			}
		} `gnark:",public"`
		C [2]int `gnark:"super" json:"super"`
	}
	H struct {
		E int
		F [2]int
		O struct {
			M int
		}
		P [1]struct {
			M int
		}
	} `gnark:",secret"`
	I [2]struct {
		E int
		F [2]int
		O struct {
			M int
		}
		P [1]struct {
			M int
		}
	}
}

func TestSchemaCorrectness(t *testing.T) {
	assert := require.New(t)

	// build schema
	witness := &Circuit{Z: make([]variable, 3)}
	s, err := Parse(witness, tVariable, nil)
	assert.NoError(err)

	// instantiate a concrete object
	var a int
	instance := s.Instantiate(reflect.TypeOf(a), false)

	// encode it to json
	var instanceBuf, expectedBuf bytes.Buffer
	err = json.NewEncoder(&instanceBuf).Encode(instance)
	assert.NoError(err)
	err = json.NewEncoder(&expectedBuf).Encode(expected{})
	assert.NoError(err)

	// ensure it matches what we expect
	assert.Equal(expectedBuf.String(), instanceBuf.String())
}

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A variable }{}).FieldByName("A").Type()
}
