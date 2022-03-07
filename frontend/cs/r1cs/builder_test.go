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

package r1cs

import (
	"sort"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/compiled"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/stretchr/testify/require"
)

func TestQuickSort(t *testing.T) {

	toSort := make(compiled.LinearExpression, 12)
	rand := 3
	for i := 0; i < 12; i++ {
		toSort[i].SetVariableVisibility(schema.Secret)
		toSort[i].SetWireID(rand)
		rand += 3
		rand = rand % 13
	}

	sort.Sort(toSort)

	for i := 0; i < 10; i++ {
		_, cur, _ := toSort[i].Unpack()
		_, next, _ := toSort[i+1].Unpack()
		if cur >= next {
			t.Fatal("err sorting linear expression")
		}
	}

}

func TestReduce(t *testing.T) {

	cs := newBuilder(ecc.BN254, frontend.CompileConfig{})
	x := cs.newInternalVariable()
	y := cs.newInternalVariable()
	z := cs.newInternalVariable()

	a := cs.Mul(x, 3)
	b := cs.Mul(x, 5)
	c := cs.Mul(y, 10)
	d := cs.Mul(y, 11)
	e := cs.Mul(z, 2)
	f := cs.Mul(z, 2)

	toTest := (cs.Add(a, b, c, d, e, f)).(compiled.LinearExpression)

	// check sizes
	if len(toTest) != 3 {
		t.Fatal("Error reduce, duplicate variables not collapsed")
	}

}

func TestAddQuadraticConstraint(t *testing.T) {
	assert := require.New(t)
	cs := newBuilder(ecc.BN254, frontend.CompileConfig{})
	x := cs.newInternalVariable()

	// x must be 0, 1 or 2
	// x * (1 -x ) * (2 -x) == 0
	cs.AddQuadraticConstraint(x, cs.Mul(cs.Sub(1, x), cs.Sub(2, x)), 0)

	assert.Equal(2, len(cs.Constraints), "expected 2 constraints")

}
