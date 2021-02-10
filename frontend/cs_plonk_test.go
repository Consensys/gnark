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
	"testing"

	"github.com/consensys/gnark/internal/backend/untyped"
)

func TestPopVariable(t *testing.T) {

	sizeAfterPoped := 29
	nbInternalVars := 10

	le := make([]untyped.Term, 30)
	for i := 0; i < 10; i++ {
		le[i] = untyped.Pack(i, 2*i, untyped.Internal)
		le[10+i] = untyped.Pack(i, 2*(i+10), untyped.Public)
		le[20+i] = untyped.Pack(i, 2*(i+20), untyped.Secret)
	}

	for i := 0; i < nbInternalVars; i++ {
		l, v := popInternalVariable(le, i)
		_v := le[i]
		_l := make(untyped.LinearExpression, len(le)-1)
		copy(_l, le[:i])
		copy(_l[i:], le[i+1:])
		if len(l) != sizeAfterPoped {
			t.Fatal("wrong length")
		}
		if _v != v {
			t.Fatal("wrong variable")
		}
		for j := 0; j < sizeAfterPoped; j++ {
			if _l[j] != l[j] {
				t.Fatal("wrong lin exp")
			}
		}
	}
}

func TestFindUnsolvedVariable(t *testing.T) {

	sizeLe := 10
	totalInternalVariables := 3 * sizeLe / 2

	l := make(untyped.LinearExpression, sizeLe)
	r := make(untyped.LinearExpression, sizeLe)
	o := make(untyped.LinearExpression, sizeLe)
	for i := 0; i < sizeLe/2; i++ {
		l[i] = untyped.Pack(3*i, i, untyped.Internal)
		l[i+sizeLe/2] = untyped.Pack(3*i, i, untyped.Public)
	}
	for i := 0; i < sizeLe/2; i++ {
		r[i] = untyped.Pack(3*i+1, i, untyped.Internal)
		r[i+sizeLe/2] = untyped.Pack(3*i+1, i, untyped.Public)
	}
	for i := 0; i < sizeLe/2; i++ {
		o[i] = untyped.Pack(3*i+2, i, untyped.Internal)
		o[i+sizeLe/2] = untyped.Pack(3*i+2, i, untyped.Public)
	}

	solvedVariables := make([]bool, totalInternalVariables)
	for i := 0; i < totalInternalVariables; i++ {
		solvedVariables[i] = true
	}
	r1c := untyped.R1C{L: l, R: r, O: o, Solver: untyped.SingleOutput}

	for i := 0; i < totalInternalVariables; i++ {
		solvedVariables[i] = false
		expectedPos := i % 3 // left=0, right=1, out = 3
		expectedID := i
		pos, id := findUnsolvedVariable(r1c, solvedVariables)
		if pos != expectedPos {
			t.Fatal("wrong position")
		}
		if id != expectedID {
			t.Fatal("wrong id")
		}
		solvedVariables[i] = true
	}
}
