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

package plonk

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/backend/compiled"
)

// AssertIsEqual fails if i1 != i2
func (cs *SparseR1CS) AssertIsEqual(i1, i2 interface{}) {

	if cs.IsConstant(i1) && cs.IsConstant(i2) {
		a := frontend.FromInterface(i1)
		b := frontend.FromInterface(i2)
		if a.Cmp(&b) != 0 {
			panic("i1, i2 should be equal")
		}
	}
	if cs.IsConstant(i1) {
		i1, i2 = i2, i1
	}
	if cs.IsConstant(i2) {
		l := i1.(compiled.Term)
		k := frontend.FromInterface(i2)
		debug := cs.AddDebugInfo("assertIsEqual", l, " == ", k)
		k.Neg(&k)
		_k := cs.CoeffID(&k)
		cs.addPlonkConstraint(l, 0, 0, compiled.CoeffIdOne, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdZero, _k, debug)
	}
	l := i1.(compiled.Term)
	r := i1.(compiled.Term)
	debug := cs.AddDebugInfo("assertIsEqual", l, " == ", r)
	cs.addPlonkConstraint(l, 0, r, compiled.CoeffIdOne, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdOne, compiled.CoeffIdZero, debug)
}

// AssertIsDifferent fails if i1 == i2
func (cs *SparseR1CS) AssertIsDifferent(i1, i2 interface{}) {
	cs.Inverse(cs.Sub(i1, i2))
}

// AssertIsBoolean fails if v != 0 || v != 1
func (cs *SparseR1CS) AssertIsBoolean(i1 interface{}) {
	if cs.IsConstant(i1) {
		c := frontend.FromInterface(i1)
		if !(c.IsUint64() && (c.Uint64() == 0 || c.Uint64() == 1)) {
			panic(fmt.Sprintf("assertIsBoolean failed: constant(%s)", c.String()))
		}
		return
	}
	t := i1.(compiled.Term)
	debug := cs.AddDebugInfo("assertIsBoolean", t, " == (0|1)")
	cs.addPlonkConstraint(t, t, 0, compiled.CoeffIdOne, compiled.CoeffIdZero, compiled.CoeffIdMinusOne, compiled.CoeffIdOne, compiled.CoeffIdZero, compiled.CoeffIdZero, debug)
}

// AssertIsLessOrEqual fails if  v > bound
func (cs *SparseR1CS) AssertIsLessOrEqual(v frontend.Variable, bound interface{}) {
	switch b := bound.(type) {
	case compiled.Term:
		cs.mustBeLessOrEqVar(v.(compiled.Term), b)
	default:
		cs.mustBeLessOrEqCst(v.(compiled.Term), frontend.FromInterface(b))
	}
}

func (cs *SparseR1CS) mustBeLessOrEqCst(a compiled.Term, bound big.Int) {

	nbBits := cs.BitLen()

	// ensure the bound is positive, it's bit-len doesn't matter
	if bound.Sign() == -1 {
		panic("AssertIsLessOrEqual: bound must be positive")
	}
	if bound.BitLen() > nbBits {
		panic("AssertIsLessOrEqual: bound is too large, constraint will never be satisfied")
	}

	// debug info
	debug := cs.AddDebugInfo("mustBeLessOrEq", a, " <= ", bound)

	// note that at this stage, we didn't boolean-constraint these new variables yet
	// (as opposed to ToBinary)
	aBits := cs.toBinary(a, nbBits, true)

	// t trailing bits in the bound
	t := 0
	for i := 0; i < nbBits; i++ {
		if bound.Bit(i) == 0 {
			break
		}
		t++
	}

	p := make([]frontend.Variable, nbBits+1)
	// p[i] == 1 --> a[j] == c[j] for all j >= i
	p[nbBits] = 1

	for i := nbBits - 1; i >= t; i-- {
		if bound.Bit(i) == 0 {
			p[i] = p[i+1]
		} else {
			p[i] = cs.Mul(p[i+1], aBits[i])
		}
	}

	for i := nbBits - 1; i >= 0; i-- {
		if bound.Bit(i) == 0 {
			// (1 - p(i+1) - ai) * ai == 0
			l := cs.Sub(1, p[i+1]).(compiled.Term)
			l = cs.Sub(l, aBits[i]).(compiled.Term)

			cs.addPlonkConstraint(l, aBits[i], 0, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdOne, compiled.CoeffIdOne, compiled.CoeffIdZero, compiled.CoeffIdZero, debug)
			// cs.markBoolean(aBits[i].(compiled.Term))
		} else {
			cs.AssertIsBoolean(aBits[i])
		}
	}

}

func (cs *SparseR1CS) mustBeLessOrEqVar(a compiled.Term, bound compiled.Term) {

	debug := cs.AddDebugInfo("mustBeLessOrEq", a, " <= ", bound)

	nbBits := cs.BitLen()

	aBits := cs.toBinary(a, nbBits, true)
	boundBits := cs.ToBinary(bound, nbBits)

	p := make([]frontend.Variable, nbBits+1)
	p[nbBits] = 1

	for i := nbBits - 1; i >= 0; i-- {

		// if bound[i] == 0
		// 		p[i] = p[i+1]
		//		t = p[i+1]
		// else
		// 		p[i] = p[i+1] * a[i]
		//		t = 0
		v := cs.Mul(p[i+1], aBits[i])
		p[i] = cs.Select(boundBits[i], v, p[i+1])

		t := cs.Select(boundBits[i], 0, p[i+1])

		// (1 - t - ai) * ai == 0
		l := cs.Sub(1, t, aBits[i])

		// note if bound[i] == 1, this constraint is (1 - ai) * ai == 0
		// --> this is a boolean constraint
		// if bound[i] == 0, t must be 0 or 1, thus ai must be 0 or 1 too
		// cs.markBoolean(aBits[i].(compiled.Term)) // this does not create a constraint

		cs.addPlonkConstraint(l, aBits[i], 0, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdOne, compiled.CoeffIdOne, compiled.CoeffIdZero, compiled.CoeffIdZero, debug)
	}

}
