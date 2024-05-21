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
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/internal/expr"
)

func TestQuickSort(t *testing.T) {

	toSort := make(expr.LinearExpression, 12)
	rand := 3
	for i := 0; i < 12; i++ {
		toSort[i].VID = rand
		rand += 3
		rand = rand % 13
	}

	sort.Sort(toSort)

	for i := 0; i < 10; i++ {
		cur := toSort[i].WireID()
		next := toSort[i+1].WireID()
		if cur >= next {
			t.Fatal("err sorting linear expression")
		}
	}

}

func TestReduce(t *testing.T) {

	cs := newBuilder(ecc.BN254.ScalarField(), frontend.CompileConfig{})
	x := cs.newInternalVariable()
	y := cs.newInternalVariable()
	z := cs.newInternalVariable()

	a := cs.Mul(x, 3)
	b := cs.Mul(x, 5)
	c := cs.Mul(y, 10)
	d := cs.Mul(y, 11)
	e := cs.Mul(z, 2)
	f := cs.Mul(z, 2)

	toTest := (cs.Add(a, b, c, d, e, f)).(expr.LinearExpression)

	// check sizes
	if len(toTest) != 3 {
		t.Fatal("Error reduce, duplicate variables not collapsed")
	}

}

func TestCompress(t *testing.T) {
	cs := newBuilder(ecc.BN254.ScalarField(), frontend.CompileConfig{CompressThreshold: 3})
	vars := make([]frontend.Variable, 4)
	for i := range vars {
		v := cs.newInternalVariable()
		vars[i] = cs.Mul(v, 1<<i)
	}

	// if add two variables, then should not compress
	v1 := cs.Add(vars[0], vars[1])
	if vli1 := v1.(expr.LinearExpression); len(vli1) != 2 {
		t.Fatalf("expected linear expression length 2, got %d", len(vli1))
	}
	// if add three vars, then should compress
	v2 := cs.Add(vars[0], vars[1], vars[2])
	if vli2 := v2.(expr.LinearExpression); len(vli2) != 1 {
		t.Fatalf("expected linear expression length 1, got %d", len(vli2))
	}
}

func BenchmarkReduce(b *testing.B) {
	cs := newBuilder(ecc.BN254.ScalarField(), frontend.CompileConfig{})
	// 4 interesting cases;
	// Add many small linear expressions
	// Add few large linear expressions
	// Add many large linear expressions
	// Doubling of large linear expressions
	rand := rand.New(rand.NewSource(time.Now().Unix())) //#nosec G404 weak rng is fine here
	const nbTerms = 100000
	terms := make([]frontend.Variable, nbTerms)
	for i := 0; i < len(terms); i++ {
		terms[i] = cs.newInternalVariable()
	}

	rL := make([]frontend.Variable, 1000)
	for i := 0; i < len(rL); i++ {
		rL[i] = cs.Mul(terms[i%50], rand.Uint64()) //#nosec G404 -- This is a false positive
	}

	mL := make([]frontend.Variable, 1000)
	b.ResetTimer()
	b.Run("reduce redudancy", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			mL[i%len(mL)] = cs.Add(rand.Uint64(), rL[0], rL[1:]...) //#nosec G404 -- This is a false positive
		}
	})

	b.ResetTimer()
	b.Run("many small", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = cs.Add(mL[0], mL[1], mL[2:]...)
		}
	})

	c := cs.Add(terms[0], terms[1], terms[2:]...)

	b.ResetTimer()
	b.Run("doubling large", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = cs.Add(c, c)
		}
	})
}

type EmptyCircuit struct {
	X  frontend.Variable
	cb func(frontend.API) error
}

func (c *EmptyCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, 0)
	api.Compiler().Defer(c.cb)
	return nil
}

func TestPreCompileHook(t *testing.T) {
	var called bool
	c := &EmptyCircuit{
		cb: func(a frontend.API) error { called = true; return nil },
	}
	_, err := frontend.Compile(ecc.BN254.ScalarField(), NewBuilder, c)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("callback not called")
	}
}

type subSameNoConstraintCircuit struct {
	A frontend.Variable
}

func (c *subSameNoConstraintCircuit) Define(api frontend.API) error {
	r := api.Sub(c.A, c.A)
	api.AssertIsEqual(r, 0)
	return nil
}

func TestSubSameNoConstraint(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), NewBuilder, &subSameNoConstraintCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	if ccs.GetNbConstraints() != 0 {
		t.Fatal("expected 0 constraints")
	}
}
