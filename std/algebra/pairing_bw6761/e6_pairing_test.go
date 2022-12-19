/*
 *
 * Copyright © 2020 ConsenSys
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * /
 */

package pairing_bw6761

import (
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"testing"
)

type e6Expt struct {
	A, B E6
}

func (circuit *e6Expt) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected := e.Zero()
	expected = e.Expt(&circuit.A)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestExptFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Set(&a)
	b.Expt(&a)

	witness := e6Expt{
		A: NewE6(a),
		B: NewE6(b),
	}

	err := test.IsSolved(&e6Expt{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type e6Expc2 struct {
	A, B E6
}

func (circuit *e6Expc2) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected := e.Set(&circuit.A)
	expected = e.Expc2(&circuit.A)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestExpc2Fp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Set(&a)
	b.Expc2(&a)

	witness := e6Expc2{
		A: NewE6(a),
		B: NewE6(b),
	}

	err := test.IsSolved(&e6Expc2{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type e6Expc1 struct {
	A, B E6
}

func (circuit *e6Expc1) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected := e.Set(&circuit.A)
	expected = e.Expc1(&circuit.A)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestExpc1Fp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Set(&a)
	b.Expc1(&a)

	witness := e6Expc1{
		A: NewE6(a),
		B: NewE6(b),
	}

	err := test.IsSolved(&e6Expc1{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type e6MulBy034 struct {
	A, B       E6
	C0, C3, C4 baseField
}

func (circuit *e6MulBy034) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	circuit.A = *e.MulBy034(&circuit.A, &circuit.C0, &circuit.C3, &circuit.C4)
	e.AssertIsEqual(&circuit.A, &circuit.B)
	return nil
}

func TestMulBy034Fp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Set(&a)
	var c0, c3, c4 fp.Element
	c0.SetRandom()
	c3.SetRandom()
	c4.SetRandom()
	b.MulBy034(&c0, &c3, &c4)

	witness := e6MulBy034{
		A:  NewE6(a),
		B:  NewE6(b),
		C0: emulated.NewElement[emulated.BW6761Fp](c0),
		C3: emulated.NewElement[emulated.BW6761Fp](c3),
		C4: emulated.NewElement[emulated.BW6761Fp](c4),
	}

	err := test.IsSolved(&e6MulBy034{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}
