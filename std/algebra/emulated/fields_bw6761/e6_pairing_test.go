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

package fields_bw6761

import (
	"github.com/consensys/gnark-crypto/ecc"
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
	expected := e.Expt(&circuit.A)
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

	err := test.IsSolved(&e6Expt{}, &witness, ecc.BN254.ScalarField())
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
	expected := e.Expc2(&circuit.A)
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

	// add=287618 equals=4068 fromBinary=0 mul=281540 sub=3690 toBinary=0
	// add=197836 equals=3048 fromBinary=0 mul=188488 sub=3810 toBinary=0
	err := test.IsSolved(&e6Expc2{}, &witness, ecc.BN254.ScalarField())
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
	expected := e.Expc1(&circuit.A)
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

	// add=578954 equals=8028 fromBinary=0 mul=566870 sub=7248 toBinary=0
	err := test.IsSolved(&e6Expc1{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6MulBy034 struct {
	A, B       E6
	R0, R1, R2 BaseField
}

func (circuit *e6MulBy034) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	var l LineEvaluation
	l.R0 = circuit.R0
	l.R1 = circuit.R1
	l.R2 = circuit.R2
	expected := e.MulBy034(&circuit.A, &l)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestMulBy034Fp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Set(&a)
	var c0, c0Copy, c3, c4 fp.Element
	c0.SetRandom()
	c3.SetRandom()
	c4.SetRandom()
	c0Copy.Set(&c0)
	b.MulBy034(&c0, &c3, &c4)

	witness := e6MulBy034{
		A:  NewE6(a),
		R0: emulated.ValueOf[emulated.BW6761Fp](c0Copy),
		R1: emulated.ValueOf[emulated.BW6761Fp](c3),
		R2: emulated.ValueOf[emulated.BW6761Fp](c4),
		B:  NewE6(b),
	}

	//  add=54322 equals=823 fromBinary=0 mul=53414 sub=702 toBinary=0
	err := test.IsSolved(&e6MulBy034{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6Mul034By034 struct {
	D0, D3, D4 BaseField
	C0, C3, C4 BaseField
	Res        E6
}

func (circuit *e6Mul034By034) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected := e.Mul034By034(&circuit.D0, &circuit.D3, &circuit.D4, &circuit.C0, &circuit.C3, &circuit.C4)
	e.AssertIsEqual(expected, &circuit.Res)
	return nil
}

func TestMul034By034Fp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a bw6761.E6
	var d0, d3, d4, c0, c3, c4 fp.Element
	d0.SetRandom()
	d3.SetRandom()
	d4.SetRandom()
	c0.SetRandom()
	c3.SetRandom()
	c4.SetRandom()
	a.Mul034By034(&d0, &d3, &d4, &c0, &c3, &c4)

	witness := e6Mul034By034{
		D0:  emulated.ValueOf[emulated.BW6761Fp](d0),
		D3:  emulated.ValueOf[emulated.BW6761Fp](d3),
		D4:  emulated.ValueOf[emulated.BW6761Fp](d4),
		C0:  emulated.ValueOf[emulated.BW6761Fp](c0),
		C3:  emulated.ValueOf[emulated.BW6761Fp](c3),
		C4:  emulated.ValueOf[emulated.BW6761Fp](c4),
		Res: NewE6(a),
	}

	// add=28733 equals=438 fromBinary=0 mul=28386 sub=401 toBinary=0
	err := test.IsSolved(&e6Mul034By034{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
