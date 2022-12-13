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

const testCurve = ecc.BN254

type e3Add struct {
	A, B, C E3
}

func (circuit *e3Add) Define(api frontend.API) error {
	var expected E3
	expected.Add(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestAddFp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b, c bw6761.E3
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	circuit := e3Add{
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](nil),
			A1: emulated.NewElement[emulated.BW6761Fp](nil),
			A2: emulated.NewElement[emulated.BW6761Fp](nil),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](nil),
			A1: emulated.NewElement[emulated.BW6761Fp](nil),
			A2: emulated.NewElement[emulated.BW6761Fp](nil),
		},
		C: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](nil),
			A1: emulated.NewElement[emulated.BW6761Fp](nil),
			A2: emulated.NewElement[emulated.BW6761Fp](nil),
		},
	}

	witness := e3Add{
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](a.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](a.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](a.A2),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](b.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](b.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](b.A2),
		},
		C: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](c.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](c.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](c.A2),
		},
	}

	wrapperOpt := test.WithApiWrapper(func(api frontend.API) frontend.API {
		napi, err := emulated.NewAPI[emulated.BW6761Fp](api)
		assert.NoError(err)
		return napi
	})

	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), wrapperOpt)
	assert.NoError(err)
}

type e3Sub struct {
	A, B, C E3
}

func (circuit *e3Sub) Define(api frontend.API) error {
	var expected E3
	expected.Sub(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestSubFp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b, c bw6761.E3
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)

	circuit := e3Sub{
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](nil),
			A1: emulated.NewElement[emulated.BW6761Fp](nil),
			A2: emulated.NewElement[emulated.BW6761Fp](nil),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](nil),
			A1: emulated.NewElement[emulated.BW6761Fp](nil),
			A2: emulated.NewElement[emulated.BW6761Fp](nil),
		},
		C: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](nil),
			A1: emulated.NewElement[emulated.BW6761Fp](nil),
			A2: emulated.NewElement[emulated.BW6761Fp](nil),
		},
	}

	witness := e3Sub{
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](a.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](a.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](a.A2),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](b.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](b.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](b.A2),
		},
		C: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](c.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](c.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](c.A2),
		},
	}

	wrapperOpt := test.WithApiWrapper(func(api frontend.API) frontend.API {
		napi, err := emulated.NewAPI[emulated.BW6761Fp](api)
		assert.NoError(err)
		return napi
	})

	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), wrapperOpt)
	assert.NoError(err)
}

type e3Neg struct {
	A, B E3
}

func (circuit *e3Neg) Define(api frontend.API) error {
	var expected E3
	expected.Neg(api, circuit.A)
	expected.AssertIsEqual(api, circuit.B)
	return nil
}

func TestNegFp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E3
	_, _ = a.SetRandom()
	b.Neg(&a)

	circuit := e3Neg{
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](nil),
			A1: emulated.NewElement[emulated.BW6761Fp](nil),
			A2: emulated.NewElement[emulated.BW6761Fp](nil),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](nil),
			A1: emulated.NewElement[emulated.BW6761Fp](nil),
			A2: emulated.NewElement[emulated.BW6761Fp](nil),
		},
	}

	witness := e3Neg{
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](a.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](a.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](a.A2),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](b.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](b.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](b.A2),
		},
	}

	wrapperOpt := test.WithApiWrapper(func(api frontend.API) frontend.API {
		napi, err := emulated.NewAPI[emulated.BW6761Fp](api)
		assert.NoError(err)
		return napi
	})

	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), wrapperOpt)
	assert.NoError(err)
}

type e3Double struct {
	A, B E3
}

func (circuit *e3Double) Define(api frontend.API) error {
	var expected E3
	expected.Double(api, circuit.A)
	expected.AssertIsEqual(api, circuit.B)
	return nil
}

func TestDoubleFp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E3
	_, _ = a.SetRandom()
	b.Double(&a)

	circuit := e3Double{
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](nil),
			A1: emulated.NewElement[emulated.BW6761Fp](nil),
			A2: emulated.NewElement[emulated.BW6761Fp](nil),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](nil),
			A1: emulated.NewElement[emulated.BW6761Fp](nil),
			A2: emulated.NewElement[emulated.BW6761Fp](nil),
		},
	}

	witness := e3Double{
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](a.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](a.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](a.A2),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](b.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](b.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](b.A2),
		},
	}

	wrapperOpt := test.WithApiWrapper(func(api frontend.API) frontend.API {
		napi, err := emulated.NewAPI[emulated.BW6761Fp](api)
		assert.NoError(err)
		return napi
	})

	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), wrapperOpt)
	assert.NoError(err)
}

type e3Mul struct {
	A, B, C E3
}

func (circuit *e3Mul) Define(api frontend.API) error {
	var expected E3
	expected.Mul(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestMulFp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b, c bw6761.E3
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	circuit := e3Mul{
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](nil),
			A1: emulated.NewElement[emulated.BW6761Fp](nil),
			A2: emulated.NewElement[emulated.BW6761Fp](nil),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](nil),
			A1: emulated.NewElement[emulated.BW6761Fp](nil),
			A2: emulated.NewElement[emulated.BW6761Fp](nil),
		},
		C: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](nil),
			A1: emulated.NewElement[emulated.BW6761Fp](nil),
			A2: emulated.NewElement[emulated.BW6761Fp](nil),
		},
	}

	witness := e3Mul{
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](a.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](a.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](a.A2),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](b.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](b.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](b.A2),
		},
		C: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](c.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](c.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](c.A2),
		},
	}

	wrapperOpt := test.WithApiWrapper(func(api frontend.API) frontend.API {
		napi, err := emulated.NewAPI[emulated.BW6761Fp](api)
		assert.NoError(err)
		return napi
	})

	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), wrapperOpt)
	assert.NoError(err)
}

type e3MulByNonResidue struct {
	A, B E3
}

func (circuit *e3MulByNonResidue) Define(api frontend.API) error {
	var expected E3
	expected.MulByNonResidue(api, circuit.A)
	expected.AssertIsEqual(api, circuit.B)
	return nil
}

func TestMulByNonResidueFp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E3
	_, _ = a.SetRandom()
	b.MulByNonResidue(&a)

	circuit := e3MulByNonResidue{
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](nil),
			A1: emulated.NewElement[emulated.BW6761Fp](nil),
			A2: emulated.NewElement[emulated.BW6761Fp](nil),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](nil),
			A1: emulated.NewElement[emulated.BW6761Fp](nil),
			A2: emulated.NewElement[emulated.BW6761Fp](nil),
		},
	}

	witness := e3MulByNonResidue{
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](a.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](a.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](a.A2),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](b.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](b.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](b.A2),
		},
	}

	wrapperOpt := test.WithApiWrapper(func(api frontend.API) frontend.API {
		napi, err := emulated.NewAPI[emulated.BW6761Fp](api)
		assert.NoError(err)
		return napi
	})

	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), wrapperOpt)
	assert.NoError(err)
}

type e3MulBy01 struct {
	A      E3
	C0, C1 frontend.Variable
	B      E3
}

func (circuit *e3MulBy01) Define(api frontend.API) error {
	circuit.A.MulBy01(api, circuit.C0, circuit.C1)
	circuit.A.AssertIsEqual(api, circuit.B)
	return nil
}

func TestMulBy01Fp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E3
	_, _ = a.SetRandom()
	var c0, c1 fp.Element
	c0.SetRandom()
	c1.SetRandom()
	b.Set(&a)
	b.MulBy01(&c0, &c1)

	circuit := e3MulBy01{
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](nil),
			A1: emulated.NewElement[emulated.BW6761Fp](nil),
			A2: emulated.NewElement[emulated.BW6761Fp](nil),
		},
		C0: emulated.NewElement[emulated.BW6761Fp](nil),
		C1: emulated.NewElement[emulated.BW6761Fp](nil),
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](nil),
			A1: emulated.NewElement[emulated.BW6761Fp](nil),
			A2: emulated.NewElement[emulated.BW6761Fp](nil),
		},
	}

	witness := e3MulBy01{
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](a.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](a.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](a.A2),
		},
		C0: emulated.NewElement[emulated.BW6761Fp](c0),
		C1: emulated.NewElement[emulated.BW6761Fp](c1),
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](b.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](b.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](b.A2),
		},
	}

	wrapperOpt := test.WithApiWrapper(func(api frontend.API) frontend.API {
		napi, err := emulated.NewAPI[emulated.BW6761Fp](api)
		assert.NoError(err)
		return napi
	})

	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), wrapperOpt)
	assert.NoError(err)
}

type e3Square struct {
	A, B E3
}

func (circuit *e3Square) Define(api frontend.API) error {
	var expected E3
	expected.Square(api, circuit.A)
	expected.AssertIsEqual(api, circuit.B)
	return nil
}

func TestSquareFp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E3
	_, _ = a.SetRandom()
	b.Square(&a)

	circuit := e3Square{
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](nil),
			A1: emulated.NewElement[emulated.BW6761Fp](nil),
			A2: emulated.NewElement[emulated.BW6761Fp](nil),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](nil),
			A1: emulated.NewElement[emulated.BW6761Fp](nil),
			A2: emulated.NewElement[emulated.BW6761Fp](nil),
		},
	}

	witness := e3Square{
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](a.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](a.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](a.A2),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](b.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](b.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](b.A2),
		},
	}

	wrapperOpt := test.WithApiWrapper(func(api frontend.API) frontend.API {
		napi, err := emulated.NewAPI[emulated.BW6761Fp](api)
		assert.NoError(err)
		return napi
	})

	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), wrapperOpt)
	assert.NoError(err)
}

type e3Inverse struct {
	A, B E3
}

func (circuit *e3Inverse) Define(api frontend.API) error {
	var expected E3
	expected.Inverse(api, circuit.A)
	expected.AssertIsEqual(api, circuit.B)
	return nil
}

func TestInverseFp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E3
	_, _ = a.SetRandom()
	b.Inverse(&a)

	circuit := e3Inverse{
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](nil),
			A1: emulated.NewElement[emulated.BW6761Fp](nil),
			A2: emulated.NewElement[emulated.BW6761Fp](nil),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](nil),
			A1: emulated.NewElement[emulated.BW6761Fp](nil),
			A2: emulated.NewElement[emulated.BW6761Fp](nil),
		},
	}

	witness := e3Inverse{
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](a.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](a.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](a.A2),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](b.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](b.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](b.A2),
		},
	}

	wrapperOpt := test.WithApiWrapper(func(api frontend.API) frontend.API {
		napi, err := emulated.NewAPI[emulated.BW6761Fp](api)
		assert.NoError(err)
		return napi
	})

	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), wrapperOpt)
	assert.NoError(err)
}
