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

package fp24

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

//--------------------------------------------------------------------
// test

type fp24Add struct {
	A, B E24
	C    E24 `gnark:",public"`
}

func (circuit *fp24Add) Define(api frontend.API) error {
	expected, err := NewFp24Zero(api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expected.Add(circuit.A, circuit.B)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestAddFp24(t *testing.T) {

	var circuit, witness fp24Add

	// witness values
	var a, b, c bls24315.E24
	a.SetRandom()
	b.SetRandom()
	c.Add(&a, &b)

	witness.A = FromFp24(a)
	witness.B = FromFp24(b)
	witness.C = FromFp24(c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))
}

type fp24Sub struct {
	A, B E24
	C    E24 `gnark:",public"`
}

func (circuit *fp24Sub) Define(api frontend.API) error {
	expected, err := NewFp24Zero(api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expected.Sub(circuit.A, circuit.B)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestSubFp24(t *testing.T) {

	var circuit, witness fp24Sub

	// witness values
	var a, b, c bls24315.E24
	a.SetRandom()
	b.SetRandom()
	c.Sub(&a, &b)

	witness.A = FromFp24(a)
	witness.B = FromFp24(b)
	witness.C = FromFp24(c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))
}

type fp24Mul struct {
	A, B E24
	C    E24 `gnark:",public"`
}

func (circuit *fp24Mul) Define(api frontend.API) error {
	expected, err := NewFp24Zero(api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expected.Mul(circuit.A, circuit.B)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestMulFp24(t *testing.T) {

	var circuit, witness fp24Mul

	// witness values
	var a, b, c bls24315.E24
	a.SetRandom()
	b.SetRandom()
	c.Mul(&a, &b)

	witness.A = FromFp24(a)
	witness.B = FromFp24(b)
	witness.C = FromFp24(c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))
}

type fp24Square struct {
	A E24
	B E24 `gnark:",public"`
}

func (circuit *fp24Square) Define(api frontend.API) error {
	expected, err := NewFp24Zero(api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expected.Square(circuit.A)
	expected.MustBeEqual(circuit.B)
	return nil
}

func TestSquareFp24(t *testing.T) {

	var circuit, witness fp24Square

	// witness values
	var a, b bls24315.E24
	a.SetRandom()
	b.Square(&a)

	witness.A = FromFp24(a)
	witness.B = FromFp24(b)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

}

type fp24CycloSquare struct {
	A E24
	B E24 `gnark:",public"`
}

func (circuit *fp24CycloSquare) Define(api frontend.API) error {
	u, err := NewFp24Zero(api)
	if err != nil {
		return fmt.Errorf("new u: %w", err)
	}
	v, err := NewFp24Zero(api)
	if err != nil {
		return fmt.Errorf("new v: %w", err)
	}
	u.Square(circuit.A)
	v.CyclotomicSquare(circuit.A)
	u.MustBeEqual(v)
	u.MustBeEqual(circuit.B)
	return nil
}

func TestFp24CyclotomicSquare(t *testing.T) {

	var circuit, witness fp24CycloSquare

	// witness values
	var a, b bls24315.E24
	a.SetRandom()

	// put a in the cyclotomic subgroup (we assume the group is Fp24, field of definition of bls24-315)
	var tmp bls24315.E24
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusQuad(&tmp).Mul(&a, &tmp)

	b.CyclotomicSquare(&a)
	witness.A = FromFp24(a)
	witness.B = FromFp24(b)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

}

type fp24CycloSquareCompressed struct {
	A E24
	B E24 `gnark:",public"`
}

func (circuit *fp24CycloSquareCompressed) Define(api frontend.API) error {
	u, err := NewFp24Zero(api)
	if err != nil {
		return fmt.Errorf("new u: %w", err)
	}
	v, err := NewFp24Zero(api)
	if err != nil {
		return fmt.Errorf("new v: %w", err)
	}
	u.Square(circuit.A)
	v.CyclotomicSquareCompressed(circuit.A)
	v.Decompress(v)
	u.MustBeEqual(v)
	u.MustBeEqual(circuit.B)
	return nil
}

func TestFp24CyclotomicSquareCompressed(t *testing.T) {

	var circuit, witness fp24CycloSquareCompressed

	// witness values
	var a, b bls24315.E24
	a.SetRandom()

	// put a in the cyclotomic subgroup (we assume the group is Fp24, field of definition of bls24-315)
	var tmp bls24315.E24
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusQuad(&tmp).Mul(&a, &tmp)

	b.CyclotomicSquare(&a)
	b.Decompress(&b)
	witness.A = FromFp24(a)
	witness.B = FromFp24(b)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

}

type fp24Conjugate struct {
	A E24
	C E24 `gnark:",public"`
}

func (circuit *fp24Conjugate) Define(api frontend.API) error {
	expected, err := NewFp24Zero(api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expected.Conjugate(circuit.A)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestConjugateFp24(t *testing.T) {

	var circuit, witness fp24Conjugate

	// witness values
	var a, c bls24315.E24
	a.SetRandom()
	c.Conjugate(&a)

	witness.A = FromFp24(a)
	witness.C = FromFp24(c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))
}

type fp24Inverse struct {
	A E24
	C E24 `gnark:",public"`
}

func (circuit *fp24Inverse) Define(api frontend.API) error {
	expected, err := NewFp24Zero(api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expected.Inverse(circuit.A)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestInverseFp24(t *testing.T) {

	var circuit, witness fp24Inverse

	// witness values
	var a, c bls24315.E24
	a.SetRandom()
	c.Inverse(&a)

	witness.A = FromFp24(a)
	witness.C = FromFp24(c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))
}

type fp24MulBy034 struct {
	A    E24 `gnark:",public"`
	W    E24
	B, C E4
}

func (circuit *fp24MulBy034) Define(api frontend.API) error {
	expected, err := NewFp24Zero(api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expected.Set(circuit.A)
	expected.MulBy034(circuit.B, circuit.C)
	expected.MustBeEqual(circuit.W)
	return nil
}

func TestFp24MulBy034(t *testing.T) {

	var circuit, witness fp24MulBy034

	var a bls24315.E24
	var b, c, one bls24315.E4
	one.SetOne()
	a.SetRandom()
	witness.A = FromFp24(a)

	b.SetRandom()
	witness.B = FromFp4(b)

	c.SetRandom()
	witness.C = FromFp4(c)

	a.MulBy034(&one, &b, &c)
	witness.W = FromFp24(a)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

}

type fp24Frobenius struct {
	A       E24
	C, D, E E24 `gnark:",public"`
}

func (circuit *fp24Frobenius) Define(api frontend.API) error {

	fb, err := NewFp24Zero(api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	fb.Frobenius(circuit.A)
	fb.MustBeEqual(circuit.C)

	fbSquare, err := NewFp24Zero(api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	fbSquare.FrobeniusSquare(circuit.A)
	fbSquare.MustBeEqual(circuit.D)

	fbQuad, err := NewFp24Zero(api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	fbQuad.FrobeniusQuad(circuit.A)
	fbQuad.MustBeEqual(circuit.E)

	return nil
}

func TestFrobeniusFp24(t *testing.T) {

	var circuit, witness fp24Frobenius

	// witness values
	var a, c, d, e bls24315.E24
	a.SetRandom()
	c.Frobenius(&a)
	d.FrobeniusSquare(&a)
	e.FrobeniusQuad(&a)

	witness.A = FromFp24(a)
	witness.C = FromFp24(c)
	witness.D = FromFp24(d)
	witness.E = FromFp24(e)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))
}

type fp24FinalExpo struct {
	A E24
	C E24 `gnark:",public"`
}

func (circuit *fp24FinalExpo) Define(api frontend.API) error {
	expected, err := NewFp24Zero(api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expo := uint64(3218079743)
	expected.FinalExponentiation(circuit.A, expo)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestExpFinalExpoFp24(t *testing.T) {
	var circuit, witness fp24FinalExpo

	// witness values
	var a, c bls24315.E24

	a.SetRandom()
	c = bls24315.FinalExponentiation(&a)

	witness.A = FromFp24(a)
	witness.C = FromFp24(c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))
}

// benches
var ccsBench frontend.CompiledConstraintSystem

func BenchmarkMulE24(b *testing.B) {
	var c fp24Mul
	b.Run("groth16", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccsBench, _ = frontend.Compile(ecc.BW6_633, backend.GROTH16, &c)
		}

	})
	b.Log("groth16", ccsBench.GetNbConstraints())
}

func BenchmarkSquareE24(b *testing.B) {
	var c fp24Square
	b.Run("groth16", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccsBench, _ = frontend.Compile(ecc.BW6_633, backend.GROTH16, &c)
		}

	})
	b.Log("groth16", ccsBench.GetNbConstraints())
}

func BenchmarkInverseE24(b *testing.B) {
	var c fp24Inverse
	b.Run("groth16", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccsBench, _ = frontend.Compile(ecc.BW6_633, backend.GROTH16, &c)
		}

	})
	b.Log("groth16", ccsBench.GetNbConstraints())
}

func BenchmarkConjugateE24(b *testing.B) {
	var c fp24Conjugate
	b.Run("groth16", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccsBench, _ = frontend.Compile(ecc.BW6_633, backend.GROTH16, &c)
		}

	})
	b.Log("groth16", ccsBench.GetNbConstraints())
}

func BenchmarkMulBy034E24(b *testing.B) {
	var c fp24MulBy034
	b.Run("groth16", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccsBench, _ = frontend.Compile(ecc.BW6_633, backend.GROTH16, &c)
		}

	})
	b.Log("groth16", ccsBench.GetNbConstraints())
}
