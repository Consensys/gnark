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

package fields_bls24315

import (
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
	expected := E24{}
	expected.Add(api, circuit.A, circuit.B)
	expected.MustBeEqual(api, circuit.C)
	return nil
}

func TestAddFp24(t *testing.T) {

	var circuit, witness fp24Add

	// witness values
	var a, b, c bls24315.E24
	a.SetRandom()
	b.SetRandom()
	c.Add(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))
}

type fp24Sub struct {
	A, B E24
	C    E24 `gnark:",public"`
}

func (circuit *fp24Sub) Define(api frontend.API) error {
	expected := E24{}
	expected.Sub(api, circuit.A, circuit.B)
	expected.MustBeEqual(api, circuit.C)
	return nil
}

func TestSubFp24(t *testing.T) {

	var circuit, witness fp24Sub

	// witness values
	var a, b, c bls24315.E24
	a.SetRandom()
	b.SetRandom()
	c.Sub(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))
}

type fp24Mul struct {
	A, B E24
	C    E24 `gnark:",public"`
}

func (circuit *fp24Mul) Define(api frontend.API) error {
	expected := E24{}
	ext := GetBLS24315ExtensionFp24(api)
	expected.Mul(api, circuit.A, circuit.B, ext)
	expected.MustBeEqual(api, circuit.C)
	return nil
}

func TestMulFp24(t *testing.T) {

	var circuit, witness fp24Mul

	// witness values
	var a, b, c bls24315.E24
	a.SetRandom()
	b.SetRandom()
	c.Mul(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))
}

type fp24Square struct {
	A E24
	B E24 `gnark:",public"`
}

func (circuit *fp24Square) Define(api frontend.API) error {
	ext := GetBLS24315ExtensionFp24(api)
	s := circuit.A.Square(api, circuit.A, ext)
	s.MustBeEqual(api, circuit.B)
	return nil
}

func TestSquareFp24(t *testing.T) {

	var circuit, witness fp24Square

	// witness values
	var a, b bls24315.E24
	a.SetRandom()
	b.Square(&a)

	witness.A.Assign(&a)
	witness.B.Assign(&b)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

}

/*
type fp24CycloSquare struct {
	A E24
	B E24 `gnark:",public"`
}

func (circuit *fp24CycloSquare) Define(api frontend.API) error {
	ext := GetBLS24315ExtensionFp24(api)
	var u, v E24
	u.Square(api, circuit.A, ext)
	v.CyclotomicSquare(api, circuit.A, ext)
	u.MustBeEqual(api, v)
	u.MustBeEqual(api, circuit.B)
	return nil
}

func TestFp24CyclotomicSquare(t *testing.T) {

	var circuit, witness fp24CycloSquare

	// witness values
	var a, b bls24315.E24
	a.SetRandom()

	// put a in the cyclotomic subgroup (we assume the group is Fp24, field of definition of bls277)
	var tmp bls24315.E24
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)

	b.CyclotomicSquare(&a)
	witness.A.Assign(&a)
	witness.B.Assign(&b)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

}
*/

type fp24Conjugate struct {
	A E24
	C E24 `gnark:",public"`
}

func (circuit *fp24Conjugate) Define(api frontend.API) error {
	expected := E24{}
	expected.Conjugate(api, circuit.A)
	expected.MustBeEqual(api, circuit.C)
	return nil
}

func TestConjugateFp24(t *testing.T) {

	var circuit, witness fp24Conjugate

	// witness values
	var a, c bls24315.E24
	a.SetRandom()
	c.Conjugate(&a)

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))
}

type fp24Inverse struct {
	A E24
	C E24 `gnark:",public"`
}

func (circuit *fp24Inverse) Define(api frontend.API) error {
	expected := E24{}
	ext := GetBLS24315ExtensionFp24(api)
	expected.Inverse(api, circuit.A, ext)
	expected.MustBeEqual(api, circuit.C)
	return nil
}

func TestInverseFp24(t *testing.T) {

	var circuit, witness fp24Inverse

	// witness values
	var a, c bls24315.E24
	a.SetRandom()
	c.Inverse(&a)

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))
}

// benches
var ccsBench frontend.CompiledConstraintSystem

func BenchmarkMulE12(b *testing.B) {
	var c fp24Mul
	b.Run("groth16", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccsBench, _ = frontend.Compile(ecc.BW6_633, backend.GROTH16, &c)
		}

	})
	b.Log("groth16", ccsBench.GetNbConstraints())
}

func BenchmarkSquareE12(b *testing.B) {
	var c fp24Square
	b.Run("groth16", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccsBench, _ = frontend.Compile(ecc.BW6_633, backend.GROTH16, &c)
		}

	})
	b.Log("groth16", ccsBench.GetNbConstraints())
}

func BenchmarkInverseE12(b *testing.B) {
	var c fp24Inverse
	b.Run("groth16", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccsBench, _ = frontend.Compile(ecc.BW6_633, backend.GROTH16, &c)
		}

	})
	b.Log("groth16", ccsBench.GetNbConstraints())
}

func BenchmarkConjugateE12(b *testing.B) {
	var c fp24Conjugate
	b.Run("groth16", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccsBench, _ = frontend.Compile(ecc.BW6_633, backend.GROTH16, &c)
		}

	})
	b.Log("groth16", ccsBench.GetNbConstraints())
}
