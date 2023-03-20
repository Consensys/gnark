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
	"crypto/rand"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"testing"
)

const testCurve = ecc.BN254

type millerLoopBW6761 struct {
	A G1Affine
	B G2Affine
	C GT
}

func (circuit *millerLoopBW6761) Define(api frontend.API) error {
	pr, err := NewPairing(api)
	if err != nil {
		panic(err)
	}
	expected, err := pr.MillerLoop([]*G1Affine{&circuit.A}, []*G2Affine{&circuit.B})
	if err != nil {
		return err
	}

	pr.Equal(expected, &circuit.C)

	return nil
}

func TestMillerLoopBW6761(t *testing.T) {
	assert := test.NewAssert(t)
	for i := 0; i < 1; i++ {
		fmt.Println("round:", i)
		// witness values
		var (
			a     bw6761.G1Affine
			b     bw6761.G2Affine
			c     bw6761.GT
			r1, _ = rand.Int(rand.Reader, fr.Modulus())
			r2, _ = rand.Int(rand.Reader, fr.Modulus())
		)
		_, _, g1, g2 := bw6761.Generators()

		a.ScalarMultiplication(&g1, r1)
		b.ScalarMultiplication(&g2, r2)
		c, err := bw6761.MillerLoop([]bw6761.G1Affine{a}, []bw6761.G2Affine{b})
		if err != nil {
			panic(err)
		}

		witness := millerLoopBW6761{
			A: NewG1Affine(a),
			B: NewG2Affine(b),
			C: NewE6(c),
		}

		err = test.IsSolved(&millerLoopBW6761{}, &witness, testCurve.ScalarField())
		assert.NoError(err)
	}
}

type tripleMillerLoopBW6761 struct {
	A1, A2, A3 G1Affine
	B1, B2, B3 G2Affine
	C          GT
}

func (circuit *tripleMillerLoopBW6761) Define(api frontend.API) error {
	pr, err := NewPairing(api)
	if err != nil {
		panic(err)
	}
	expected, err := pr.MillerLoop([]*G1Affine{&circuit.A1, &circuit.A2, &circuit.A3}, []*G2Affine{&circuit.B1, &circuit.B2, &circuit.B3})
	if err != nil {
		return err
	}

	pr.Equal(expected, &circuit.C)

	return nil
}

func TestDoubleMillerLoopBW6761(t *testing.T) {
	assert := test.NewAssert(t)
	for i := 0; i < 1; i++ {
		fmt.Println("round:", i)
		// witness values
		var (
			a1, a2, a3 bw6761.G1Affine
			b1, b2, b3 bw6761.G2Affine
			c          bw6761.GT
			r1, _      = rand.Int(rand.Reader, fr.Modulus())
			r2, _      = rand.Int(rand.Reader, fr.Modulus())
			r3, _      = rand.Int(rand.Reader, fr.Modulus())
			r4, _      = rand.Int(rand.Reader, fr.Modulus())
			r5, _      = rand.Int(rand.Reader, fr.Modulus())
			r6, _      = rand.Int(rand.Reader, fr.Modulus())
		)
		_, _, g1, g2 := bw6761.Generators()

		a1.ScalarMultiplication(&g1, r1)
		a2.ScalarMultiplication(&g1, r2)
		a3.ScalarMultiplication(&g1, r3)
		b1.ScalarMultiplication(&g2, r4)
		b2.ScalarMultiplication(&g2, r5)
		b3.ScalarMultiplication(&g2, r6)
		c, err := bw6761.MillerLoop([]bw6761.G1Affine{a1, a2, a3}, []bw6761.G2Affine{b1, b2, b3})
		if err != nil {
			panic(err)
		}

		witness := tripleMillerLoopBW6761{
			A1: NewG1Affine(a1),
			A2: NewG1Affine(a2),
			A3: NewG1Affine(a3),
			B1: NewG2Affine(b1),
			B2: NewG2Affine(b2),
			B3: NewG2Affine(b3),
			C:  NewE6(c),
		}

		err = test.IsSolved(&tripleMillerLoopBW6761{}, &witness, testCurve.ScalarField())
		assert.NoError(err)
	}
}

type finalExponentiationBW6761 struct {
	A GT
	B GT
}

func (circuit *finalExponentiationBW6761) Define(api frontend.API) error {
	pr, err := NewPairing(api)
	if err != nil {
		panic(err)
	}
	expected := pr.FinalExponentiation(&circuit.A)
	if err != nil {
		return err
	}

	pr.Equal(expected, &circuit.B)

	return nil
}

func TestFinalExponentiationBW6761(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var (
		a     bw6761.G1Affine
		b     bw6761.G2Affine
		c     bw6761.GT
		r1, _ = rand.Int(rand.Reader, fr.Modulus())
		r2, _ = rand.Int(rand.Reader, fr.Modulus())
	)
	_, _, g1, g2 := bw6761.Generators()

	a.ScalarMultiplication(&g1, r1)
	b.ScalarMultiplication(&g2, r2)
	c, err := bw6761.MillerLoop([]bw6761.G1Affine{a}, []bw6761.G2Affine{b})
	if err != nil {
		panic(err)
	}

	d := bw6761.FinalExponentiation(&c)

	witness := finalExponentiationBW6761{
		A: NewE6(c),
		B: NewE6(d),
	}

	err = test.IsSolved(&finalExponentiationBW6761{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type pairingBW6761 struct {
	A G1Affine
	B G2Affine
	C GT
}

func (circuit *pairingBW6761) Define(api frontend.API) error {
	pr, err := NewPairing(api)
	if err != nil {
		panic(err)
	}
	expected, err := pr.Pair([]*G1Affine{&circuit.A}, []*G2Affine{&circuit.B})
	if err != nil {
		return err
	}

	pr.Equal(expected, &circuit.C)

	return nil
}

func TestPairingBW6761(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var (
		a     bw6761.G1Affine
		b     bw6761.G2Affine
		c     bw6761.GT
		r1, _ = rand.Int(rand.Reader, fr.Modulus())
		r2, _ = rand.Int(rand.Reader, fr.Modulus())
	)
	_, _, g1, g2 := bw6761.Generators()

	a.ScalarMultiplication(&g1, r1)
	b.ScalarMultiplication(&g2, r2)
	c, err := bw6761.Pair([]bw6761.G1Affine{a}, []bw6761.G2Affine{b})
	if err != nil {
		panic(err)
	}

	witness := pairingBW6761{
		A: NewG1Affine(a),
		B: NewG2Affine(b),
		C: NewE6(c),
	}

	err = test.IsSolved(&pairingBW6761{}, &witness, testCurve.ScalarField())
	assert.NoError(err)

	_, err = frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &pairingBW6761{}, frontend.IgnoreUnconstrainedInputs())
	assert.NoError(err)
}
