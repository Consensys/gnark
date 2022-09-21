// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tensorcommitment

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type EvalAtPower struct {

	// polynomial
	P [16]frontend.Variable

	// variable at which P is evaluated
	X big.Int

	// size of the polynomial
	size uint64

	// exponent n at which we compute P(X^{n})
	N frontend.Variable

	// expected result P(X^{n})
	R frontend.Variable
}

func (circuit *EvalAtPower) Define(api frontend.API) error {

	r := evalAtPower(api, circuit.P[:], circuit.X, circuit.N, circuit.size)
	api.AssertIsEqual(r, circuit.R)

	return nil
}

func printPoly(p []fr.Element) {

	for i := 0; i < len(p)-1; i++ {
		fmt.Printf("%s*x**%d+", p[i].String(), i)
	}
	fmt.Printf("%s*x**%d\n", p[len(p)-1].String(), len(p)-1)

}

func TestEvalAtPower(t *testing.T) {

	// generate random polynomial
	var p [16]fr.Element
	for i := 0; i < 16; i++ {
		p[i].SetRandom()
	}

	// pick arbitrary point at which p is evaluated
	var x fr.Element
	x.SetRandom()

	// arbitrary exponent
	var e big.Int
	e.SetUint64(189)

	// exponentiate x mod BN254 scalar field
	var xexp fr.Element
	xexp.Exp(x, &e)

	// calcuate p(x^{e})
	var res fr.Element
	res.SetUint64(0)
	for i := 0; i < len(p); i++ {
		res.Mul(&res, &xexp)
		res.Add(&res, &p[len(p)-1-i])
	}

	// create the witness
	var witness EvalAtPower
	for i := 0; i < 16; i++ {
		witness.P[i] = p[i].String()
	}
	x.ToBigIntRegular(&witness.X)
	witness.size = 16
	witness.N = e.String()
	witness.R = res.String()

	// create the circuit
	var circuit EvalAtPower
	circuit.size = 16
	x.ToBigIntRegular(&circuit.X)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		t.Fatal(err)
	}

	// check if the solving is correct
	twitness, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	err = ccs.IsSolved(twitness)
	if err != nil {
		t.Fatal(err)
	}

}
