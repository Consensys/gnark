// Copyright 2020 ConsenSys AG
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

package main

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/internal/backend/bn254/cs"

	"github.com/consensys/gnark/frontend"
)

// In this example we show how to use PLONK with KZG commitments. The circuit that is
// showed here is the same as in ../exponentiate.

// Circuit y == x**e
// only the bitSize least significant bits of e are used
type Circuit struct {
	// tagging a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`

	E frontend.Variable
}

// Define declares the circuit's constraints
// y == x**e
func (circuit *Circuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {

	// number of bits of exponent
	const bitSize = 3

	// specify constraints
	output := cs.Constant(1)
	bits := cs.ToBinary(circuit.E, bitSize)

	for i := 0; i < len(bits); i++ {
		// cs.Println(fmt.Sprintf("e[%d]", i), bits[i]) // we may print a variable for testing and / or debugging purposes

		if i != 0 {
			output = cs.Mul(output, output)
		}
		multiply := cs.Mul(output, circuit.X)
		output = cs.Select(bits[len(bits)-1-i], multiply, output)

	}

	cs.AssertIsEqual(circuit.Y, output)

	return nil
}

func main() {

	var circuit Circuit

	fR1CS, _ := os.Create("r1cs.html")
	fSparseR1CS, _ := os.Create("sparse_r1cs.html")

	r1, _ := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	err := r1.ToHTML(fR1CS)
	if err != nil {
		fmt.Println(err)
	}

	r2, _ := frontend.Compile(ecc.BN254, backend.PLONK, &circuit)
	err = r2.ToHTML(fSparseR1CS)
	if err != nil {
		fmt.Println(err)
	}
	return

	// building the circuit...
	r1cs, err_r1cs := frontend.Compile(ecc.BN254, backend.PLONK, &circuit)
	if err_r1cs != nil {
		fmt.Println("circuit compilation error")
	}

	// create the necessary data for KZG.
	// This is a toy example, normally the trusted setup to build ZKG
	// has been ran before.
	// The size of the data in KZG should be the closest power of 2 bounding //
	// above max(nbConstraints, nbVariables).
	_r1cs := r1cs.(*cs.SparseR1CS)
	srs, err := plonk.NewSRS(_r1cs)
	if err != nil {
		panic(err)
	}

	// Correct data: the proof passes
	{
		// Witnesses instantiation. Witness is known only by the prover,
		// while public witness is a public data known by the verifier.
		var witness, publicWitness Circuit
		witness.X.Assign(2)
		witness.E.Assign(3)
		witness.Y.Assign(8)

		publicWitness.X.Assign(2)
		publicWitness.Y.Assign(8)

		// public data consists the polynomials describing the constants involved
		// in the constraints, the polynomial describing the permutation ("grand
		// product argument"), and the FFT domains.
		pk, vk, err := plonk.Setup(r1cs, srs)
		//_, err := plonk.Setup(r1cs, kate, &publicWitness)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		proof, err := plonk.Prove(r1cs, pk, &witness, nil)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		err = plonk.Verify(proof, vk, &publicWitness)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
	}

	// Wrong data: the proof fails
	{
		// Witnesses instantiation. Witness is known only by the prover,
		// while public witness is a public data known by the verifier.
		var witness, publicWitness Circuit
		witness.X.Assign(3)
		witness.E.Assign(12)
		witness.Y.Assign(4096)

		publicWitness.X.Assign(2)
		publicWitness.Y.Assign(4096)

		// public data consists the polynomials describing the constants involved
		// in the constraints, the polynomial describing the permutation ("grand
		// product argument"), and the FFT domains.
		pk, vk, err := plonk.Setup(r1cs, srs)
		//_, err := plonk.Setup(r1cs, kate, &publicWitness)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		proof, err := plonk.Prove(r1cs, pk, &witness, nil)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		err = plonk.Verify(proof, vk, &publicWitness)
		if err == nil {
			fmt.Printf("Error: wrong proof is accepted")
			os.Exit(-1)
		}
	}

}
