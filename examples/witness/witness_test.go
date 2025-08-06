package witness

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
)

type Circuit struct {
	A frontend.Variable `gnark:",public"`
	B frontend.Variable
	P sw_emulated.AffinePoint[sw_bn254.BaseField] `gnark:",public"`
}

func (c *Circuit) Define(api frontend.API) error {
	api.AssertIsDifferent(c.A, c.B)

	curve, err := sw_bn254.NewPairing(api)
	if err != nil {
		return err
	}
	curve.AssertIsOnG1(&c.P)
	return nil
}

func Example() {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	if err != nil {
		panic(fmt.Sprintf("failed to compile the circuit: %v", err))
	}

	a, b := 3, 4
	_, _, P, _ := bn254.Generators()
	fmt.Printf("assignment: A = %d, B = %d, P = %s\n", a, b, P.String())
	assignment := &Circuit{A: a, B: b, P: sw_bn254.NewG1Affine(P)}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(fmt.Sprintf("failed to create witness: %v", err))
	}
	_, err = ccs.Solve(witness)
	if err != nil {
		panic(fmt.Sprintf("failed to solve the circuit: %v", err))
	}
	witnessVector := witness.Vector().(fr_bn254.Vector)
	for i, v := range witnessVector {
		fmt.Printf("witness[%d] = %s\n", i, v.String())
	}
	pubWitness, err := witness.Public()
	if err != nil {
		panic(fmt.Sprintf("failed to get public witness: %v", err))
	}
	pubWitnessVector := pubWitness.Vector().(fr_bn254.Vector)
	for i, v := range pubWitnessVector {
		fmt.Printf("public witness[%d] = %s\n", i, v.String())
	}
	// Output:
	// assignment: A = 3, B = 4, P = E([1,2])
	// witness[0] = 3
	// witness[1] = 1
	// witness[2] = 0
	// witness[3] = 0
	// witness[4] = 0
	// witness[5] = 2
	// witness[6] = 0
	// witness[7] = 0
	// witness[8] = 0
	// witness[9] = 4
	// public witness[0] = 3
	// public witness[1] = 1
	// public witness[2] = 0
	// public witness[3] = 0
	// public witness[4] = 0
	// public witness[5] = 2
	// public witness[6] = 0
	// public witness[7] = 0
	// public witness[8] = 0
}
