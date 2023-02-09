package weierstrass_test

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/weierstrass"
	"github.com/consensys/gnark/std/math/emulated"
)

type ExampleCurveCircuit[Base, Scalar emulated.FieldParams] struct {
	Res weierstrass.AffinePoint[Base]
}

func (c *ExampleCurveCircuit[B, S]) Define(api frontend.API) error {
	curve, err := weierstrass.New[B, S](api, weierstrass.GetCurveParams[emulated.BN254Fp]())
	if err != nil {
		panic("initalize new curve")
	}
	G := curve.Generator()
	scalar4 := emulated.ValueOf[S](4)
	g4 := curve.ScalarMul(G, &scalar4) // 4*G
	scalar5 := emulated.ValueOf[S](5)
	g5 := curve.ScalarMul(G, &scalar5) // 5*G
	g9 := curve.Add(g4, g5)            // 9*G
	curve.AssertIsEqual(g9, &c.Res)
	return nil
}

func ExampleCurve() {
	s := big.NewInt(9)
	_, g := secp256k1.Generators()
	var Q secp256k1.G1Affine
	Q.ScalarMultiplication(&g, s)
	fmt.Printf("result (%d, %d)", Q.X, Q.Y)

	circuit := ExampleCurveCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := ExampleCurveCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		Res: weierstrass.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](g.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](g.Y),
		},
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("compiled")
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("setup done")
	}
	secretWitness, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	} else {
		fmt.Println("secret witness")
	}
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic(err)
	} else {
		fmt.Println("public witness")
	}
	proof, err := groth16.Prove(ccs, pk, secretWitness)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("proof")
	}
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("verify")
	}
}
