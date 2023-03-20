package groth16_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

//--------------------//
//     benches		  //
//--------------------//

func BenchmarkSetup(b *testing.B) {
	for _, curve := range getCurves() {
		b.Run(curve.String(), func(b *testing.B) {
			r1cs, _ := referenceCircuit(curve)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _, _ = groth16.Setup(r1cs)
			}
		})
	}
}

func BenchmarkProver(b *testing.B) {
	for _, curve := range getCurves() {
		b.Run(curve.String(), func(b *testing.B) {
			r1cs, _solution := referenceCircuit(curve)
			fullWitness, err := frontend.NewWitness(_solution, curve.ScalarField())
			if err != nil {
				b.Fatal(err)
			}
			pk, err := groth16.DummySetup(r1cs)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = groth16.Prove(r1cs, pk, fullWitness)
			}
		})
	}
}

func BenchmarkVerifier(b *testing.B) {
	for _, curve := range getCurves() {
		b.Run(curve.String(), func(b *testing.B) {
			r1cs, _solution := referenceCircuit(curve)
			fullWitness, err := frontend.NewWitness(_solution, curve.ScalarField())
			if err != nil {
				b.Fatal(err)
			}
			publicWitness, err := fullWitness.Public()
			if err != nil {
				b.Fatal(err)
			}

			pk, vk, err := groth16.Setup(r1cs)
			if err != nil {
				b.Fatal(err)
			}
			proof, err := groth16.Prove(r1cs, pk, fullWitness)
			if err != nil {
				panic(err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = groth16.Verify(proof, vk, publicWitness)
			}
		})
	}
}

type refCircuit struct {
	nbConstraints int
	X             frontend.Variable
	Y             frontend.Variable `gnark:",public"`
}

func (circuit *refCircuit) Define(api frontend.API) error {
	for i := 0; i < circuit.nbConstraints; i++ {
		circuit.X = api.Mul(circuit.X, circuit.X)
	}
	api.AssertIsEqual(circuit.X, circuit.Y)
	return nil
}

func referenceCircuit(curve ecc.ID) (constraint.ConstraintSystem, frontend.Circuit) {
	const nbConstraints = 40000
	circuit := refCircuit{
		nbConstraints: nbConstraints,
	}
	r1cs, err := frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	var good refCircuit
	good.X = 2

	// compute expected Y
	expectedY := new(big.Int).SetUint64(2)
	exp := big.NewInt(1)
	exp.Lsh(exp, nbConstraints)
	expectedY.Exp(expectedY, exp, curve.ScalarField())

	good.Y = expectedY

	return r1cs, &good
}

func getCurves() []ecc.ID {
	if testing.Short() {
		return []ecc.ID{ecc.BN254}
	}
	return gnark.Curves()
}
