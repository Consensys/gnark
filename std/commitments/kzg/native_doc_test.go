package kzg_test

import (
	"crypto/rand"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	kzg_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/kzg"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/commitments/kzg"
)

// Example of using KZG verifier using 2-chains of curves. It is significantly
// more efficient than using field emulation, but requires a specific chain of
// inner and outer curves.
func Example_native() {
	// !!! UNSAFE SRS. FOR EXAMPLE PURPOSES ONLY. We create a trusted SRS for
	// KZG polynomial commitment scheme. In practice this must be prepared using
	// MPC or by reusing existing SRS. !!!

	const (
		// size of the SRS. Defines the maximum degree of the polynomial which can be committed to
		kzgSize = 128
		// degree of the random polynomial in the example
		polynomialSize = 100
	)

	// create new SRS for example purposes (NB! UNSAFE!)
	alpha, err := rand.Int(rand.Reader, ecc.BLS12_377.ScalarField())
	if err != nil {
		panic("sampling alpha failed: " + err.Error())
	}
	srs, err := kzg_bls12377.NewSRS(kzgSize, alpha) // UNSAFE!
	if err != nil {
		panic("new SRS failed: " + err.Error())
	}

	// sample the random polynomial by sampling the coefficients.
	f := make([]fr_bls12377.Element, polynomialSize)
	for i := range f {
		f[i].SetRandom()
	}

	// natively commit to the polynomial using SRS
	com, err := kzg_bls12377.Commit(f, srs.Pk)
	if err != nil {
		panic("commitment failed: " + err.Error())
	}

	// sample random evaluation point
	var point fr_bls12377.Element
	point.SetRandom()

	// construct a proof of correct opening. The evaluation value is proof.ClaimedValue
	proof, err := kzg_bls12377.Open(f, point, srs.Pk)
	if err != nil {
		panic("test opening failed: " + err.Error())
	}

	// test opening proof natively
	if err = kzg_bls12377.Verify(&com, &proof, point, srs.Vk); err != nil {
		panic("test verify failed: " + err.Error())
	}

	// create a witness element of the commitment
	wCmt, err := kzg.ValueOfCommitment[sw_bls12377.G1Affine](com)
	if err != nil {
		panic("commitment witness failed: " + err.Error())
	}

	// create a witness element of the opening proof
	wProof, err := kzg.ValueOfOpeningProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine](proof)
	if err != nil {
		panic("opening proof witness failed: " + err.Error())
	}

	// create a witness element of the SRS
	wVk, err := kzg.ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine](srs.Vk)
	if err != nil {
		panic("verifying key witness failed: " + err.Error())
	}

	// create a witness element of the evaluation point
	wPt, err := kzg.ValueOfScalar[sw_bls12377.ScalarField](point)
	if err != nil {
		panic("point witness failed: " + err.Error())
	}

	assignment := KZGVerificationCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		VerifyingKey: wVk,
		Commitment:   wCmt,
		OpeningProof: wProof,
		Point:        wPt,
	}
	circuit := KZGVerificationCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{}

	// because we are using 2-chains then the outer curve must correspond to the
	// inner curve. For inner BLS12-377 the outer curve is BW6-761.
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic("compile failed: " + err.Error())
	}

	// create Groth16 setup. NB! UNSAFE
	pk, vk, err := groth16.Setup(ccs) // UNSAFE! Use MPC
	if err != nil {
		panic("setup failed: " + err.Error())
	}

	// create prover witness from the assignment
	secretWitness, err := frontend.NewWitness(&assignment, ecc.BW6_761.ScalarField())
	if err != nil {
		panic("secret witness failed: " + err.Error())
	}

	// create public witness from the assignment
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic("public witness failed: " + err.Error())
	}

	// construct the groth16 proof of verifying KZG commitment opening in-circuit
	circuitProof, err := groth16.Prove(ccs, pk, secretWitness)
	if err != nil {
		panic("proving failed: " + err.Error())
	}

	// verify the Groth16 proof
	err = groth16.Verify(circuitProof, vk, publicWitness)
	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}
}
