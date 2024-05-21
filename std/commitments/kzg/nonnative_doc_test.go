package kzg_test

import (
	"crypto/rand"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/commitments/kzg"
	"github.com/consensys/gnark/std/math/emulated"
)

type KZGVerificationCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GTEl algebra.GtElementT] struct {
	kzg.VerifyingKey[G1El, G2El]
	kzg.Commitment[G1El]
	kzg.OpeningProof[FR, G1El]
	Point emulated.Element[FR]
}

func (c *KZGVerificationCircuit[FR, G1El, G2El, GTEl]) Define(api frontend.API) error {
	verifier, err := kzg.NewVerifier[FR, G1El, G2El, GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	if err := verifier.CheckOpeningProof(c.Commitment, c.OpeningProof, c.Point, c.VerifyingKey); err != nil {
		return fmt.Errorf("assert proof: %w", err)
	}
	return nil
}

// Example of using KZG verifier using emulated pairing implementation.
func Example_emulated() {
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
	alpha, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	if err != nil {
		panic("sampling alpha failed: " + err.Error())
	}
	srs, err := kzg_bn254.NewSRS(kzgSize, alpha) // UNSAFE!
	if err != nil {
		panic("new SRS failed: " + err.Error())
	}

	// sample the random polynomial by sampling the coefficients.
	f := make([]fr_bn254.Element, polynomialSize)
	for i := range f {
		f[i].SetRandom()
	}

	// natively commit to the polynomial using SRS
	com, err := kzg_bn254.Commit(f, srs.Pk)
	if err != nil {
		panic("commitment failed: " + err.Error())
	}

	// sample random evaluation point
	var point fr_bn254.Element
	point.SetRandom()

	// construct a proof of correct opening. The evaluation value is proof.ClaimedValue
	proof, err := kzg_bn254.Open(f, point, srs.Pk)
	if err != nil {
		panic("test opening failed: " + err.Error())
	}

	// test opening proof natively
	if err = kzg_bn254.Verify(&com, &proof, point, srs.Vk); err != nil {
		panic("test verify failed: " + err.Error())
	}

	// create a witness element of the commitment
	wCmt, err := kzg.ValueOfCommitment[sw_bn254.G1Affine](com)
	if err != nil {
		panic("commitment witness failed: " + err.Error())
	}

	// create a witness element of the opening proof
	wProof, err := kzg.ValueOfOpeningProof[sw_bn254.ScalarField, sw_bn254.G1Affine](proof)
	if err != nil {
		panic("opening proof witness failed: " + err.Error())
	}

	// create a witness element of the SRS
	wVk, err := kzg.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine](srs.Vk)
	if err != nil {
		panic("verifying key witness failed: " + err.Error())
	}

	// create a witness element of the evaluation point
	wPt, err := kzg.ValueOfScalar[sw_bn254.ScalarField](point)
	if err != nil {
		panic("point witness failed: " + err.Error())
	}

	assignment := KZGVerificationCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		VerifyingKey: wVk,
		Commitment:   wCmt,
		OpeningProof: wProof,
		Point:        wPt,
	}
	circuit := KZGVerificationCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{}

	// as we are currently using the emulated implementation of BN254
	// in-circuit, then we can compile to any curve. For example purposes, here
	// we use BN254.
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic("compile failed: " + err.Error())
	}

	// create Groth16 setup. NB! UNSAFE
	pk, vk, err := groth16.Setup(ccs) // UNSAFE! Use MPC
	if err != nil {
		panic("setup failed: " + err.Error())
	}

	// create prover witness from the assignment
	secretWitness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
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
