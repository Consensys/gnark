package kzg_refactor

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

const (
	kzgSize        = 128
	polynomialSize = 100
)

//--------------------------------------------------------
// Single opening single point

type KZGVerificationCircuit[S emulated.FieldParams, G1El, G2El, GTEl any] struct {
	Vk     VerifyingKey[G1El, G2El]
	Digest Commitment[G1El]
	Proof  OpeningProof[S, G1El]
	Point  emulated.Element[S]
}

func (c *KZGVerificationCircuit[S, G1El, G2El, GTEl]) Define(api frontend.API) error {
	verifier, err := NewVerifier[S, G1El, G2El, GTEl](api)
	if err != nil {
		return fmt.Errorf("get pairing: %w", err)
	}
	if err := verifier.CheckOpeningProof(c.Digest, c.Proof, c.Point, c.Vk); err != nil {
		return fmt.Errorf("assert proof: %w", err)
	}
	return nil
}

func TestKZGVerificationEmulated(t *testing.T) {
	assert := test.NewAssert(t)

	alpha, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bn254.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	f := make([]fr_bn254.Element, polynomialSize)
	for i := range f {
		f[i].SetRandom()
	}

	com, err := kzg_bn254.Commit(f, srs.Pk)
	assert.NoError(err)

	var point fr_bn254.Element
	point.SetRandom()
	proof, err := kzg_bn254.Open(f, point, srs.Pk)
	assert.NoError(err)

	if err = kzg_bn254.Verify(&com, &proof, point, srs.Vk); err != nil {
		t.Fatal("verify proof", err)
	}

	wCmt, err := ValueOfCommitment[sw_bn254.G1Affine](com)
	assert.NoError(err)
	wProof, err := ValueOfOpeningProof[emulated.BN254Fr, sw_bn254.G1Affine](proof)
	assert.NoError(err)
	wVk, err := ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine](srs.Vk)
	assert.NoError(err)

	// wPoint, err := ValueOfScalar[emulated.BN254Fr](point)
	wPoint, err := ValueOfScalar[emulated.BN254Fr](point)
	assert.NoError(err)

	assignment := KZGVerificationCircuit[emulated.BN254Fr, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Vk:     wVk,
		Digest: wCmt,
		Proof:  wProof,
		Point:  wPoint,
	}
	assert.CheckCircuit(&KZGVerificationCircuit[emulated.BN254Fr, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{}, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BLS12_381), test.WithBackends(backend.PLONK))
}

//--------------------------------------------------------
// Fold proof

// type TestFoldProof[S emulated.FieldParams, G1El, G2El, GTEl any] struct {
// 	Vk                VerifyingKey[G1El, G2El]
// 	Point             emulated.Element[S]
// 	Digests           [10]Commitment[G1El]
// 	BatchOpeningProof OpeningProof[S, G1El]
// }

// func (c *TestFoldProof[S, G1El, G2El, GTEl]) Define(api frontend.API) error {

// 	verifier, err := NewVerifier[S, G1El, G2El, GTEl](api)
// 	if err != nil {
// 		return fmt.Errorf("get pairing: %w", err)
// 	}

// 	return nil
// }
