package kzg

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

type KZGVerificationCircuit struct {
	SRS [2]sw_bn254.G2Affine
	Commitment[sw_bn254.G1Affine]
	OpeningProof[emulated.Element[emparams.BN254Fr], sw_bn254.G1Affine]
}

func (c *KZGVerificationCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emparams.BN254Fp, emparams.BN254Fr](api, sw_emulated.GetBN254Params())
	if err != nil {
		return fmt.Errorf("new curve: %w", err)
	}
	pairing, err := sw_bn254.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	verifier := NewVerifier[emulated.Element[emparams.BN254Fr], sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](c.SRS, curve, pairing)
	if err := verifier.AssertProof(c.Commitment, c.OpeningProof); err != nil {
		return fmt.Errorf("assert proof: %w", err)
	}
	return nil
}

func TestKZGBN254(t *testing.T) {
	assert := test.NewAssert(t)
	const kzgSize = 128
	const polynomialSize = 100

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

	assignment := KZGVerificationCircuit{
		SRS: [2]sw_bn254.G2Affine{
			sw_bn254.NewG2Affine(srs.Vk.G2[0]),
			sw_bn254.NewG2Affine(srs.Vk.G2[1]),
		},
		Commitment: Commitment[sw_emulated.AffinePoint[emparams.BN254Fp]]{
			G1El: sw_bn254.NewG1Affine(com),
		},
		OpeningProof: OpeningProof[emulated.Element[emparams.BN254Fr], sw_emulated.AffinePoint[emparams.BN254Fp]]{
			QuotientPoly: sw_bn254.NewG1Affine(proof.H),
			ClaimedValue: emulated.ValueOf[emparams.BN254Fr](proof.ClaimedValue),
			Point:        emulated.ValueOf[emparams.BN254Fr](point),
		},
	}
	assert.CheckCircuit(&KZGVerificationCircuit{}, test.WithValidAssignment(&assignment))
}
