package kzg

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	kzg_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/kzg"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

type KZGVerificationCircuitBN254 struct {
	SRS [2]sw_bn254.G2Affine
	Commitment[sw_bn254.G1Affine]
	OpeningProof[emulated.Element[emparams.BN254Fr], sw_bn254.G1Affine]
}

func (c *KZGVerificationCircuitBN254) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emparams.BN254Fp, emparams.BN254Fr](api, sw_emulated.GetBN254Params())
	if err != nil {
		return fmt.Errorf("new curve: %w", err)
	}
	pairing, err := sw_bn254.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	verifier := NewVerifier(c.SRS, curve, pairing)
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

	assignment := KZGVerificationCircuitBN254{
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
	assert.CheckCircuit(&KZGVerificationCircuitBN254{}, test.WithValidAssignment(&assignment))
}

type KZGVerificationCircuitBLS12377 struct {
	SRS [2]sw_bls12377.G2Affine
	Commitment[sw_bls12377.G1Affine]
	OpeningProof[frontend.Variable, sw_bls12377.G1Affine]
}

func (c *KZGVerificationCircuitBLS12377) Define(api frontend.API) error {
	curve := sw_bls12377.NewCurve(api)
	pairing := sw_bls12377.NewPairing(api)
	verifier := NewVerifier(c.SRS, curve, pairing)
	if err := verifier.AssertProof(c.Commitment, c.OpeningProof); err != nil {
		return fmt.Errorf("assert proof: %w", err)
	}
	return nil
}

func TestKZGBLS12377(t *testing.T) {
	assert := test.NewAssert(t)
	const kzgSize = 128
	const polynomialSize = 100

	alpha, err := rand.Int(rand.Reader, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bls12377.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	f := make([]fr_bls12377.Element, polynomialSize)
	for i := range f {
		f[i].SetRandom()
	}

	com, err := kzg_bls12377.Commit(f, srs.Pk)
	assert.NoError(err)

	var point fr_bls12377.Element
	point.SetRandom()
	proof, err := kzg_bls12377.Open(f, point, srs.Pk)
	assert.NoError(err)

	if err = kzg_bls12377.Verify(&com, &proof, point, srs.Vk); err != nil {
		t.Fatal("verify proof", err)
	}

	assignment := KZGVerificationCircuitBLS12377{
		SRS: [2]sw_bls12377.G2Affine{
			sw_bls12377.NewG2Affine(srs.Vk.G2[0]),
			sw_bls12377.NewG2Affine(srs.Vk.G2[1]),
		},
		Commitment: Commitment[sw_bls12377.G1Affine]{
			G1El: sw_bls12377.NewG1Affine(com),
		},
		OpeningProof: OpeningProof[frontend.Variable, sw_bls12377.G1Affine]{
			QuotientPoly: sw_bls12377.NewG1Affine(proof.H),
			// the evaluation point and value are in Fr of BLS12377. However it
			// is strictly smaller than Fr of BW6. In order to be assignable, we
			// go to integer form first by taking a `String()`.
			ClaimedValue: proof.ClaimedValue.String(),
			Point:        point.String(),
		},
	}
	assert.CheckCircuit(&KZGVerificationCircuitBLS12377{}, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BW6_761))
}
