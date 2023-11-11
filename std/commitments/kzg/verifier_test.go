package kzg

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	kzg_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/kzg"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/test"
)

const (
	kzgSize        = 128
	polynomialSize = 100
)

type KZGVerificationCircuit[S algebra.ScalarT, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GTEl algebra.GtElementT, L algebra.LinesT] struct {
	VerifyingKey[L]
	Commitment[G1El]
	OpeningProof[S, G1El]
}

func (c *KZGVerificationCircuit[S, G1El, G2El, GTEl, L]) Define(api frontend.API) error {
	curve, err := algebra.GetCurve[S, G1El](api)
	if err != nil {
		return fmt.Errorf("get curve: %w", err)
	}
	pairing, err := algebra.GetPairing[G1El, G2El, GTEl, L](api)
	if err != nil {
		return fmt.Errorf("get pairing: %w", err)
	}
	verifier := NewVerifier(c.VerifyingKey, curve, pairing)
	if err := verifier.AssertProof(c.Commitment, c.OpeningProof); err != nil {
		return fmt.Errorf("assert proof: %w", err)
	}
	return nil
}

/*
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
	wProof, err := ValueOfOpeningProof[sw_bn254.Scalar, sw_bn254.G1Affine](point, proof)
	assert.NoError(err)
	wVk, err := ValueOfVerifyingKey[sw_bn254.G2Affine](srs.Vk)
	assert.NoError(err)

	assignment := KZGVerificationCircuit[sw_bn254.Scalar, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		VerifyingKey: wVk,
		Commitment:   wCmt,
		OpeningProof: wProof,
	}
	assert.CheckCircuit(&KZGVerificationCircuit[sw_bn254.Scalar, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{}, test.WithValidAssignment(&assignment))
}

func TestKZGVerificationEmulated2(t *testing.T) {
	assert := test.NewAssert(t)

	alpha, err := rand.Int(rand.Reader, ecc.BLS12_381.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bls12381.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	f := make([]fr_bls12381.Element, polynomialSize)
	for i := range f {
		f[i].SetRandom()
	}

	com, err := kzg_bls12381.Commit(f, srs.Pk)
	assert.NoError(err)

	var point fr_bls12381.Element
	point.SetRandom()
	proof, err := kzg_bls12381.Open(f, point, srs.Pk)
	assert.NoError(err)

	if err = kzg_bls12381.Verify(&com, &proof, point, srs.Vk); err != nil {
		t.Fatal("verify proof", err)
	}

	wCmt, err := ValueOfCommitment[sw_bls12381.G1Affine](com)
	assert.NoError(err)
	wProof, err := ValueOfOpeningProof[sw_bls12381.Scalar, sw_bls12381.G1Affine](point, proof)
	assert.NoError(err)
	wVk, err := ValueOfVerifyingKey[sw_bls12381.G2Affine](srs.Vk)
	assert.NoError(err)

	assignment := KZGVerificationCircuit[sw_bls12381.Scalar, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]{
		VerifyingKey: wVk,
		Commitment:   wCmt,
		OpeningProof: wProof,
	}
	assert.CheckCircuit(&KZGVerificationCircuit[sw_bls12381.Scalar, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]{}, test.WithValidAssignment(&assignment))
}
*/

func TestKZGVerificationEmulated3(t *testing.T) {
	assert := test.NewAssert(t)

	alpha, err := rand.Int(rand.Reader, ecc.BW6_761.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bw6761.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	f := make([]fr_bw6761.Element, polynomialSize)
	for i := range f {
		f[i].SetRandom()
	}

	com, err := kzg_bw6761.Commit(f, srs.Pk)
	assert.NoError(err)

	var point fr_bw6761.Element
	point.SetRandom()
	proof, err := kzg_bw6761.Open(f, point, srs.Pk)
	assert.NoError(err)

	if err = kzg_bw6761.Verify(&com, &proof, point, srs.Vk); err != nil {
		t.Fatal("verify proof", err)
	}

	wCmt, err := ValueOfCommitment[sw_bw6761.G1Affine](com)
	assert.NoError(err)
	wProof, err := ValueOfOpeningProof[sw_bw6761.Scalar, sw_bw6761.G1Affine](point, proof)
	assert.NoError(err)
	wVk, err := ValueOfVerifyingKey[sw_bw6761.LineEvaluation](srs.Vk)
	assert.NoError(err)

	assignment := KZGVerificationCircuit[sw_bw6761.Scalar, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl, sw_bw6761.LineEvaluation]{
		VerifyingKey: wVk,
		Commitment:   wCmt,
		OpeningProof: wProof,
	}
	assert.CheckCircuit(&KZGVerificationCircuit[sw_bw6761.Scalar, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl, sw_bw6761.LineEvaluation]{}, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BN254))
}

/*
func TestKZGVerificationTwoChain(t *testing.T) {
	assert := test.NewAssert(t)

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

	wCmt, err := ValueOfCommitment[sw_bls12377.G1Affine](com)
	assert.NoError(err)
	wProof, err := ValueOfOpeningProof[sw_bls12377.Scalar, sw_bls12377.G1Affine](point, proof)
	assert.NoError(err)
	wVk, err := ValueOfVerifyingKey[sw_bls12377.G2Affine](srs.Vk)
	assert.NoError(err)

	assignment := KZGVerificationCircuit[sw_bls12377.Scalar, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		VerifyingKey: wVk,
		Commitment:   wCmt,
		OpeningProof: wProof,
	}

	assert.CheckCircuit(&KZGVerificationCircuit[sw_bls12377.Scalar, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{}, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BW6_761))
}

func TestKZGVerificationTwoChain2(t *testing.T) {
	assert := test.NewAssert(t)

	alpha, err := rand.Int(rand.Reader, ecc.BLS24_315.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bls24315.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	f := make([]fr_bls24315.Element, polynomialSize)
	for i := range f {
		f[i].SetRandom()
	}

	com, err := kzg_bls24315.Commit(f, srs.Pk)
	assert.NoError(err)

	var point fr_bls24315.Element
	point.SetRandom()
	proof, err := kzg_bls24315.Open(f, point, srs.Pk)
	assert.NoError(err)

	if err = kzg_bls24315.Verify(&com, &proof, point, srs.Vk); err != nil {
		t.Fatal("verify proof", err)
	}

	wCmt, err := ValueOfCommitment[sw_bls24315.G1Affine](com)
	assert.NoError(err)
	wProof, err := ValueOfOpeningProof[sw_bls24315.Scalar, sw_bls24315.G1Affine](point, proof)
	assert.NoError(err)
	wVk, err := ValueOfVerifyingKey[sw_bls24315.G2Affine](srs.Vk)
	assert.NoError(err)

	assignment := KZGVerificationCircuit[sw_bls24315.Scalar, sw_bls24315.G1Affine, sw_bls24315.G2Affine, sw_bls24315.GT]{
		VerifyingKey: wVk,
		Commitment:   wCmt,
		OpeningProof: wProof,
	}

	assert.CheckCircuit(&KZGVerificationCircuit[sw_bls24315.Scalar, sw_bls24315.G1Affine, sw_bls24315.G2Affine, sw_bls24315.GT]{}, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BW6_633))
}
*/

func TestValueOfCommitment(t *testing.T) {
	assert := test.NewAssert(t)
	/*
		assert.Run(func(assert *test.Assert) {
			_, _, G1, _ := bn254.Generators()
			assignment, err := ValueOfCommitment[sw_bn254.G1Affine](G1)
			assert.NoError(err)
			_ = assignment
		}, "bn254")
		assert.Run(func(assert *test.Assert) {
			_, _, G1, _ := bls12377.Generators()
			assignment, err := ValueOfCommitment[sw_bls12377.G1Affine](G1)
			assert.NoError(err)
			_ = assignment
		}, "bls12377")
		assert.Run(func(assert *test.Assert) {
			_, _, G1, _ := bls12381.Generators()
			assignment, err := ValueOfCommitment[sw_bls12381.G1Affine](G1)
			assert.NoError(err)
			_ = assignment
		}, "bls12381")
	*/
	assert.Run(func(assert *test.Assert) {
		_, _, G1, _ := bw6761.Generators()
		assignment, err := ValueOfCommitment[sw_bw6761.G1Affine](G1)
		assert.NoError(err)
		_ = assignment
	}, "bw6761")
	/*
		assert.Run(func(assert *test.Assert) {
			_, _, G1, _ := bls24315.Generators()
			assignment, err := ValueOfCommitment[sw_bls24315.G1Affine](G1)
			assert.NoError(err)
			_ = assignment
		}, "bls24315")
	*/
}

func TestValueOfOpeningProof(t *testing.T) {
	assert := test.NewAssert(t)
	/*
		assert.Run(func(assert *test.Assert) {
			_, _, G1, _ := bn254.Generators()
			var value, point fr_bn254.Element
			value.SetRandom()
			point.SetRandom()
			proof := kzg_bn254.OpeningProof{
				H:            G1,
				ClaimedValue: value,
			}
			assignment, err := ValueOfOpeningProof[sw_bn254.Scalar, sw_bn254.G1Affine](point, proof)
			assert.NoError(err)
			_ = assignment
		}, "bn254")
		assert.Run(func(assert *test.Assert) {
			_, _, G1, _ := bls12377.Generators()
			var value, point fr_bls12377.Element
			value.SetRandom()
			point.SetRandom()
			proof := kzg_bls12377.OpeningProof{
				H:            G1,
				ClaimedValue: value,
			}
			assignment, err := ValueOfOpeningProof[sw_bls12377.Scalar, sw_bls12377.G1Affine](point, proof)
			assert.NoError(err)
			_ = assignment
		}, "bls12377")
		assert.Run(func(assert *test.Assert) {
			_, _, G1, _ := bls12381.Generators()
			var value, point fr_bls12381.Element
			value.SetRandom()
			point.SetRandom()
			proof := kzg_bls12381.OpeningProof{
				H:            G1,
				ClaimedValue: value,
			}
			assignment, err := ValueOfOpeningProof[sw_bls12381.Scalar, sw_bls12381.G1Affine](point, proof)
			assert.NoError(err)
			_ = assignment
		}, "bls12381")
	*/
	assert.Run(func(assert *test.Assert) {
		_, _, G1, _ := bw6761.Generators()
		var value, point fr_bw6761.Element
		value.SetRandom()
		point.SetRandom()
		proof := kzg_bw6761.OpeningProof{
			H:            G1,
			ClaimedValue: value,
		}
		assignment, err := ValueOfOpeningProof[sw_bw6761.Scalar, sw_bw6761.G1Affine](point, proof)
		assert.NoError(err)
		_ = assignment
	}, "bw6761")
	/*
		assert.Run(func(assert *test.Assert) {
			_, _, G1, _ := bls24315.Generators()
			var value, point fr_bls24315.Element
			value.SetRandom()
			point.SetRandom()
			proof := kzg_bls24315.OpeningProof{
				H:            G1,
				ClaimedValue: value,
			}
			assignment, err := ValueOfOpeningProof[sw_bls24315.Scalar, sw_bls24315.G1Affine](point, proof)
			assert.NoError(err)
			_ = assignment
		}, "bls24315")
	*/
}

func TestValueOfSRS(t *testing.T) {
	assert := test.NewAssert(t)
	/*
		assert.Run(func(assert *test.Assert) {
			_, _, _, G2 := bn254.Generators()
			vk := kzg_bn254.VerifyingKey{
				G2: [2]bn254.G2Affine{G2, G2},
			}
			assignment, err := ValueOfVerifyingKey[sw_bn254.G2Affine](vk)
			assert.NoError(err)
			_ = assignment
		}, "bn254")
		assert.Run(func(assert *test.Assert) {
			_, _, _, G2 := bls12377.Generators()
			vk := kzg_bls12377.VerifyingKey{
				G2: [2]bls12377.G2Affine{G2, G2},
			}
			assignment, err := ValueOfVerifyingKey[sw_bls12377.G2Affine](vk)
			assert.NoError(err)
			_ = assignment
		}, "bls12377")
		assert.Run(func(assert *test.Assert) {
			_, _, _, G2 := bls12381.Generators()
			vk := kzg_bls12381.VerifyingKey{
				G2: [2]bls12381.G2Affine{G2, G2},
			}
			assignment, err := ValueOfVerifyingKey[sw_bls12381.G2Affine](vk)
			assert.NoError(err)
			_ = assignment
		}, "bls12381")
	*/
	assert.Run(func(assert *test.Assert) {
		_, _, _, G2 := bw6761.Generators()
		lines := bw6761.PrecomputeLines(G2)
		vk := kzg_bw6761.VerifyingKey{
			Lines: [2][2][189]bw6761.LineEvaluationAff{lines, lines},
		}
		assignment, err := ValueOfVerifyingKey[sw_bw6761.LineEvaluation](vk)
		assert.NoError(err)
		_ = assignment
	}, "bw6761")
	/*
		assert.Run(func(assert *test.Assert) {
			_, _, _, G2 := bls24315.Generators()
			vk := kzg_bls24315.VerifyingKey{
				G2: [2]bls24315.G2Affine{G2, G2},
			}
			assignment, err := ValueOfVerifyingKey[sw_bls24315.G2Affine](vk)
			assert.NoError(err)
			_ = assignment
		}, "bls24315")
	*/
}
