package kzg

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion"
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
// Slice proof

// type SliceTest[S emulated.FieldParams, G1El any] struct {
// 	Proof BatchOpeningProof[S, G1El]
// }

// func (circuit *SliceTest[S, G1El]) Define(api frontend.API) error {

// 	fmt.Println(len(circuit.Proof.ClaimedValues))
// 	return nil
// }

// func TestSlices(t *testing.T) {

// 	assert := test.NewAssert(t)

// 	// prepare test data
// 	alpha, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
// 	assert.NoError(err)
// 	srs, err := kzg_bn254.NewSRS(kzgSize, alpha)
// 	assert.NoError(err)

// 	var polynomials [10][]fr_bn254.Element
// 	var coms [10]kzg_bn254.Digest
// 	for i := 0; i < 10; i++ {
// 		polynomials[i] = make([]fr_bn254.Element, polynomialSize)
// 		for j := 0; j < polynomialSize; j++ {
// 			polynomials[i][j].SetRandom()
// 		}
// 		coms[i], err = kzg_bn254.Commit(polynomials[i], srs.Pk)
// 		assert.NoError(err)
// 	}

// 	var point fr_bn254.Element
// 	point.SetRandom()
// 	var target big.Int
// 	target.SetUint64(1)
// 	nbBits := ecc.BLS12_381.ScalarField().BitLen()
// 	nn := ((nbBits+7)/8)*8 - 8
// 	target.Lsh(&target, uint(nn))
// 	h, err := recursion.NewShort(ecc.BLS12_381.ScalarField(), &target)
// 	assert.NoError(err)

// 	batchOpeningProof, err := kzg_bn254.BatchOpenSinglePoint(polynomials[:], coms[:], point, h, srs.Pk)
// 	assert.NoError(err)

// 	_, _, err = kzg_bn254.FoldProof(coms[:], &batchOpeningProof, point, h)
// 	assert.NoError(err)

// 	// circuit
// 	var circuit SliceTest[emulated.BN254Fr, sw_bn254.G1Affine]
// 	circuit.Proof.ClaimedValues = make([]emulated.Element[emulated.BN254Fr], 10)

// 	var assignment SliceTest[emulated.BN254Fr, sw_bn254.G1Affine]
// 	// assignment.Proof.ClaimedValues = make([]emulated.Element[emulated.BN254Fr], 10)
// 	assignment.Proof, err = ValueOfBatchOpeningProof[emulated.BN254Fr, sw_bn254.G1Affine](batchOpeningProof)
// 	assert.NoError(err)

// 	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BLS12_381), test.WithBackends(backend.PLONK))

// }

//--------------------------------------------------------
// Fold proof

type FoldProofTest[S emulated.FieldParams, G1El, G2El, GTEl any] struct {
	Point                emulated.Element[S]
	Digests              [10]Commitment[G1El]
	BatchOpeningProof    BatchOpeningProof[S, G1El]
	ExpectedFoldedProof  OpeningProof[S, G1El]
	ExpectedFoldedDigest Commitment[G1El]
}

func (c *FoldProofTest[S, G1El, G2El, GTEl]) Define(api frontend.API) error {

	verifier, err := NewVerifier[S, G1El, G2El, GTEl](api)
	if err != nil {
		return fmt.Errorf("get pairing: %w", err)
	}

	// pick a number on byte shorter than the modulus size
	var target big.Int
	target.SetUint64(1)
	nbBits := api.Compiler().Field().BitLen()
	nn := ((nbBits+7)/8)*8 - 8
	target.Lsh(&target, uint(nn))

	// create the wrapped hash function
	whSnark, err := recursion.NewHash(api, &target, true)
	if err != nil {
		return err
	}

	// op, com, err := verifier.FoldProof(c.Digests[:], c.BatchOpeningProof, c.Point, whSnark)
	foldedProof, foldedDigests, err := verifier.FoldProof(c.Digests[:], c.BatchOpeningProof, c.Point, whSnark)
	if err != nil {
		return err
	}

	verifier.ec.AssertIsEqual(&foldedDigests.G1El, &c.ExpectedFoldedDigest.G1El)
	verifier.ec.AssertIsEqual(&foldedProof.Quotient, &c.ExpectedFoldedProof.Quotient)
	verifier.scalarApi.AssertIsEqual(&foldedProof.ClaimedValue, &c.ExpectedFoldedProof.ClaimedValue)

	return nil
}

func TestFoldProof(t *testing.T) {

	assert := test.NewAssert(t)

	// prepare test data
	alpha, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bn254.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	var polynomials [10][]fr_bn254.Element
	var coms [10]kzg_bn254.Digest
	for i := 0; i < 10; i++ {
		polynomials[i] = make([]fr_bn254.Element, polynomialSize)
		for j := 0; j < polynomialSize; j++ {
			polynomials[i][j].SetRandom()
		}
		coms[i], err = kzg_bn254.Commit(polynomials[i], srs.Pk)
		assert.NoError(err)
	}

	var point fr_bn254.Element
	point.SetRandom()
	var target big.Int
	target.SetUint64(1)
	nbBits := ecc.BLS12_381.ScalarField().BitLen()
	nn := ((nbBits+7)/8)*8 - 8
	target.Lsh(&target, uint(nn))
	h, err := recursion.NewShort(ecc.BLS12_381.ScalarField(), &target)
	assert.NoError(err)

	batchOpeningProof, err := kzg_bn254.BatchOpenSinglePoint(polynomials[:], coms[:], point, h, srs.Pk)
	assert.NoError(err)

	foldedProofs, foldedDigest, err := kzg_bn254.FoldProof(coms[:], &batchOpeningProof, point, h)
	assert.NoError(err)

	// prepare witness
	wPoint, err := ValueOfScalar[emulated.BN254Fr](point)
	assert.NoError(err)
	var wDigests [10]Commitment[sw_bn254.G1Affine]
	for i := 0; i < 10; i++ {
		wDigests[i], err = ValueOfCommitment[sw_bn254.G1Affine](coms[i])
		assert.NoError(err)
	}
	wBatchOpeningProof, err := ValueOfBatchOpeningProof[emulated.BN254Fr, sw_bn254.G1Affine](batchOpeningProof)
	assert.NoError(err)
	wExpectedFoldedProof, err := ValueOfOpeningProof[emulated.BN254Fr, sw_bn254.G1Affine](foldedProofs)
	assert.NoError(err)
	wExpectedFoldedDigest, err := ValueOfCommitment[sw_bn254.G1Affine](foldedDigest)
	assert.NoError(err)

	assignment := FoldProofTest[emulated.BN254Fr, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Point:                wPoint,
		Digests:              wDigests,
		BatchOpeningProof:    wBatchOpeningProof,
		ExpectedFoldedProof:  wExpectedFoldedProof,
		ExpectedFoldedDigest: wExpectedFoldedDigest,
	}

	var circuit FoldProofTest[emulated.BN254Fr, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	circuit.BatchOpeningProof.ClaimedValues = make([]emulated.Element[emulated.BN254Fr], 10)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BLS12_381), test.WithBackends(backend.PLONK))

}

//--------------------------------------------------------
// Batch verify single point

type BatchVerifySinglePointTest[S emulated.FieldParams, G1El, G2El, GTEl any] struct {
	Vk                VerifyingKey[G1El, G2El]
	Point             emulated.Element[S]
	Digests           [10]Commitment[G1El]
	BatchOpeningProof BatchOpeningProof[S, G1El]
}

func (c *BatchVerifySinglePointTest[S, G1El, G2El, GTEl]) Define(api frontend.API) error {

	verifier, err := NewVerifier[S, G1El, G2El, GTEl](api)
	if err != nil {
		return fmt.Errorf("get pairing: %w", err)
	}

	// pick a number on byte shorter than the modulus size
	var target big.Int
	target.SetUint64(1)
	nbBits := api.Compiler().Field().BitLen()
	nn := ((nbBits+7)/8)*8 - 8
	target.Lsh(&target, uint(nn))

	// create the wrapped hash function
	whSnark, err := recursion.NewHash(api, &target, true)
	if err != nil {
		return err
	}

	// op, com, err := verifier.FoldProof(c.Digests[:], c.BatchOpeningProof, c.Point, whSnark)
	verifier.BatchVerifySinglePoint(c.Digests[:], c.BatchOpeningProof, c.Point, whSnark, c.Vk)

	return nil
}

func TestBatchVerifySinglePoint(t *testing.T) {

	assert := test.NewAssert(t)

	// prepare test data
	alpha, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bn254.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	var polynomials [10][]fr_bn254.Element
	var coms [10]kzg_bn254.Digest
	for i := 0; i < 10; i++ {
		polynomials[i] = make([]fr_bn254.Element, polynomialSize)
		for j := 0; j < polynomialSize; j++ {
			polynomials[i][j].SetRandom()
		}
		coms[i], err = kzg_bn254.Commit(polynomials[i], srs.Pk)
		assert.NoError(err)
	}

	// random point at which the polynomials are evaluated
	var point fr_bn254.Element
	point.SetRandom()

	// build short hash, we pick a number one byte less than the snark field...
	var target big.Int
	target.SetUint64(1)
	nbBits := ecc.BLS12_381.ScalarField().BitLen()
	nn := ((nbBits+7)/8)*8 - 8
	target.Lsh(&target, uint(nn))
	h, err := recursion.NewShort(ecc.BLS12_381.ScalarField(), &target)
	assert.NoError(err)

	batchOpeningProof, err := kzg_bn254.BatchOpenSinglePoint(polynomials[:], coms[:], point, h, srs.Pk)
	assert.NoError(err)

	err = kzg_bn254.BatchVerifySinglePoint(coms[:], &batchOpeningProof, point, h, srs.Vk)
	assert.NoError(err)

	// prepare witness
	wVk, err := ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine](srs.Vk)
	assert.NoError(err)
	wPoint, err := ValueOfScalar[emulated.BN254Fr](point)
	assert.NoError(err)
	var wDigests [10]Commitment[sw_bn254.G1Affine]
	for i := 0; i < 10; i++ {
		wDigests[i], err = ValueOfCommitment[sw_bn254.G1Affine](coms[i])
		assert.NoError(err)
	}
	wBatchOpeningProof, err := ValueOfBatchOpeningProof[emulated.BN254Fr, sw_bn254.G1Affine](batchOpeningProof)
	assert.NoError(err)

	assignment := BatchVerifySinglePointTest[emulated.BN254Fr, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Vk:                wVk,
		Point:             wPoint,
		Digests:           wDigests,
		BatchOpeningProof: wBatchOpeningProof,
	}

	var circuit BatchVerifySinglePointTest[emulated.BN254Fr, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	circuit.BatchOpeningProof.ClaimedValues = make([]emulated.Element[emulated.BN254Fr], 10)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BLS12_381), test.WithBackends(backend.PLONK))

}

//--------------------------------------------------------
// Batch verify multi point

// type BatchVerifyMultiPointsTest[S emulated.FieldParams, G1El, G2El, GTEl any] struct {
// 	Vk      VerifyingKey[G1El, G2El]
// 	Digests [5]Commitment[G1El]
// 	Proofs  [5]OpeningProof[S, G1El]
// 	Points  [5]emulated.Element[S]
// }

type BatchVerifyMultiPointsTest[S emulated.FieldParams, G1El, G2El, GTEl any] struct {
	Vk      VerifyingKey[G1El, G2El]
	Digests [2]Commitment[G1El]
	Proofs  [2]OpeningProof[S, G1El]
	Points  [2]emulated.Element[S]
}

func (circuit *BatchVerifyMultiPointsTest[S, G1El, G2El, GTEl]) Define(api frontend.API) error {

	verifier, err := NewVerifier[S, G1El, G2El, GTEl](api)
	if err != nil {
		return fmt.Errorf("get pairing: %w", err)
	}

	verifier.BatchVerifyMultiPoints(circuit.Digests[:], circuit.Proofs[:], circuit.Points[:], circuit.Vk)

	return nil
}

func TestBatchVerifyMultiPoints(t *testing.T) {

	assert := test.NewAssert(t)

	// prepare test data
	alpha, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	assert.NoError(err)
	srs, err := kzg_bn254.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	var polynomials [2][]fr_bn254.Element
	var coms [2]kzg_bn254.Digest
	for i := 0; i < 2; i++ {
		polynomials[i] = make([]fr_bn254.Element, polynomialSize)
		for j := 0; j < polynomialSize; j++ {
			polynomials[i][j].SetRandom()
		}
		coms[i], err = kzg_bn254.Commit(polynomials[i], srs.Pk)
		assert.NoError(err)
	}

	// random points at which the polynomials are evaluated
	var points [2]fr_bn254.Element
	for i := 0; i < 2; i++ {
		points[i].SetRandom()
	}

	// build opening proofs
	var openingProofs [2]kzg_bn254.OpeningProof
	for i := 0; i < 2; i++ {
		openingProofs[i], err = kzg_bn254.Open(polynomials[i], points[i], srs.Pk)
		assert.NoError(err)
	}

	// check that the proofs are correct
	err = kzg_bn254.BatchVerifyMultiPoints(coms[:], openingProofs[:], points[:], srs.Vk)
	assert.NoError(err)

	// prepare witness
	wVk, err := ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine](srs.Vk)
	assert.NoError(err)
	var wDigests [2]Commitment[sw_bn254.G1Affine]
	var wPoints [2]emulated.Element[emulated.BN254Fr]
	var wOpeningProofs [2]OpeningProof[emulated.BN254Fr, sw_bn254.G1Affine]
	for i := 0; i < 2; i++ {
		wPoints[i], err = ValueOfScalar[emulated.BN254Fr](points[i])
		assert.NoError(err)
		wDigests[i], err = ValueOfCommitment[sw_bn254.G1Affine](coms[i])
		assert.NoError(err)
		wOpeningProofs[i], err = ValueOfOpeningProof[emulated.BN254Fr, sw_bn254.G1Affine](openingProofs[i])
		assert.NoError(err)
	}

	assignment := BatchVerifyMultiPointsTest[emulated.BN254Fr, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Vk:      wVk,
		Points:  wPoints,
		Digests: wDigests,
		Proofs:  wOpeningProofs,
	}

	var circuit BatchVerifyMultiPointsTest[emulated.BN254Fr, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BLS12_381), test.WithBackends(backend.PLONK))

}

//--------------------------------------------------------
// derive gamma

// type DeriveGammaTest[S emulated.FieldParams, G1El, G2El, GTEl any] struct {
// 	Point         emulated.Element[S]
// 	Digests       [10]Commitment[G1El]
// 	ClaimedValues [10]emulated.Element[S]
// 	Gamma         emulated.Element[S]
// }

// func (circuit *DeriveGammaTest[S, G1El, G2El, GTEl]) Define(api frontend.API) error {

// 	verifier, err := NewVerifier[S, G1El, G2El, GTEl](api)
// 	if err != nil {
// 		return fmt.Errorf("get pairing: %w", err)
// 	}

// 	// pick a number on byte shorter than the modulus size
// 	var target big.Int
// 	target.SetUint64(1)
// 	nbBits := api.Compiler().Field().BitLen()
// 	nn := ((nbBits+7)/8)*8 - 8
// 	target.Lsh(&target, uint(nn))

// 	// create the wrapped hash function
// 	whSnark, err := recursion.NewHash(api, &target, true)
// 	if err != nil {
// 		return err
// 	}

// 	res, err := verifier.deriveGamma(circuit.Point, circuit.Digests[:], circuit.ClaimedValues[:], whSnark)
// 	if err != nil {
// 		return err
// 	}
// 	verifier.scalarApi.AssertIsEqual(&res, &circuit.Gamma)
// 	return nil
// }

// func TestDeriveGamma(t *testing.T) {

// 	assert := test.NewAssert(t)

// 	// prepare test data
// 	alpha, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
// 	assert.NoError(err)
// 	srs, err := kzg_bn254.NewSRS(kzgSize, alpha)
// 	assert.NoError(err)

// 	var polynomials [10][]fr_bn254.Element
// 	var digests [10]kzg_bn254.Digest
// 	for i := 0; i < 10; i++ {
// 		polynomials[i] = make([]fr_bn254.Element, polynomialSize)
// 		for j := 0; j < polynomialSize; j++ {
// 			polynomials[i][j].SetRandom()
// 		}
// 		digests[i], err = kzg_bn254.Commit(polynomials[i], srs.Pk)
// 		assert.NoError(err)
// 	}

// 	var point fr_bn254.Element
// 	point.SetRandom()
// 	var target big.Int
// 	target.SetUint64(1)
// 	nbBits := ecc.BLS12_381.ScalarField().BitLen()
// 	nn := ((nbBits+7)/8)*8 - 8
// 	target.Lsh(&target, uint(nn))
// 	h, err := recursion.NewShort(ecc.BLS12_381.ScalarField(), &target)
// 	assert.NoError(err)

// 	batchOpeningProof, err := kzg_bn254.BatchOpenSinglePoint(polynomials[:], digests[:], point, h, srs.Pk)
// 	assert.NoError(err)

// 	gamma, err := kzg_bn254.DeriveGamma(point, digests[:], batchOpeningProof.ClaimedValues, h)
// 	assert.NoError(err)

// 	// prepare witness
// 	wPoint, err := ValueOfScalar[emulated.BN254Fr](point)
// 	assert.NoError(err)
// 	var wDigests [10]Commitment[sw_bn254.G1Affine]
// 	for i := 0; i < 10; i++ {
// 		wDigests[i], err = ValueOfCommitment[sw_bn254.G1Affine](digests[i])
// 		assert.NoError(err)
// 	}
// 	var wClaimedValues [10]emulated.Element[emulated.BN254Fr]
// 	for i := 0; i < 10; i++ {
// 		wClaimedValues[i], err = ValueOfScalar[emulated.BN254Fr](batchOpeningProof.ClaimedValues[i])
// 		assert.NoError(err)
// 	}
// 	wGmma, err := ValueOfScalar[emulated.BN254Fr](gamma)
// 	assert.NoError(err)

// 	assignment := DeriveGammaTest[emulated.BN254Fr, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
// 		Point:         wPoint,
// 		Digests:       wDigests,
// 		ClaimedValues: wClaimedValues,
// 		Gamma:         wGmma,
// 	}

// 	assert.CheckCircuit(&DeriveGammaTest[emulated.BN254Fr, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{}, test.WithValidAssignment(&assignment), test.WithCurves(ecc.BLS12_381), test.WithBackends(backend.PLONK))
// }
