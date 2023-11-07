package kzg_refactor

import (
	"errors"
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/emulated"
)

var (
	ErrInvalidNbDigests = errors.New("number of digests is not the same as the number of polynomials")
	ErrZeroNbDigests    = errors.New("number of digests is zero")
)

// Commitment is an KZG commitment to a polynomial. Use [ValueOfCommitment] to
// initialize a witness from the native commitment.
type Commitment[G1El any] struct {
	G1El G1El
}

// OpeningProof embeds the opening proof that polynomial evaluated at Point is
// equal to ClaimedValue. Use [ValueOfOpeningProof] to initialize a witness from
// a native opening proof.
type OpeningProof[S emulated.FieldParams, G1El any] struct {
	Quotient     G1El
	ClaimedValue emulated.Element[S]
}

// VerifyingKey is the trusted setup for KZG polynomial commitment scheme. Use
// [ValueOfVerifyingKey] to initialize a witness from the native VerifyingKey.
type VerifyingKey[G1El, G2El any] struct {
	G2 [2]G2El
	G1 G1El
}

type BatchOpeningProof[S emulated.FieldParams, G1El any] struct {
	Quotient      G1El
	ClaimedValues []emulated.Element[S]
}

// B base field, S scalar
// S here is emulated.Element[S]
type IVerifier[S emulated.FieldParams, G1El, G2El any] interface {
	CheckOpeningProof(Commitment[G1El], OpeningProof[S, G1El], emulated.Element[S], VerifyingKey[G1El, G2El]) error
	FoldProof([]Commitment[G1El], BatchOpeningProof[S, G1El], emulated.Element[S], hash.FieldHasher, ...frontend.Variable) (OpeningProof[S, G1El], Commitment[G1El], error)
	BatchVerifySinglePoint([]Commitment[G1El], BatchOpeningProof[S, G1El], emulated.Element[S], VerifyingKey[G1El, G2El], hash.FieldHasher, ...frontend.Variable) error
	BatchVerifyMultiPoints([]Commitment[G1El], []OpeningProof[S, G1El], []emulated.Element[S], VerifyingKey[G1El, G2El]) error
}

type Verifier[S emulated.FieldParams, G1El, G2El, GtEl any] struct {
	api       frontend.API
	scalarApi *emulated.Field[S]
	ec        algebra.Curve[emulated.Element[S], G1El]
	pairing   algebra.Pairing[G1El, G2El, GtEl]
}

func NewVerifier[S emulated.FieldParams, G1El, G2El, GtEl any](api frontend.API) (Verifier[S, G1El, G2El, GtEl], error) {
	var res Verifier[S, G1El, G2El, GtEl]
	var err error
	res.api = api
	res.ec, err = algebra.GetCurve[emulated.Element[S], G1El](api)
	if err != nil {
		return res, err
	}
	res.scalarApi, err = emulated.NewField[S](api)
	if err != nil {
		return res, err
	}
	res.pairing, err = algebra.GetPairing[G1El, G2El, GtEl](api)
	if err != nil {
		return res, err
	}

	return res, nil
}

// S here is emulated.FieldParams
func (v *Verifier[S, G1El, G2El, GTEl]) CheckOpeningProof(digest Commitment[G1El], proof OpeningProof[S, G1El], point emulated.Element[S], vk VerifyingKey[G1El, G2El]) error {

	claimedValueG1 := v.ec.ScalarMulBase(&proof.ClaimedValue)

	// [f(α) - f(a)]G₁
	fminusfaG1 := v.ec.Neg(claimedValueG1)
	fminusfaG1 = v.ec.Add(fminusfaG1, &digest.G1El)

	// [-H(α)]G₁
	negQuotientPoly := v.ec.Neg(&proof.Quotient)

	// [f(α) - f(a) + a*H(α)]G₁
	totalG1 := v.ec.ScalarMul(&proof.Quotient, &point)
	totalG1 = v.ec.Add(totalG1, fminusfaG1)

	// e([f(α)-f(a)+aH(α)]G₁], G₂).e([-H(α)]G₁, [α]G₂) == 1
	if err := v.pairing.PairingCheck(
		[]*G1El{totalG1, negQuotientPoly},
		[]*G2El{&vk.G2[0], &vk.G2[1]},
	); err != nil {
		return fmt.Errorf("pairing check: %w", err)
	}
	return nil

}

func (v *Verifier[S, G1El, G2El, GTEl]) FoldProof(digests []Commitment[G1El], batchOpeningProof BatchOpeningProof[S, G1El], point emulated.Element[S], hf hash.FieldHasher, dataTranscript ...frontend.Variable) (OpeningProof[S, G1El], Commitment[G1El], error) {

	nbDigests := len(digests)

	// check consistency between numbers of claims vs number of digests
	if nbDigests != len(batchOpeningProof.ClaimedValues) {
		return OpeningProof[S, G1El]{}, Commitment[G1El]{}, ErrInvalidNbDigests
	}

	// derive the challenge γ, binded to the point and the commitments
	gamma, err := v.deriveGamma(point, digests, batchOpeningProof.ClaimedValues, hf, dataTranscript...)
	if err != nil {
		return OpeningProof[S, G1El]{}, Commitment[G1El]{}, err
	}

	// fold the claimed values and digests
	// gammai = [1,γ,γ²,..,γⁿ⁻¹]
	gammai := make([]emulated.Element[S], nbDigests)
	gammai[0] = emulated.ValueOf[S](1)
	if nbDigests > 1 {
		gammai[1] = gamma
	}
	for i := 2; i < nbDigests; i++ {
		gammai[i] = *(v.scalarApi.Mul(&gammai[i-1], &gamma))
	}

	foldedDigests, foldedEvaluations := v.fold(digests, batchOpeningProof.ClaimedValues, gammai)

	var foldedProof OpeningProof[S, G1El]
	foldedProof.Quotient = batchOpeningProof.Quotient
	foldedProof.ClaimedValue = foldedEvaluations
	return foldedProof, foldedDigests, nil

	// create the folded opening proof
	// var res OpeningProof[S, G1El]
	// res.ClaimedValue = batchOpeningProof.ClaimedValues[0]
	// res.Quotient = batchOpeningProof.Quotient
	// return res, digests[0], nil

}

func (v *Verifier[S, G1El, G2El, GTEl]) BatchVerifySinglePoint(digests []Commitment[G1El], batchOpeningProof BatchOpeningProof[S, G1El], point emulated.Element[S], hf hash.FieldHasher, vk VerifyingKey[G1El, G2El], dataTranscript ...frontend.Variable) error {

	// fold the proof
	foldedProof, foldedDigest, err := v.FoldProof(digests, batchOpeningProof, point, hf, dataTranscript...)
	if err != nil {
		return err
	}

	// verify the foldedProof against the foldedDigest
	err = v.CheckOpeningProof(foldedDigest, foldedProof, point, vk)

	return err
}

func (v *Verifier[S, G1El, G2El, GTEl]) BatchVerifyMultiPoints(digests []Commitment[G1El], proofs []OpeningProof[S, G1El], points []emulated.Element[S], vk VerifyingKey[G1El, G2El]) error {

	// check consistency nb proogs vs nb digests
	if len(digests) != len(proofs) || len(digests) != len(points) {
		return ErrInvalidNbDigests
	}

	// len(digests) should be nonzero because of randomNumbers
	if len(digests) == 0 {
		return ErrZeroNbDigests
	}

	// if only one digest, call Verify
	if len(digests) == 1 {
		return v.CheckOpeningProof(digests[0], proofs[0], points[0], vk)
	}

	// sample random numbers λᵢ for sampling
	randomNumbers := make([]emulated.Element[S], len(digests))
	randomNumbers[0] = emulated.ValueOf[S](1)
	for i := 1; i < len(randomNumbers); i++ {
		// TODO use real random numbers, follow the solidity smart contract to know which variables are used as seed
		randomNumbers[i] = emulated.ValueOf[S](42)
	}

	// fold the committed quotients compute ∑ᵢλᵢ[Hᵢ(α)]G₁
	var foldedQuotients G1El
	quotients := make([]G1El, len(proofs))
	for i := 0; i < len(randomNumbers); i++ {
		quotients[i] = proofs[i].Quotient
	}
	foldedQuotients = *v.ec.ScalarMul(&quotients[0], &randomNumbers[0])
	for i := 1; i < len(digests); i++ {
		tmp := *v.ec.ScalarMul(&quotients[i], &randomNumbers[i])
		foldedQuotients = *v.ec.Add(&tmp, &foldedQuotients)
	}
	// aa := v.ec.MarshalG1(foldedQuotients)
	// slices.Reverse(aa[:256])
	// slices.Reverse(aa[256:])
	// xx := v.api.FromBinary(aa[:256]...)
	// yy := v.api.FromBinary(aa[256:]...)
	// v.api.Println(xx)
	// v.api.Println(yy)

	// fold digests and evals
	evals := make([]emulated.Element[S], len(digests))

	// fold the digests: ∑ᵢλᵢ[f_i(α)]G₁
	// fold the evals  : ∑ᵢλᵢfᵢ(aᵢ)
	for i := 0; i < len(digests); i++ {

		evals[i] = proofs[i].ClaimedValue

		// aa := v.scalarApi.ToBits(&proofs[i].ClaimedValue)
		// bb := v.api.FromBinary(aa...)
		// v.api.Println(bb)
	}
	foldedDigests, foldedEvals := v.fold(digests, evals, randomNumbers)

	// bb := v.scalarApi.ToBits(&foldedEvals)
	// bbb := v.api.FromBinary(bb...)
	// v.api.Println(bbb)

	// aa := v.ec.MarshalG1(foldedDigests.G1El)
	// slices.Reverse(aa[:256])
	// slices.Reverse(aa[256:])
	// xx := v.api.FromBinary(aa[:256]...)
	// yy := v.api.FromBinary(aa[256:]...)
	// v.api.Println(xx)
	// v.api.Println(yy)

	// compute commitment to folded Eval  [∑ᵢλᵢfᵢ(aᵢ)]G₁
	foldedEvalsCommit := v.ec.ScalarMul(&vk.G1, &foldedEvals)

	// bb := v.scalarApi.ToBits(&foldedEvals)
	// bbb := v.api.FromBinary(bb...)
	// v.api.Println(bbb)

	// compute foldedDigests = ∑ᵢλᵢ[fᵢ(α)]G₁ - [∑ᵢλᵢfᵢ(aᵢ)]G₁
	// foldedDigests.Sub(&foldedDigests, &foldedEvalsCommit)
	tmp := v.ec.Neg(foldedEvalsCommit)
	foldedDigests.G1El = *v.ec.Add(&foldedDigests.G1El, tmp)

	// combien the points and the quotients using γᵢ
	// ∑ᵢλᵢ[p_i]([Hᵢ(α)]G₁)
	var foldedPointsQuotients G1El
	for i := 0; i < len(randomNumbers); i++ {
		randomNumbers[i] = *v.scalarApi.Mul(&randomNumbers[i], &points[i])
		// randomNumbers[i] = *v.scalarApi.Reduce(&randomNumbers[i])
	}
	foldedPointsQuotients = *v.ec.ScalarMul(&quotients[0], &randomNumbers[0])
	for i := 1; i < len(digests); i++ {
		tmp = v.ec.ScalarMul(&quotients[i], &randomNumbers[i])
		foldedPointsQuotients = *v.ec.Add(&foldedPointsQuotients, tmp)
	}

	// ∑ᵢλᵢ[f_i(α)]G₁ - [∑ᵢλᵢfᵢ(aᵢ)]G₁ + ∑ᵢλᵢ[p_i]([Hᵢ(α)]G₁)
	// = [∑ᵢλᵢf_i(α) - ∑ᵢλᵢfᵢ(aᵢ) + ∑ᵢλᵢpᵢHᵢ(α)]G₁
	foldedDigests.G1El = *v.ec.Add(&foldedDigests.G1El, &foldedPointsQuotients)

	// -∑ᵢλᵢ[Qᵢ(α)]G₁
	// foldedQuotients.Neg(&foldedQuotients)
	foldedQuotients = *v.ec.Neg(&foldedQuotients)

	// pairing check
	err := v.pairing.PairingCheck(
		[]*G1El{&foldedDigests.G1El, &foldedQuotients},
		[]*G2El{&vk.G2[0], &vk.G2[1]},
	)

	return err
}

func (v *Verifier[S, G1El, G2El, GTEl]) fold(digests []Commitment[G1El], fai, ci []emulated.Element[S]) (Commitment[G1El], emulated.Element[S]) {

	// length inconsistency between digests and evaluations should have been done before calling this function
	nbDigests := len(digests)

	// fold the claimed values ∑ᵢcᵢf(aᵢ)
	var foldedEvaluations, tmp emulated.Element[S]
	foldedEvaluations = emulated.ValueOf[S](0)
	for i := 0; i < nbDigests; i++ {
		tmp = *v.scalarApi.Mul(&fai[i], &ci[i])
		foldedEvaluations = *v.scalarApi.Add(&foldedEvaluations, &tmp)
	}

	// fold the digests ∑ᵢ[cᵢ]([fᵢ(α)]G₁)
	var foldedDigests Commitment[G1El]
	foldedDigests.G1El = *v.ec.ScalarMul(&digests[0].G1El, &ci[0])
	for i := 1; i < nbDigests; i++ {
		tmp := *v.ec.ScalarMul(&digests[i].G1El, &ci[i])
		foldedDigests.G1El = *v.ec.Add(&tmp, &foldedDigests.G1El)
	}

	// folding done
	return foldedDigests, foldedEvaluations

}

// deriveGamma derives a challenge using Fiat Shamir to fold proofs.
// dataTranscript are supposed to be bits.
// /!\ bitMode = true here /!\
func (v *Verifier[S, G1El, G2El, GTEl]) deriveGamma(point emulated.Element[S], digests []Commitment[G1El], claimedValues []emulated.Element[S], hf hash.FieldHasher, dataTranscript ...frontend.Variable) (emulated.Element[S], error) {

	// derive the challenge gamma, binded to the point and the commitments
	fs := fiatshamir.NewTranscript(v.api, hf, "gamma")

	marhsalledPoint := v.ec.MarshalScalar(point)
	if err := fs.Bind("gamma", marhsalledPoint); err != nil {
		return emulated.Element[S]{}, err
	}
	for i := range digests {
		if err := fs.Bind("gamma", v.ec.MarshalG1(digests[i].G1El)); err != nil {
			return emulated.Element[S]{}, err
		}
	}
	for i := range claimedValues {
		if err := fs.Bind("gamma", v.ec.MarshalScalar(claimedValues[i])); err != nil {
			return emulated.Element[S]{}, err
		}
	}

	if err := fs.Bind("gamma", dataTranscript); err != nil {
		return emulated.Element[S]{}, err
	}

	gamma, err := fs.ComputeChallenge("gamma", true)
	if err != nil {
		return emulated.Element[S]{}, err
	}
	bGamma := v.api.ToBinary(gamma)
	gammaS := v.scalarApi.FromBits(bGamma...)

	return *gammaS, nil
}
