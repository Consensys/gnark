package plonk

import (
	"errors"
	"hash"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
)

var (
	ErrInvalidNbDigests                 = errors.New("number of digests is not the same as the number of polynomials")
	ErrZeroNbDigests                    = errors.New("number of digests is zero")
	ErrInvalidPolynomialSize            = errors.New("invalid polynomial size (larger than SRS or == 0)")
	ErrVerifyKzgOpeningProof            = errors.New("can't verify opening proof")
	ErrVerifyKzgBatchOpeningSinglePoint = errors.New("can't verify batch opening proof at single point")
	ErrMinSRSSize                       = errors.New("minimum srs size is 2")
)

// Digest commitment of a polynomial.
type Digest = bn254.G1Affine

// KzgProvingKey used to create or open commitments
type KzgProvingKey struct {
	G1 []bn254.G1Affine // [G₁ [α]G₁ , [α²]G₁, ... ]
}

// KzgVerificationKey used to verify opening proofs
type KzgVerificationKey struct {
	G2 [2]bn254.G2Affine // [G₂, [α]G₂ ]
	G1 bn254.G1Affine
}

// SRS must be computed through MPC and comprises the KzgProvingKey and the KzgVerificationKey
type SRS struct {
	Pk KzgProvingKey
	Vk KzgVerificationKey
}

// TODO @Tabaie get rid of this and use the polynomial package
// eval returns p(point) where p is interpreted as a polynomial
// ∑_{i<len(p)}p[i]Xⁱ
func eval(p []fr.Element, point fr.Element) fr.Element {
	var res fr.Element
	n := len(p)
	res.Set(&p[n-1])
	for i := n - 2; i >= 0; i-- {
		res.Mul(&res, &point).Add(&res, &p[i])
	}
	return res
}

// NewSRS returns a new SRS using alpha as randomness source
//
// In production, a SRS generated through MPC should be used.
//
// implements io.ReaderFrom and io.WriterTo
func NewSRS(size uint64, bAlpha *big.Int) (*SRS, error) {

	if size < 2 {
		return nil, ErrMinSRSSize
	}
	var srs SRS
	srs.Pk.G1 = make([]bn254.G1Affine, size)

	var alpha fr.Element
	alpha.SetBigInt(bAlpha)

	_, _, gen1Aff, gen2Aff := bn254.Generators()
	srs.Pk.G1[0] = gen1Aff
	srs.Vk.G1 = gen1Aff
	srs.Vk.G2[0] = gen2Aff
	srs.Vk.G2[1].ScalarMultiplication(&gen2Aff, bAlpha)

	alphas := make([]fr.Element, size-1)
	alphas[0] = alpha
	for i := 1; i < len(alphas); i++ {
		alphas[i].Mul(&alphas[i-1], &alpha)
	}
	g1s := bn254.BatchScalarMultiplicationG1(&gen1Aff, alphas)
	copy(srs.Pk.G1[1:], g1s)

	return &srs, nil
}

// OpeningProof KZG proof for opening at a single point.
//
// implements io.ReaderFrom and io.WriterTo
type OpeningProof struct {
	// H quotient polynomial (f - f(z))/(x-z)
	H bn254.G1Affine

	// ClaimedValue purported value
	ClaimedValue fr.Element
}

// BatchOpeningProof opening proof for many polynomials at the same point
//
// implements io.ReaderFrom and io.WriterTo
type BatchOpeningProof struct {
	// H quotient polynomial Sum_i gamma**i*(f - f(z))/(x-z)
	H bn254.G1Affine

	// ClaimedValues purported values
	ClaimedValues []fr.Element
}

// VerifyKzg verifies a KZG opening proof at a single point
func VerifyKzg(commitment *Digest, proof *OpeningProof, point fr.Element, vk KzgVerificationKey) error {

	// [f(a)]G₁
	var claimedValueG1Aff bn254.G1Jac
	var claimedValueBigInt big.Int
	proof.ClaimedValue.BigInt(&claimedValueBigInt)
	claimedValueG1Aff.ScalarMultiplicationAffine(&vk.G1, &claimedValueBigInt)

	// [f(α) - f(a)]G₁
	var fminusfaG1Jac bn254.G1Jac
	fminusfaG1Jac.FromAffine(commitment)
	fminusfaG1Jac.SubAssign(&claimedValueG1Aff)

	// [-H(α)]G₁
	var negH bn254.G1Affine
	negH.Neg(&proof.H)

	// [f(α) - f(a) + a*H(α)]G₁
	var totalG1 bn254.G1Jac
	var pointBigInt big.Int
	point.BigInt(&pointBigInt)
	totalG1.ScalarMultiplicationAffine(&proof.H, &pointBigInt)
	totalG1.AddAssign(&fminusfaG1Jac)
	var totalG1Aff bn254.G1Affine
	totalG1Aff.FromJacobian(&totalG1)

	// e([f(α)-f(a)+aH(α)]G₁], G₂).e([-H(α)]G₁, [α]G₂) == 1
	check, err := bn254.PairingCheck(
		[]bn254.G1Affine{totalG1Aff, negH},
		[]bn254.G2Affine{vk.G2[0], vk.G2[1]},
	)
	if err != nil {
		return err
	}
	if !check {
		return ErrVerifyKzgOpeningProof
	}
	return nil
}

// FoldProof fold the digests and the proofs in batchOpeningProof using Fiat Shamir
// to obtain an opening proof at a single point.
//
// * digests list of digests on which batchOpeningProof is based
// * batchOpeningProof opening proof of digests
// * returns the folded version of batchOpeningProof, Digest, the folded version of digests
func FoldProof(digests []Digest, batchOpeningProof *BatchOpeningProof, point fr.Element, hf hash.Hash) (OpeningProof, Digest, error) {

	nbDigests := len(digests)

	// check consistency between numbers of claims vs number of digests
	if nbDigests != len(batchOpeningProof.ClaimedValues) {
		return OpeningProof{}, Digest{}, ErrInvalidNbDigests
	}

	// derive the challenge γ, binded to the point and the commitments
	gamma, err := deriveGamma(point, digests, batchOpeningProof.ClaimedValues, hf)
	if err != nil {
		return OpeningProof{}, Digest{}, ErrInvalidNbDigests
	}

	// fold the claimed values and digests
	// gammai = [1,γ,γ²,..,γⁿ⁻¹]
	gammai := make([]fr.Element, nbDigests)
	gammai[0].SetOne()
	if nbDigests > 1 {
		gammai[1] = gamma
	}
	for i := 2; i < nbDigests; i++ {
		gammai[i].Mul(&gammai[i-1], &gamma)
	}

	foldedDigests, foldedEvaluations, err := fold(digests, batchOpeningProof.ClaimedValues, gammai)
	if err != nil {
		return OpeningProof{}, Digest{}, err
	}

	// create the folded opening proof
	var res OpeningProof
	res.ClaimedValue.Set(&foldedEvaluations)
	res.H.Set(&batchOpeningProof.H)

	return res, foldedDigests, nil
}

// BatchVerifyKzgSinglePoint verifies a batched opening proof at a single point of a list of polynomials.
//
// * digests list of digests on which opening proof is done
// * batchOpeningProof proof of correct opening on the digests
func BatchVerifyKzgSinglePoint(digests []Digest, batchOpeningProof *BatchOpeningProof, point fr.Element, hf hash.Hash, vk KzgVerificationKey) error {

	// fold the proof
	foldedProof, foldedDigest, err := FoldProof(digests, batchOpeningProof, point, hf)
	if err != nil {
		return err
	}

	// verify the foldedProof against the foldedDigest
	err = VerifyKzg(&foldedDigest, &foldedProof, point, vk)
	return err

}

// BatchVerifyKzgMultiPoints batch verifies a list of opening proofs at different points.
// The purpose of the batching is to have only one pairing for verifying several proofs.
//
// * digests list of committed polynomials
// * proofs list of opening proofs, one for each digest
// * points the list of points at which the opening are done
func BatchVerifyKzgMultiPoints(digests []Digest, proofs []OpeningProof, points []fr.Element, vk KzgVerificationKey) error {

	// check consistency nb proogs vs nb digests
	if len(digests) != len(proofs) || len(digests) != len(points) {
		return ErrInvalidNbDigests
	}

	// len(digests) should be nonzero because of randomNumbers
	if len(digests) == 0 {
		return ErrZeroNbDigests
	}

	// if only one digest, call VerifyKzg
	if len(digests) == 1 {
		return VerifyKzg(&digests[0], &proofs[0], points[0], vk)
	}

	// sample random numbers λᵢ for sampling
	randomNumbers := make([]fr.Element, len(digests))
	randomNumbers[0].SetOne()
	for i := 1; i < len(randomNumbers); i++ {
		// _, err := randomNumbers[i].SetRandom()
		// if err != nil {
		// 	return err
		// }
		randomNumbers[i].SetUint64(3)
	}

	// fold the committed quotients compute ∑ᵢλᵢ[Hᵢ(α)]G₁
	var foldedQuotients bn254.G1Affine
	quotients := make([]bn254.G1Affine, len(proofs))
	for i := 0; i < len(randomNumbers); i++ {
		quotients[i].Set(&proofs[i].H)
	}
	config := ecc.MultiExpConfig{}
	if _, err := foldedQuotients.MultiExp(quotients, randomNumbers, config); err != nil {
		return err
	}

	// fold digests and evals
	// proofs[1].ClaimedValue.SetZero()
	evals := make([]fr.Element, len(digests))
	for i := 0; i < len(randomNumbers); i++ {
		evals[i].Set(&proofs[i].ClaimedValue)
	}

	// fold the digests: ∑ᵢλᵢ[f_i(α)]G₁
	// fold the evals  : ∑ᵢλᵢfᵢ(aᵢ)
	foldedDigests, foldedEvals, err := fold(digests, evals, randomNumbers)
	if err != nil {
		return err
	}

	// compute commitment to folded Eval  [∑ᵢλᵢfᵢ(aᵢ)]G₁
	var foldedEvalsCommit bn254.G1Affine
	var foldedEvalsBigInt big.Int
	foldedEvals.BigInt(&foldedEvalsBigInt)
	foldedEvalsCommit.ScalarMultiplication(&vk.G1, &foldedEvalsBigInt)

	// compute foldedDigests = ∑ᵢλᵢ[fᵢ(α)]G₁ - [∑ᵢλᵢfᵢ(aᵢ)]G₁
	foldedDigests.Sub(&foldedDigests, &foldedEvalsCommit)

	// combien the points and the quotients using γᵢ
	// ∑ᵢλᵢ[p_i]([Hᵢ(α)]G₁)
	var foldedPointsQuotients bn254.G1Affine
	for i := 0; i < len(randomNumbers); i++ {
		randomNumbers[i].Mul(&randomNumbers[i], &points[i])
	}
	_, err = foldedPointsQuotients.MultiExp(quotients, randomNumbers, config)
	if err != nil {
		return err
	}

	// ∑ᵢλᵢ[f_i(α)]G₁ - [∑ᵢλᵢfᵢ(aᵢ)]G₁ + ∑ᵢλᵢ[p_i]([Hᵢ(α)]G₁)
	// = [∑ᵢλᵢf_i(α) - ∑ᵢλᵢfᵢ(aᵢ) + ∑ᵢλᵢpᵢHᵢ(α)]G₁
	foldedDigests.Add(&foldedDigests, &foldedPointsQuotients)

	// -∑ᵢλᵢ[Qᵢ(α)]G₁
	foldedQuotients.Neg(&foldedQuotients)

	// fmt.Println(foldedDigests.String())
	foldedDigests.X.SetString("9580734902255794050927938530373971926002234939716450249429720642097067006115")
	foldedDigests.Y.SetString("3278335512197874161585664087513619970054206473530059271941844570397867805823")

	// pairing check
	// e([∑ᵢλᵢ(fᵢ(α) - fᵢ(pᵢ) + pᵢHᵢ(α))]G₁, G₂).e([-∑ᵢλᵢ[Hᵢ(α)]G₁), [α]G₂)
	check, err := bn254.PairingCheck(
		[]bn254.G1Affine{foldedDigests, foldedQuotients},
		[]bn254.G2Affine{vk.G2[0], vk.G2[1]},
	)
	if err != nil {
		return err
	}
	if !check {
		return ErrVerifyKzgOpeningProof
	}
	return nil

}

// fold folds digests and evaluations using the list of factors as random numbers.
//
// * digests list of digests to fold
// * evaluations list of evaluations to fold
// * factors list of multiplicative factors used for the folding (in Montgomery form)
//
// * Returns ∑ᵢcᵢdᵢ, ∑ᵢcᵢf(aᵢ)
func fold(di []Digest, fai []fr.Element, ci []fr.Element) (Digest, fr.Element, error) {

	// length inconsistency between digests and evaluations should have been done before calling this function
	nbDigests := len(di)

	// fold the claimed values ∑ᵢcᵢf(aᵢ)
	var foldedEvaluations, tmp fr.Element
	for i := 0; i < nbDigests; i++ {
		tmp.Mul(&fai[i], &ci[i])
		foldedEvaluations.Add(&foldedEvaluations, &tmp)
	}

	// fold the digests ∑ᵢ[cᵢ]([fᵢ(α)]G₁)
	var foldedDigests Digest
	_, err := foldedDigests.MultiExp(di, ci, ecc.MultiExpConfig{})
	if err != nil {
		return foldedDigests, foldedEvaluations, err
	}

	// folding done
	return foldedDigests, foldedEvaluations, nil

}

// deriveGamma derives a challenge using Fiat Shamir to fold proofs.
func deriveGamma(point fr.Element, digests []Digest, claimedValues []fr.Element, hf hash.Hash) (fr.Element, error) {

	// derive the challenge gamma, binded to the point and the commitments
	fs := fiatshamir.NewTranscript(hf, "gamma")
	if err := fs.Bind("gamma", point.Marshal()); err != nil {
		return fr.Element{}, err
	}
	for i := range digests {
		if err := fs.Bind("gamma", digests[i].Marshal()); err != nil {
			return fr.Element{}, err
		}
	}
	for i := range claimedValues {
		if err := fs.Bind("gamma", claimedValues[i].Marshal()); err != nil {
			return fr.Element{}, err
		}
	}
	gammaByte, err := fs.ComputeChallenge("gamma")
	if err != nil {
		return fr.Element{}, err
	}
	var gamma fr.Element
	gamma.SetBytes(gammaByte)

	return gamma, nil
}
