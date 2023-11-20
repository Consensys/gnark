package plonk

import (
	"fmt"
	stdbits "math/bits"

	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	fr_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	backend_plonk "github.com/consensys/gnark/backend/plonk"
	plonkbackend_bls12377 "github.com/consensys/gnark/backend/plonk/bls12-377"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/algebra/native/sw_bls24315"
	"github.com/consensys/gnark/std/commitments/kzg"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion"
)

type Proof[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT] struct {
	// Commitments to the solution vectors
	LRO [3]kzg.Commitment[G1El]
	// Commitment to Z, the permutation polynomial
	Z kzg.Commitment[G1El]
	// Commitments to h1, h2, h3 such that h = h1 + Xh2 + X**2h3 is the quotient polynomial
	H [3]kzg.Commitment[G1El]

	Bsb22Commitments []kzg.Commitment[G1El]

	// Batch opening proof of h1 + zeta*h2 + zeta**2h3, linearizedPolynomial, l, r, o, s1, s2, qCPrime
	BatchedProof kzg.BatchOpeningProof[FR, G1El]

	// Opening proof of Z at zeta*mu
	ZShiftedOpening kzg.OpeningProof[FR, G1El]
}

func ValueOfProof[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT](proof backend_plonk.Proof) (Proof[FR, G1El, G2El], error) {
	var ret Proof[FR, G1El, G2El]
	var err error
	switch r := any(&ret).(type) {
	case *Proof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine]:
		tProof, ok := proof.(*plonkbackend_bls12377.Proof)
		if !ok {
			return ret, fmt.Errorf("expected sw_bls12377.Proof, got %T", proof)
		}
		for i := range r.LRO {
			r.LRO[i], err = kzg.ValueOfCommitment[sw_bls12377.G1Affine](tProof.LRO[i])
			if err != nil {
				return ret, fmt.Errorf("commitment LRO[%d] value assignment: %w", i, err)
			}
		}
		r.Z, err = kzg.ValueOfCommitment[sw_bls12377.G1Affine](tProof.Z)
		if err != nil {
			return ret, fmt.Errorf("commitment Z value assignment: %w", err)
		}
		for i := range r.H {
			r.H[i], err = kzg.ValueOfCommitment[sw_bls12377.G1Affine](tProof.H[i])
			if err != nil {
				return ret, fmt.Errorf("commitment H[%d] value assignment: %w", i, err)
			}
		}
		r.Bsb22Commitments = make([]kzg.Commitment[sw_bls12377.G1Affine], len(tProof.Bsb22Commitments))
		for i := range r.Bsb22Commitments {
			r.Bsb22Commitments[i], err = kzg.ValueOfCommitment[sw_bls12377.G1Affine](tProof.Bsb22Commitments[i])
			if err != nil {
				return ret, fmt.Errorf("bsb22 commitment %d value assignment: %w", i, err)
			}
		}
		// TODO: actually we compute the opening point later. Maybe we can precompute it here and later assert its correctness?
		r.BatchedProof, err = kzg.ValueOfBatchOpeningProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine](tProof.BatchedProof)
		if err != nil {
			return ret, fmt.Errorf("batch opening proof value assignment: %w", err)
		}
		r.ZShiftedOpening, err = kzg.ValueOfOpeningProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine](tProof.ZShiftedOpening)
		if err != nil {
			return ret, fmt.Errorf("z shifted opening proof value assignment: %w", err)
		}
	default:
		return ret, fmt.Errorf("unknown parametric type combination: %T", ret)
	}
	return ret, nil
}

func PlaceholderProof[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT](ccs constraint.ConstraintSystem) Proof[FR, G1El, G2El] {
	return Proof[FR, G1El, G2El]{
		BatchedProof: kzg.BatchOpeningProof[FR, G1El]{
			ClaimedValues: make([]emulated.Element[FR], 7),
		},
	}
}

type VerifyingKey[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT] struct {
	// Size circuit
	Size              uint64
	SizeInv           emulated.Element[FR]
	Generator         emulated.Element[FR]
	NbPublicVariables uint64

	// Commitment scheme that is used for an instantiation of PLONK
	Kzg kzg.VerifyingKey[G1El, G2El]

	// cosetShift generator of the coset on the small domain
	CosetShift emulated.Element[FR]

	// S commitments to S1, S2, S3
	S [3]kzg.Commitment[G1El]

	// Commitments to ql, qr, qm, qo, qcp prepended with as many zeroes (ones for l) as there are public inputs.
	// In particular Qk is not complete.
	Ql, Qr, Qm, Qo, Qk kzg.Commitment[G1El]

	Qcp []kzg.Commitment[G1El]

	CommitmentConstraintIndexes []uint64
}

func ValueOfVerifyingKey[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT](vk backend_plonk.VerifyingKey) (VerifyingKey[FR, G1El, G2El], error) {
	var ret VerifyingKey[FR, G1El, G2El]
	var err error
	switch r := any(&ret).(type) {
	case *VerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine]:
		tVk, ok := vk.(*plonkbackend_bls12377.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected bls12377.VerifyingKey, got %T", vk)
		}
		r.Size = tVk.Size
		r.SizeInv = sw_bls12377.NewScalar(tVk.SizeInv)
		r.Generator = sw_bls12377.NewScalar(tVk.Generator)
		r.NbPublicVariables = tVk.NbPublicVariables
		r.Kzg, err = kzg.ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine](tVk.Kzg)
		if err != nil {
			return ret, fmt.Errorf("verifying key witness assignment: %w", err)
		}
		r.CosetShift = sw_bls12377.NewScalar(tVk.CosetShift)
		for i := range r.S {
			r.S[i], err = kzg.ValueOfCommitment[sw_bls12377.G1Affine](tVk.S[i])
			if err != nil {
				return ret, fmt.Errorf("commitment S[%d] witness assignment: %w", i, err)
			}
		}
		r.Ql, err = kzg.ValueOfCommitment[sw_bls12377.G1Affine](tVk.Ql)
		if err != nil {
			return ret, fmt.Errorf("commitment Ql witness assignment: %w", err)
		}
		r.Qr, err = kzg.ValueOfCommitment[sw_bls12377.G1Affine](tVk.Qr)
		if err != nil {
			return ret, fmt.Errorf("commitment Qr witness assignment: %w", err)
		}
		r.Qm, err = kzg.ValueOfCommitment[sw_bls12377.G1Affine](tVk.Qm)
		if err != nil {
			return ret, fmt.Errorf("commitment Qm witness assignment: %w", err)
		}
		r.Qo, err = kzg.ValueOfCommitment[sw_bls12377.G1Affine](tVk.Qo)
		if err != nil {
			return ret, fmt.Errorf("commitment Qo witness assignment: %w", err)
		}
		r.Qk, err = kzg.ValueOfCommitment[sw_bls12377.G1Affine](tVk.Qk)
		if err != nil {
			return ret, fmt.Errorf("commitment Qk witness assignment: %w", err)
		}
		r.Qcp = make([]kzg.Commitment[sw_bls12377.G1Affine], len(tVk.Qcp))
		for i := range r.Qcp {
			r.Qcp[i], err = kzg.ValueOfCommitment[sw_bls12377.G1Affine](tVk.Qcp[i])
			if err != nil {
				return ret, fmt.Errorf("commitment Qcp[%d] witness assignment: %w", i, err)
			}
		}
		r.CommitmentConstraintIndexes = make([]uint64, len(tVk.CommitmentConstraintIndexes))
		copy(r.CommitmentConstraintIndexes, tVk.CommitmentConstraintIndexes)
	default:
		return ret, fmt.Errorf("unknown parametric type combination")
	}
	return ret, nil
}

func PlaceholderVerifyingKey[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT](ccs constraint.ConstraintSystem) VerifyingKey[FR, G1El, G2El] {
	// TODO: we're not considering the commitments right now
	nbPublic := ccs.GetNbPublicVariables()
	nbConstraints := ccs.GetNbConstraints()
	sizeSystem := nbPublic + nbConstraints
	nextPowerTwo := 1 << stdbits.Len(uint(sizeSystem))
	return VerifyingKey[FR, G1El, G2El]{
		Size: uint64(nextPowerTwo),
	}
}

// Witness is a public witness to verify the SNARK proof against. For assigning
// witness use [ValueOfWitness] and to create stub witness for compiling use
// [PlaceholderWitness].
type Witness[FR emulated.FieldParams] struct {
	// Public is the public inputs. The first element does not need to be one
	// wire and is added implicitly during verification.
	Public []emulated.Element[FR]
}

func ValueOfWitness[FR emulated.FieldParams](w witness.Witness) (Witness[FR], error) {
	var ret Witness[FR]
	pubw, err := w.Public()
	if err != nil {
		return ret, fmt.Errorf("get public witness: %w", err)
	}
	vec := pubw.Vector()
	switch s := any(&ret).(type) {
	case *Witness[sw_bn254.ScalarField]:
		vect, ok := vec.(fr_bn254.Vector)
		if !ok {
			return ret, fmt.Errorf("expected fr_bn254.Vector, got %T", vec)
		}
		for i := range vect {
			s.Public = append(s.Public, sw_bn254.NewScalar(vect[i]))
		}
	case *Witness[sw_bls12377.ScalarField]:
		vect, ok := vec.(fr_bls12377.Vector)
		if !ok {
			return ret, fmt.Errorf("expected fr_bls12377.Vector, got %T", vec)
		}
		for i := range vect {
			s.Public = append(s.Public, sw_bls12377.NewScalar(vect[i]))
		}
	case *Witness[sw_bls12381.ScalarField]:
		vect, ok := vec.(fr_bls12381.Vector)
		if !ok {
			return ret, fmt.Errorf("expected fr_bls12381.Vector, got %T", vec)
		}
		for i := range vect {
			s.Public = append(s.Public, sw_bls12381.NewScalar(vect[i]))
		}
	case *Witness[sw_bls24315.ScalarField]:
		vect, ok := vec.(fr_bls24315.Vector)
		if !ok {
			return ret, fmt.Errorf("expected fr_bls24315.Vector, got %T", vec)
		}
		for i := range vect {
			s.Public = append(s.Public, sw_bls24315.NewScalar(vect[i]))
		}
	default:
		return ret, fmt.Errorf("unknown parametric type combination")
	}
	return ret, nil
}

// PlaceholderWitness creates a stub witness which can be used to allocate the
// variables in the circuit if the actual witness is not yet known. It takes
// into account the number of public inputs and number of used commitments.
func PlaceholderWitness[FR emulated.FieldParams](ccs constraint.ConstraintSystem) Witness[FR] {
	return Witness[FR]{
		Public: make([]emulated.Element[FR], ccs.GetNbPublicVariables()),
	}
}

type Verifier[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	api     frontend.API
	f       *emulated.Field[FR]
	curve   algebra.Curve[FR, G1El]
	pairing algebra.Pairing[G1El, G2El, GtEl]
	kzg     *kzg.Verifier[FR, G1El, G2El, GtEl]
}

func NewVerifier[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	api frontend.API, curve algebra.Curve[FR, G1El], pairing algebra.Pairing[G1El, G2El, GtEl],
) (*Verifier[FR, G1El, G2El, GtEl], error) {
	// var fr FR
	f, err := emulated.NewField[FR](api)
	if err != nil {
		return nil, fmt.Errorf("new scalars: %w", err)
	}
	kzg, err := kzg.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return nil, fmt.Errorf("new kzg verifier: %w", err)
	}
	return &Verifier[FR, G1El, G2El, GtEl]{
		api:     api,
		f:       f,
		curve:   curve,
		pairing: pairing,
		kzg:     kzg,
	}, nil
}

func (v *Verifier[FR, G1El, G2El, GtEl]) AssertProof(vk VerifyingKey[FR, G1El, G2El], proof Proof[FR, G1El, G2El], witness Witness[FR]) error {
	var fr FR
	if len(proof.Bsb22Commitments) != len(vk.Qcp) {
		return fmt.Errorf("BSB22 commitment number mismatch")
	}
	fs, err := recursion.NewTranscript(v.api, fr.Modulus(), []string{"gamma", "beta", "alpha", "zeta"})
	if err != nil {
		return fmt.Errorf("init new transcript: %w", err)
	}

	if err := v.bindPublicData(fs, "gamma", vk, witness); err != nil {
		return fmt.Errorf("bind public data: %w", err)
	}

	// The first challenge is derived using the public data: the commitments to the permutation,
	// the coefficients of the circuit, and the public inputs.
	// derive gamma from the Comm(blinded cl), Comm(blinded cr), Comm(blinded co)
	gamma, err := v.deriveRandomness(fs, "gamma", proof.LRO[0].G1El, proof.LRO[1].G1El, proof.LRO[2].G1El)
	if err != nil {
		return err
	}

	// derive beta from Comm(l), Comm(r), Comm(o)
	beta, err := v.deriveRandomness(fs, "beta")
	if err != nil {
		return err
	}

	// derive alpha from Comm(l), Comm(r), Comm(o), Com(Z), Bsb22Commitments
	alphaDeps := make([]G1El, len(proof.Bsb22Commitments)+1)
	for i := range proof.Bsb22Commitments {
		alphaDeps[i] = proof.Bsb22Commitments[i].G1El
	}
	alphaDeps[len(alphaDeps)-1] = proof.Z.G1El
	alpha, err := v.deriveRandomness(fs, "alpha", alphaDeps...)
	if err != nil {
		return err
	}

	// derive zeta, the point of evaluation
	zeta, err := v.deriveRandomness(fs, "zeta", proof.H[0].G1El, proof.H[1].G1El, proof.H[2].G1El)
	if err != nil {
		return err
	}

	// evaluation of Z=Xⁿ-1 at ζ
	one := v.f.One()
	zetaPowerM := v.fixedExpN(vk.Size, zeta) // ζⁿ
	zzeta := v.f.Sub(zetaPowerM, one)        // ζⁿ-1

	// L1 = (1/n)(ζⁿ-1)/(ζ-1)
	denom := v.f.Sub(zeta, one)
	lagrangeOne := v.f.Div(zzeta, denom)
	lagrangeOne = v.f.Mul(lagrangeOne, &vk.SizeInv)
	lagrange := lagrangeOne
	// compute PI = ∑_{i<n} Lᵢ*wᵢ
	pi := v.f.Zero()
	wPowI := v.f.One()
	for i := 0; i < len(witness.Public); i++ {
		xiLi := v.f.Mul(lagrange, &witness.Public[i])
		pi = v.f.Add(pi, xiLi)
		if i+1 != len(witness.Public) {
			lagrange = v.f.Mul(lagrange, &vk.Generator)
			lagrange = v.f.Mul(lagrange, denom)
			wPowI = v.f.Mul(wPowI, &vk.Generator)
			denom = v.f.Sub(zeta, wPowI)
			lagrange = v.f.Div(lagrange, denom)
		}
	}
	// TODO: omitted hashing the commitment constraint indexes

	// 	var hashBts []byte
	// 	var hashedCmt fr.Element
	// 	nbBuf := fr.Bytes
	// 	if cfg.HashToFieldFn.Size() < fr.Bytes {
	// 		nbBuf = cfg.HashToFieldFn.Size()
	// 	}
	// 	for i := range vk.CommitmentConstraintIndexes {
	// 		cfg.HashToFieldFn.Write(proof.Bsb22Commitments[i].Marshal())
	// 		hashBts = cfg.HashToFieldFn.Sum(hashBts[0:])
	// 		cfg.HashToFieldFn.Reset()
	// 		hashedCmt.SetBytes(hashBts[:nbBuf])

	// 		// Computing L_{CommitmentIndex}

	// 		wPowI.Exp(vk.Generator, big.NewInt(int64(vk.NbPublicVariables)+int64(vk.CommitmentConstraintIndexes[i])))
	// 		den.Sub(&zeta, &wPowI) // ζ-wⁱ

	// 		lagrange.SetOne().
	// 			Sub(&zeta, &lagrange).       // ζ-1
	// 			Mul(&lagrange, &wPowI).      // wⁱ(ζ-1)
	// 			Div(&lagrange, &den).        // wⁱ(ζ-1)/(ζ-wⁱ)
	// 			Mul(&lagrange, &lagrangeOne) // wⁱ/n (ζⁿ-1)/(ζ-wⁱ)

	// 		xiLi.Mul(&lagrange, &hashedCmt)
	// 		pi.Add(&pi, &xiLi)
	// 	}
	// }

	// linearizedpolynomial + pi(ζ) + α*(Z(μζ))*(l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*(o(ζ)+γ) - α²*L₁(ζ)

	zu := proof.ZShiftedOpening.ClaimedValue
	claimedQuotient := &proof.BatchedProof.ClaimedValues[0]
	linearizedPolynomialZeta := &proof.BatchedProof.ClaimedValues[1]
	l := proof.BatchedProof.ClaimedValues[2]
	r := proof.BatchedProof.ClaimedValues[3]
	o := proof.BatchedProof.ClaimedValues[4]
	s1 := proof.BatchedProof.ClaimedValues[5]
	s2 := proof.BatchedProof.ClaimedValues[6]

	// _s1 = (l(ζ)+β*s1(ζ)+γ)
	_s1 := v.f.Mul(&s1, beta)
	_s1 = v.f.Add(_s1, &l)
	_s1 = v.f.Add(_s1, gamma)

	// _s2 = (r(ζ)+β*s2(ζ)+γ)
	_s2 := v.f.Mul(&s2, beta)
	_s2 = v.f.Add(_s2, &r)
	_s2 = v.f.Add(_s2, gamma)

	// _o = (o(ζ)+γ)
	_o := v.f.Add(&o, gamma)

	// _s1 = α*(Z(μζ))*(l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*(o(ζ)+γ)
	_s1 = v.f.Mul(_s1, _s2)
	_s1 = v.f.Mul(_s1, _o)
	_s1 = v.f.Mul(_s1, alpha)
	_s1 = v.f.Mul(_s1, &zu)

	// alphaSquareLagrange = α²*L₁(ζ)
	alphaSquareLagrange := v.f.Mul(lagrangeOne, alpha)
	alphaSquareLagrange = v.f.Mul(alphaSquareLagrange, alpha)

	// linearizedPolynomialZeta = linearizedpolynomial+pi(zeta)+α*(Z(μζ))*(l(ζ)+s1(ζ)+γ)*(r(ζ)+s2(ζ)+γ)*(o(ζ)+γ)-α²*L₁(ζ)
	linearizedPolynomialZeta = v.f.Add(linearizedPolynomialZeta, pi)
	linearizedPolynomialZeta = v.f.Add(linearizedPolynomialZeta, _s1)
	linearizedPolynomialZeta = v.f.Sub(linearizedPolynomialZeta, alphaSquareLagrange)

	// Compute H(ζ) using the previous result: H(ζ) = prev_result/(ζⁿ-1)
	zetaPowerMMinusOne := v.f.Sub(zetaPowerM, one)
	linearizedPolynomialZeta = v.f.Div(linearizedPolynomialZeta, zetaPowerMMinusOne)

	// check that H(ζ) is as claimed
	v.f.AssertIsEqual(claimedQuotient, linearizedPolynomialZeta)

	// compute the folded commitment to H: Comm(h₁) + ζᵐ⁺²*Comm(h₂) + ζ²⁽ᵐ⁺²⁾*Comm(h₃)
	zetaMPlusTwo := v.f.Mul(zetaPowerM, zeta)
	zetaMPlusTwo = v.f.Mul(zetaMPlusTwo, zeta)

	foldedH := v.curve.ScalarMul(&proof.H[2].G1El, zetaMPlusTwo)
	foldedH = v.curve.Add(foldedH, &proof.H[1].G1El)
	foldedH = v.curve.ScalarMul(foldedH, zetaMPlusTwo)
	foldedH = v.curve.Add(foldedH, &proof.H[0].G1El)

	// Compute the commitment to the linearized polynomial
	// linearizedPolynomialDigest =
	// 		l(ζ)*ql+r(ζ)*qr+r(ζ)l(ζ)*qm+o(ζ)*qo+qk+Σᵢqc'ᵢ(ζ)*BsbCommitmentᵢ +
	// 		α*( Z(μζ)(l(ζ)+β*s₁(ζ)+γ)*(r(ζ)+β*s₂(ζ)+γ)*s₃(X)-Z(X)(l(ζ)+β*id_1(ζ)+γ)*(r(ζ)+β*id_2(ζ)+γ)*(o(ζ)+β*id_3(ζ)+γ) ) +
	// 		α²*L₁(ζ)*Z

	// first part: individual constraints
	rl := v.f.Mul(&r, &l)

	// second part: α*( Z(μζ)(l(ζ)+β*s₁(ζ)+γ)*(r(ζ)+β*s₂(ζ)+γ)*β*s₃(X)-Z(X)(l(ζ)+β*id_1(ζ)+γ)*(r(ζ)+β*id_2(ζ)+γ)*(o(ζ)+β*id_3(ζ)+γ) ) )

	uu := v.f.Mul(&zu, beta)

	vv := v.f.Mul(beta, &s1)
	vv = v.f.Add(vv, &l)
	vv = v.f.Add(vv, gamma)

	ww := v.f.Mul(beta, &s2)
	ww = v.f.Add(ww, &r)
	ww = v.f.Add(ww, gamma)

	// α*Z(μζ)(l(ζ)+β*s₁(ζ)+γ)*(r(ζ)+β*s₂(ζ)+γ)*β
	_s1 = v.f.Mul(uu, vv)
	_s1 = v.f.Mul(_s1, ww)
	_s1 = v.f.Mul(_s1, alpha)

	cosetsquare := v.f.Mul(&vk.CosetShift, &vk.CosetShift)

	// (l(ζ)+β*ζ+γ)
	uu = v.f.Mul(beta, zeta)
	uu = v.f.Add(uu, &l)
	uu = v.f.Add(uu, gamma)

	// (r(ζ)+β*μ*ζ+γ)
	vv = v.f.Mul(beta, zeta)
	vv = v.f.Mul(vv, &vk.CosetShift)
	vv = v.f.Add(vv, &r)
	vv = v.f.Add(vv, gamma)

	// (o(ζ)+β*μ²*ζ+γ)
	ww = v.f.Mul(beta, zeta)
	ww = v.f.Mul(ww, cosetsquare)
	ww = v.f.Add(ww, &o)
	ww = v.f.Add(ww, gamma)

	// -(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)
	_s2 = v.f.Mul(uu, vv)
	_s2 = v.f.Mul(_s2, ww)
	_s2 = v.f.Neg(_s2)

	// note since third part =  α²*L₁(ζ)*Z
	// -α*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ) + α²*L₁(ζ)
	_s2 = v.f.Mul(_s2, alpha)
	_s2 = v.f.Add(_s2, alphaSquareLagrange)

	points := make([]*G1El, len(proof.Bsb22Commitments))
	for i := range proof.Bsb22Commitments {
		points[i] = &proof.Bsb22Commitments[i].G1El
	}
	points = append(points,
		&vk.Ql.G1El, &vk.Qr.G1El, &vk.Qm.G1El, &vk.Qo.G1El, &vk.Qk.G1El, // first part
		&vk.S[2].G1El, &proof.Z.G1El, // second & third part
	)

	qC := make([]*emulated.Element[FR], len(proof.Bsb22Commitments))
	for i := range proof.BatchedProof.ClaimedValues[7:] {
		qC[i] = &proof.BatchedProof.ClaimedValues[7+i]
	}
	scalars := append(qC,
		&l, &r, rl, &o, one, // first part
		_s1, _s2, // second & third part
	)

	linearizedPolynomialDigest, err := v.curve.MultiScalarMul(points, scalars)
	if err != nil {
		return fmt.Errorf("linearized polynomial digest MSM: %w", err)
	}

	// Fold the first proof
	digestsToFold := []kzg.Commitment[G1El]{
		{G1El: *foldedH},
		{G1El: *linearizedPolynomialDigest},
		proof.LRO[0],
		proof.LRO[1],
		proof.LRO[2],
		vk.S[0],
		vk.S[1],
	}
	digestsToFold = append(digestsToFold, vk.Qcp...)
	foldedProof, foldedDigest, err := v.kzg.FoldProof(
		digestsToFold,
		proof.BatchedProof,
		*zeta,
		zu,
	)
	if err != nil {
		return fmt.Errorf("fold kzg proof: %w", err)
	}
	shiftedZeta := v.f.Mul(zeta, &vk.Generator)
	err = v.kzg.BatchVerifyMultiPoints(
		[]kzg.Commitment[G1El]{
			foldedDigest,
			proof.Z,
		},
		[]kzg.OpeningProof[FR, G1El]{
			foldedProof,
			proof.ZShiftedOpening,
		},
		[]emulated.Element[FR]{
			*zeta,
			*shiftedZeta,
		},
		vk.Kzg,
	)
	if err != nil {
		return fmt.Errorf("batch verify kzg: %w", err)
	}
	return nil
}

func (v *Verifier[FR, G1El, G2El, GtEl]) bindPublicData(fs *fiatshamir.Transcript, challenge string, vk VerifyingKey[FR, G1El, G2El], witness Witness[FR]) error {
	// permutation
	if err := fs.Bind(challenge, v.curve.MarshalG1(vk.S[0].G1El)); err != nil {
		return err
	}
	if err := fs.Bind(challenge, v.curve.MarshalG1(vk.S[1].G1El)); err != nil {
		return err
	}
	if err := fs.Bind(challenge, v.curve.MarshalG1(vk.S[2].G1El)); err != nil {
		return err
	}

	// coefficients
	if err := fs.Bind(challenge, v.curve.MarshalG1(vk.Ql.G1El)); err != nil {
		return err
	}
	if err := fs.Bind(challenge, v.curve.MarshalG1(vk.Qr.G1El)); err != nil {
		return err
	}
	if err := fs.Bind(challenge, v.curve.MarshalG1(vk.Qm.G1El)); err != nil {
		return err
	}
	if err := fs.Bind(challenge, v.curve.MarshalG1(vk.Qo.G1El)); err != nil {
		return err
	}
	if err := fs.Bind(challenge, v.curve.MarshalG1(vk.Qk.G1El)); err != nil {
		return err
	}
	for i := range vk.Qcp {
		if err := fs.Bind(challenge, v.curve.MarshalG1(vk.Qcp[i].G1El)); err != nil {
			return err
		}
	}

	// public inputs
	for i := 0; i < len(witness.Public); i++ {
		if err := fs.Bind(challenge, v.curve.MarshalScalar(witness.Public[i])); err != nil {
			return err
		}
	}

	return nil
}

func (v *Verifier[FR, G1El, G2El, GtEl]) deriveRandomness(fs *fiatshamir.Transcript, challenge string, points ...G1El) (*emulated.Element[FR], error) {
	var fr FR
	for i := range points {
		if err := fs.Bind(challenge, v.curve.MarshalG1(points[i])); err != nil {
			return nil, fmt.Errorf("bind challenge %d: %w", i, err)
		}
	}
	b, err := fs.ComputeChallenge(challenge)
	if err != nil {
		return nil, fmt.Errorf("compute challenge: %w", err)
	}
	bbits := bits.ToBinary(v.api, b, bits.WithNbDigits(fr.Modulus().BitLen()))
	ret := v.f.FromBits(bbits...)
	return ret, nil
}

func (v *Verifier[FR, G1El, G2El, GtEl]) fixedExpN(n uint64, s *emulated.Element[FR]) *emulated.Element[FR] {
	nlen := stdbits.Len64(n)
	res := s
	for i := 1; i < nlen; i++ {
		res = v.f.Mul(res, res)
	}
	return res
}
