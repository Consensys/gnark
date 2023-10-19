// Package kzg implements KZG polynomial commitment verification.
//
// KZG polynomial commitment allows for the prover to commit to a polynomial and
// then selectively prove evaluations of the said polynomial. The size of the
// commitment is a single G1 element and the size of the evaluation proof is
// also a single G1 element. However, KZG polynomial commitment scheme requires
// a trusted SRS.
//
// This package supersedes previous type-specific implementations and allows to
// use any implemented pairing-friendly curve implementation, being defined over
// a 2-chain (native implementation) or using field emulation.
package kzg

import (
	"fmt"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	kzg_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/kzg"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	kzg_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	fr_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	kzg_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/kzg"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	kzg_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/kzg"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/algebra/native/sw_bls24315"
)

// Commitment is an KZG commitment to a polynomial. Use [ValueOfCommitment] to
// initialize a witness from the native commitment.
type Commitment[G1El algebra.G1ElementT] struct {
	G1El G1El
}

// ValueOfCommitment initializes a KZG commitment witness from a native
// commitment. It returns an error if there is a conflict between the type
// parameters and provided native commitment type.
func ValueOfCommitment[G1El algebra.G1ElementT](cmt any) (Commitment[G1El], error) {
	var ret Commitment[G1El]
	switch s := any(&ret).(type) {
	case *Commitment[sw_bn254.G1Affine]:
		tCmt, ok := cmt.(bn254.G1Affine)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, cmt)
		}
		s.G1El = sw_bn254.NewG1Affine(tCmt)
	case *Commitment[sw_bls12377.G1Affine]:
		tCmt, ok := cmt.(bls12377.G1Affine)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, cmt)
		}
		s.G1El = sw_bls12377.NewG1Affine(tCmt)
	case *Commitment[sw_bls12381.G1Affine]:
		tCmt, ok := cmt.(bls12381.G1Affine)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, cmt)
		}
		s.G1El = sw_bls12381.NewG1Affine(tCmt)
	case *Commitment[sw_bw6761.G1Affine]:
		tCmt, ok := cmt.(bw6761.G1Affine)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, cmt)
		}
		s.G1El = sw_bw6761.NewG1Affine(tCmt)
	case *Commitment[sw_bls24315.G1Affine]:
		tCmt, ok := cmt.(bls24315.G1Affine)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, cmt)
		}
		s.G1El = sw_bls24315.NewG1Affine(tCmt)
	default:
		return ret, fmt.Errorf("unknown type parametrization")
	}
	return ret, nil
}

// OpeningProof embeds the opening proof that polynomial evaluated at Point is
// equal to ClaimedValue. Use [ValueOfOpeningProof] to initialize a witness from
// a native opening proof.
type OpeningProof[S algebra.ScalarT, G1El algebra.G1ElementT] struct {
	QuotientPoly G1El
	ClaimedValue S
	Point        S
}

// ValueOfOpeningProof initializes an opening proof from the given proof and
// point. It returns an error if there is a mismatch between the type parameters
// and types of the provided point and proof.
func ValueOfOpeningProof[S algebra.ScalarT, G1El algebra.G1ElementT](point any, proof any) (OpeningProof[S, G1El], error) {
	var ret OpeningProof[S, G1El]
	switch s := any(&ret).(type) {
	case *OpeningProof[sw_bn254.Scalar, sw_bn254.G1Affine]:
		tProof, ok := proof.(kzg_bn254.OpeningProof)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, proof)
		}
		tPoint, ok := point.(fr_bn254.Element)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, point)
		}
		s.QuotientPoly = sw_bn254.NewG1Affine(tProof.H)
		s.ClaimedValue = sw_bn254.NewScalar(tProof.ClaimedValue)
		s.Point = sw_bn254.NewScalar(tPoint)
	case *OpeningProof[sw_bls12377.Scalar, sw_bls12377.G1Affine]:
		tProof, ok := proof.(kzg_bls12377.OpeningProof)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, proof)
		}
		tPoint, ok := point.(fr_bls12377.Element)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, point)
		}
		s.QuotientPoly = sw_bls12377.NewG1Affine(tProof.H)
		s.ClaimedValue = tProof.ClaimedValue.String()
		s.Point = tPoint.String()
	case *OpeningProof[sw_bls12381.Scalar, sw_bls12381.G1Affine]:
		tProof, ok := proof.(kzg_bls12381.OpeningProof)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, proof)
		}
		tPoint, ok := point.(fr_bls12381.Element)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, point)
		}
		s.QuotientPoly = sw_bls12381.NewG1Affine(tProof.H)
		s.ClaimedValue = sw_bls12381.NewScalar(tProof.ClaimedValue)
		s.Point = sw_bls12381.NewScalar(tPoint)
	case *OpeningProof[sw_bw6761.Scalar, sw_bw6761.G1Affine]:
		tProof, ok := proof.(kzg_bw6761.OpeningProof)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, proof)
		}
		tPoint, ok := point.(fr_bw6761.Element)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, point)
		}
		s.QuotientPoly = sw_bw6761.NewG1Affine(tProof.H)
		s.ClaimedValue = sw_bw6761.NewScalar(tProof.ClaimedValue)
		s.Point = sw_bw6761.NewScalar(tPoint)
	case *OpeningProof[sw_bls24315.Scalar, sw_bls24315.G1Affine]:
		tProof, ok := proof.(kzg_bls24315.OpeningProof)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, proof)
		}
		tPoint, ok := point.(fr_bls24315.Element)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, point)
		}
		s.QuotientPoly = sw_bls24315.NewG1Affine(tProof.H)
		s.ClaimedValue = tProof.ClaimedValue.String()
		s.Point = tPoint.String()
	default:
		return ret, fmt.Errorf("unknown type parametrization")
	}
	return ret, nil
}

// VerifyingKey is the trusted setup for KZG polynomial commitment scheme. Use
// [ValueOfVerifyingKey] to initialize a witness from the native VerifyingKey.
type VerifyingKey[G2El algebra.G2ElementT] struct {
	SRS [2]G2El
}

// ValueOfVerifyingKey initializes verifying key witness from the native
// verifying key. It returns an error if there is a mismatch between the type
// parameters and the provided verifying key type.
func ValueOfVerifyingKey[G2El algebra.G2ElementT](vk any) (VerifyingKey[G2El], error) {
	var ret VerifyingKey[G2El]
	switch s := any(&ret).(type) {
	case *VerifyingKey[sw_bn254.G2Affine]:
		tVk, ok := vk.(kzg_bn254.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, vk)
		}
		s.SRS[0] = sw_bn254.NewG2Affine(tVk.G2[0])
		s.SRS[1] = sw_bn254.NewG2Affine(tVk.G2[1])
	case *VerifyingKey[sw_bls12377.G2Affine]:
		tVk, ok := vk.(kzg_bls12377.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, vk)
		}
		s.SRS[0] = sw_bls12377.NewG2Affine(tVk.G2[0])
		s.SRS[1] = sw_bls12377.NewG2Affine(tVk.G2[1])
	case *VerifyingKey[sw_bls12381.G2Affine]:
		tVk, ok := vk.(kzg_bls12381.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, vk)
		}
		s.SRS[0] = sw_bls12381.NewG2Affine(tVk.G2[0])
		s.SRS[1] = sw_bls12381.NewG2Affine(tVk.G2[1])
	case *VerifyingKey[sw_bw6761.G2Affine]:
		tVk, ok := vk.(kzg_bw6761.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, vk)
		}
		s.SRS[0] = sw_bw6761.NewG2Affine(tVk.G2[0])
		s.SRS[1] = sw_bw6761.NewG2Affine(tVk.G2[1])
	case *VerifyingKey[sw_bls24315.G2Affine]:
		tVk, ok := vk.(kzg_bls24315.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, vk)
		}
		s.SRS[0] = sw_bls24315.NewG2Affine(tVk.G2[0])
		s.SRS[1] = sw_bls24315.NewG2Affine(tVk.G2[1])
	default:
		return ret, fmt.Errorf("unknown type parametrization")
	}
	return ret, nil
}

// Verifier allows verifying KZG opening proofs.
type Verifier[S algebra.ScalarT, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.G2ElementT] struct {
	VerifyingKey[G2El]

	curve   algebra.Curve[S, G1El]
	pairing algebra.Pairing[G1El, G2El, GtEl]
}

// NewVerifier initializes a new Verifier instance.
func NewVerifier[S algebra.ScalarT, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.G2ElementT](vk VerifyingKey[G2El], curve algebra.Curve[S, G1El], pairing algebra.Pairing[G1El, G2El, GtEl]) *Verifier[S, G1El, G2El, GtEl] {
	return &Verifier[S, G1El, G2El, GtEl]{
		VerifyingKey: vk,
		curve:        curve,
		pairing:      pairing,
	}
}

// AssertProof asserts the validity of the opening proof for the given
// commitment.
func (vk *Verifier[S, G1El, G2El, GtEl]) AssertProof(commitment Commitment[G1El], proof OpeningProof[S, G1El]) error {
	// [f(a)]G₁
	claimedValueG1 := vk.curve.ScalarMulBase(&proof.ClaimedValue)

	// [f(α) - f(a)]G₁
	fminusfaG1 := vk.curve.Neg(claimedValueG1)
	fminusfaG1 = vk.curve.Add(fminusfaG1, &commitment.G1El)

	// [-H(α)]G₁
	negQuotientPoly := vk.curve.Neg(&proof.QuotientPoly)

	// [f(α) - f(a) + a*H(α)]G₁
	totalG1 := vk.curve.ScalarMul(&proof.QuotientPoly, &proof.Point)
	totalG1 = vk.curve.Add(totalG1, fminusfaG1)

	// e([f(α)-f(a)+aH(α)]G₁], G₂).e([-H(α)]G₁, [α]G₂) == 1
	if err := vk.pairing.DoublePairingFixedQCheck(
		[2]*G1El{totalG1, negQuotientPoly},
		&vk.SRS[1],
	); err != nil {
		return fmt.Errorf("pairing check: %w", err)
	}
	return nil
}
