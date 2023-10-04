package kzg

import (
	"fmt"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	kzg_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/kzg"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
)

type Commitment[G1El algebra.G1ElementT] struct {
	G1El G1El
}

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
	default:
		return ret, fmt.Errorf("unknown type parametrization")
	}
	return ret, nil
}

type OpeningProof[S algebra.ScalarT, G1El algebra.G1ElementT] struct {
	QuotientPoly G1El
	ClaimedValue S
	Point        S
}

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
	default:
		return ret, fmt.Errorf("unknown type parametrization")
	}
	return ret, nil
}

type SRS[G2El algebra.G2ElementT] struct {
	SRS [2]G2El
}

func ValueOfSRS[G2El algebra.G2ElementT](srs any) (SRS[G2El], error) {
	var ret SRS[G2El]
	switch s := any(&ret).(type) {
	case *SRS[sw_bn254.G2Affine]:
		tSrs, ok := srs.(*kzg_bn254.SRS)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, srs)
		}
		s.SRS[0] = sw_bn254.NewG2Affine(tSrs.Vk.G2[0])
		s.SRS[1] = sw_bn254.NewG2Affine(tSrs.Vk.G2[1])
	case *SRS[sw_bls12377.G2Affine]:
		tSrs, ok := srs.(*kzg_bls12377.SRS)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, srs)
		}
		s.SRS[0] = sw_bls12377.NewG2Affine(tSrs.Vk.G2[0])
		s.SRS[1] = sw_bls12377.NewG2Affine(tSrs.Vk.G2[1])
	default:
		return ret, fmt.Errorf("unknown type parametrization")
	}
	return ret, nil
}

type Verifier[S algebra.ScalarT, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.G2ElementT] struct {
	SRS[G2El]

	curve   algebra.Curve[S, G1El]
	pairing algebra.Pairing[G1El, G2El, GtEl]
}

func NewVerifier[S algebra.ScalarT, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.G2ElementT](srs SRS[G2El], curve algebra.Curve[S, G1El], pairing algebra.Pairing[G1El, G2El, GtEl]) *Verifier[S, G1El, G2El, GtEl] {
	return &Verifier[S, G1El, G2El, GtEl]{
		SRS:     srs,
		curve:   curve,
		pairing: pairing,
	}
}

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
	if err := vk.pairing.PairingCheck(
		[]*G1El{totalG1, negQuotientPoly},
		[]*G2El{&vk.SRS.SRS[0], &vk.SRS.SRS[1]},
	); err != nil {
		return fmt.Errorf("pairing check: %w", err)
	}
	return nil
}
