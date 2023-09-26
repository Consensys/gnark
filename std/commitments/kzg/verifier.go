package kzg

import (
	"fmt"

	"github.com/consensys/gnark/std/algebra"
)

type Verifier[Scalar any, G1El any, G2El any, GtEl any] struct {
	SRS [2]G2El

	curve   algebra.Curve[Scalar, G1El]
	pairing algebra.Pairing[G1El, G2El, GtEl]
}

func NewVerifier[Scalar any, G1El any, G2El any, GtEl any](SRS [2]G2El, curve algebra.Curve[Scalar, G1El], pairing algebra.Pairing[G1El, G2El, GtEl]) *Verifier[Scalar, G1El, G2El, GtEl] {
	return &Verifier[Scalar, G1El, G2El, GtEl]{
		SRS:     SRS,
		curve:   curve,
		pairing: pairing,
	}
}

type Commitment[G1El any] struct {
	G1El G1El
}

type OpeningProof[Scalar any, G1El any] struct {
	QuotientPoly G1El
	ClaimedValue Scalar
	Point        Scalar
}

func (vk *Verifier[Scalar, G1El, G2El, GtEl]) AssertProof(commitment Commitment[G1El], proof OpeningProof[Scalar, G1El]) error {
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
		[]*G2El{&vk.SRS[0], &vk.SRS[1]},
	); err != nil {
		return fmt.Errorf("pairing check: %w", err)
	}
	return nil
}
