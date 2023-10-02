package groth16

import (
	"fmt"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

type Proof[G1El algebra.G1ElementT, G2El algebra.G2ElementT] struct {
	Ar, Krs G1El
	Bs      G2El
}

type VerifyingKey[G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	E GtEl

	G2 struct {
		GammaNeg, DeltaNeg G2El
	}

	G1 struct {
		K []G1El
	}
}

type Witness[S algebra.ScalarT] struct {
	// Public is the public inputs. The first element does not need to be one
	// wire and is added implicitly during verification.
	Public []S
}

func ValueOfWitness[S algebra.ScalarT](w witness.Witness) (Witness[S], error) {
	var ret Witness[S]
	pubw, err := w.Public()
	if err != nil {
		return ret, fmt.Errorf("get public witness: %w", err)
	}
	vec := pubw.Vector()
	switch s := any(ret.Public).(type) {
	case []emulated.Element[emparams.BN254Fr]:
		vect, ok := vec.(fr_bn254.Vector)
		if !ok {
			return ret, fmt.Errorf("type parameter mismatch: %T %T", vec, ret.Public)
		}
		for i := range vect {
			s = append(s, emulated.ValueOf[emparams.BN254Fr](vect[i]))
		}
	}
	return ret, nil
}

type Verifier[S algebra.ScalarT, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	curve   algebra.Curve[S, G1El]
	pairing algebra.Pairing[G1El, G2El, GtEl]
}

func NewVerifier[S algebra.ScalarT, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](curve algebra.Curve[S, G1El], pairing algebra.Pairing[G1El, G2El, GtEl]) *Verifier[S, G1El, G2El, GtEl] {
	return &Verifier[S, G1El, G2El, GtEl]{
		curve:   curve,
		pairing: pairing,
	}
}

func (v *Verifier[S, G1El, G2El, GtEl]) AssertProof(vk VerifyingKey[G1El, G2El, GtEl], proof Proof[G1El, G2El], witness Witness[S]) error {
	inP := make([]*G1El, len(vk.G1.K)-1) // first is for the one wire, we add it manually after MSM
	for i := range inP {
		inP[i] = &vk.G1.K[i+1]
	}
	inS := make([]*S, len(witness.Public))
	for i := range inS {
		inS[i] = &witness.Public[i]
	}
	kSum, err := v.curve.MultiScalarMul(inP, inS)
	if err != nil {
		return fmt.Errorf("multi scalar mul: %w", err)
	}
	kSum = v.curve.Add(kSum, &vk.G1.K[0])
	pairing, err := v.pairing.Pair([]*G1El{kSum, &proof.Krs, &proof.Ar}, []*G2El{&vk.G2.GammaNeg, &vk.G2.DeltaNeg, &proof.Bs})
	if err != nil {
		return fmt.Errorf("pairing: %w", err)
	}
	v.pairing.AssertIsEqual(pairing, &vk.E)
	return nil
}
