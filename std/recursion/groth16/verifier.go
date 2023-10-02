package groth16

import (
	"fmt"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16backend_bls12377 "github.com/consensys/gnark/backend/groth16/bls12-377"
	groth16backend_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

type Proof[G1El algebra.G1ElementT, G2El algebra.G2ElementT] struct {
	Ar, Krs G1El
	Bs      G2El
}

func ValueOfProof[G1El algebra.G1ElementT, G2El algebra.G2ElementT](proof groth16.Proof) (Proof[G1El, G2El], error) {
	// even if we type switch we cannot returned the switched type. We have to
	// modify through pointers directly.
	var ret Proof[G1El, G2El]
	switch ar := any(&ret).(type) {
	case *Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]:
		tProof, ok := proof.(*groth16backend_bn254.Proof)
		if !ok {
			return ret, fmt.Errorf("expected bn254.Proof, got %T", proof)
		}
		ar.Ar = sw_bn254.NewG1Affine(tProof.Ar)
		ar.Krs = sw_bn254.NewG1Affine(tProof.Krs)
		ar.Bs = sw_bn254.NewG2Affine(tProof.Bs)
	case *Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]:
		tProof, ok := proof.(*groth16backend_bls12377.Proof)
		if !ok {
			return ret, fmt.Errorf("expected bls12377.Proof, got %T", proof)
		}
		ar.Ar = sw_bls12377.NewG1Affine(tProof.Ar)
		ar.Krs = sw_bls12377.NewG1Affine(tProof.Krs)
		ar.Bs = sw_bls12377.NewG2Affine(tProof.Bs)
	default:
		return ret, fmt.Errorf("unknown parametric type combination")
	}
	return ret, nil
}

type VerifyingKey[G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	E  GtEl
	G1 struct{ K []G1El }
	G2 struct{ GammaNeg, DeltaNeg G2El }
}

func (vk *VerifyingKey[G1El, G2El, GtEl]) ToPlaceholder() VerifyingKey[G1El, G2El, GtEl] {
	return VerifyingKey[G1El, G2El, GtEl]{
		G1: struct{ K []G1El }{
			K: make([]G1El, len(vk.G1.K)),
		},
	}
}

func ValueOfVerifyingKey[G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](vk groth16.VerifyingKey) (VerifyingKey[G1El, G2El, GtEl], error) {
	var ret VerifyingKey[G1El, G2El, GtEl]
	switch s := any(&ret).(type) {
	case *VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]:
		tVk, ok := vk.(*groth16backend_bn254.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected bn254.VerifyingKey, got %T", vk)
		}
		// compute E
		e, err := bn254.Pair([]bn254.G1Affine{tVk.G1.Alpha}, []bn254.G2Affine{tVk.G2.Beta})
		if err != nil {
			return ret, fmt.Errorf("precompute pairing: %w", err)
		}
		s.E = sw_bn254.NewGTEl(e)
		s.G1.K = make([]sw_bn254.G1Affine, len(tVk.G1.K))
		for i := range s.G1.K {
			s.G1.K[i] = sw_bn254.NewG1Affine(tVk.G1.K[i])
		}
		var deltaNeg, gammaNeg bn254.G2Affine
		deltaNeg.Neg(&tVk.G2.Delta)
		gammaNeg.Neg(&tVk.G2.Gamma)
		s.G2.DeltaNeg = sw_bn254.NewG2Affine(deltaNeg)
		s.G2.GammaNeg = sw_bn254.NewG2Affine(gammaNeg)
	case *VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]:
		tVk, ok := vk.(*groth16backend_bls12377.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected bn254.VerifyingKey, got %T", vk)
		}
		// compute E
		e, err := bls12377.Pair([]bls12377.G1Affine{tVk.G1.Alpha}, []bls12377.G2Affine{tVk.G2.Beta})
		if err != nil {
			return ret, fmt.Errorf("precompute pairing: %w", err)
		}
		s.E = sw_bls12377.NewGTEl(e)
		s.G1.K = make([]sw_bls12377.G1Affine, len(tVk.G1.K))
		for i := range s.G1.K {
			s.G1.K[i] = sw_bls12377.NewG1Affine(tVk.G1.K[i])
		}
		var deltaNeg, gammaNeg bls12377.G2Affine
		deltaNeg.Neg(&tVk.G2.Delta)
		gammaNeg.Neg(&tVk.G2.Gamma)
		s.G2.DeltaNeg = sw_bls12377.NewG2Affine(deltaNeg)
		s.G2.GammaNeg = sw_bls12377.NewG2Affine(gammaNeg)
	default:
		return ret, fmt.Errorf("unknown parametric type combination")
	}
	return ret, nil
}

type Witness[S algebra.ScalarT] struct {
	// Public is the public inputs. The first element does not need to be one
	// wire and is added implicitly during verification.
	Public []S
}

func (w *Witness[S]) ToPlaceholder() Witness[S] {
	return Witness[S]{
		Public: make([]S, len(w.Public)),
	}
}

func ValueOfWitness[S algebra.ScalarT](w witness.Witness) (Witness[S], error) {
	var ret Witness[S]
	pubw, err := w.Public()
	if err != nil {
		return ret, fmt.Errorf("get public witness: %w", err)
	}
	vec := pubw.Vector()
	switch s := any(&ret).(type) {
	case *Witness[emulated.Element[emparams.BN254Fr]]:
		vect, ok := vec.(fr_bn254.Vector)
		if !ok {
			return ret, fmt.Errorf("expected fr_bn254.Vector, got %T", vec)
		}
		for i := range vect {
			s.Public = append(s.Public, emulated.ValueOf[emparams.BN254Fr](vect[i]))
		}
	case *Witness[sw_bls12377.Scalar]:
		vect, ok := vec.(fr_bls12377.Vector)
		if !ok {
			return ret, fmt.Errorf("expected fr_bls12377.Vector, got %T", vec)
		}
		for i := range vect {
			s.Public = append(s.Public, vect[i].String())
		}
	default:
		return ret, fmt.Errorf("unknown parametric type combination")
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
