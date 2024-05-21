package pedersen

import (
	"fmt"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	ped_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/pedersen"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	ped_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/pedersen"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	ped_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/pedersen"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	ped_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/pedersen"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	ped_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/pedersen"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/algebra/native/sw_bls24315"
)

// ValueOfVerifyingKey returns a VerifyingKey from a native Pedersen verifying
// key. It returns an error if the input does not match the expected type. The
// method does not precompute the Miller loop lines for pairing computation, and
// allows to use different keys in-circuit.
func ValueOfVerifyingKey[G2El algebra.G2ElementT](vk any) (VerifyingKey[G2El], error) {
	var ret VerifyingKey[G2El]
	switch s := any(&ret).(type) {
	case *VerifyingKey[sw_bls12377.G2Affine]:
		tVk, ok := vk.(*ped_bls12377.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected *ped_bls12377.VerifyingKey, got %T", vk)
		}
		s.G = sw_bls12377.NewG2Affine(tVk.G)
		s.GRootSigmaNeg = sw_bls12377.NewG2Affine(tVk.GRootSigmaNeg)
	case *VerifyingKey[sw_bls12381.G2Affine]:
		tVk, ok := vk.(*ped_bls12381.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected *ped_bls12381.VerifyingKey, got %T", vk)
		}
		s.G = sw_bls12381.NewG2Affine(tVk.G)
		s.GRootSigmaNeg = sw_bls12381.NewG2Affine(tVk.GRootSigmaNeg)
	case *VerifyingKey[sw_bls24315.G2Affine]:
		tVk, ok := vk.(*ped_bls24315.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected *ped_bls24315.VerifyingKey, got %T", vk)
		}
		s.G = sw_bls24315.NewG2Affine(tVk.G)
		s.GRootSigmaNeg = sw_bls24315.NewG2Affine(tVk.GRootSigmaNeg)
	case *VerifyingKey[sw_bw6761.G2Affine]:
		tVk, ok := vk.(*ped_bw6761.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected *ped_bw6761.VerifyingKey, got %T", vk)
		}
		s.G = sw_bw6761.NewG2Affine(tVk.G)
		s.GRootSigmaNeg = sw_bw6761.NewG2Affine(tVk.GRootSigmaNeg)
	case *VerifyingKey[sw_bn254.G2Affine]:
		tVk, ok := vk.(*ped_bn254.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected *ped_bn254.VerifyingKey, got %T", vk)
		}
		s.G = sw_bn254.NewG2Affine(tVk.G)
		s.GRootSigmaNeg = sw_bn254.NewG2Affine(tVk.GRootSigmaNeg)
	default:
		panic(fmt.Sprintf("unknown parametric type: %T", s))
	}
	return ret, nil
}

// ValueOfVerifyingKeyFixed returns a VerifyingKey from a native Pedersen
// verifying key. It returns an error if the input does not match the expected
// type. The method precomputes the Miller loop lines for pairing computation,
// requiring to embed the key in-circuit at compile time.
func ValueOfVerifyingKeyFixed[G2El algebra.G2ElementT](vk any) (VerifyingKey[G2El], error) {
	var ret VerifyingKey[G2El]
	switch s := any(&ret).(type) {
	case *VerifyingKey[sw_bls12377.G2Affine]:
		tVk, ok := vk.(*ped_bls12377.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected *ped_bls12377.VerifyingKey, got %T", vk)
		}
		s.G = sw_bls12377.NewG2AffineFixed(tVk.G)
		s.GRootSigmaNeg = sw_bls12377.NewG2AffineFixed(tVk.GRootSigmaNeg)
	case *VerifyingKey[sw_bls12381.G2Affine]:
		tVk, ok := vk.(*ped_bls12381.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected *ped_bls12381.VerifyingKey, got %T", vk)
		}
		s.G = sw_bls12381.NewG2AffineFixed(tVk.G)
		s.GRootSigmaNeg = sw_bls12381.NewG2AffineFixed(tVk.GRootSigmaNeg)
	case *VerifyingKey[sw_bls24315.G2Affine]:
		tVk, ok := vk.(*ped_bls24315.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected *ped_bls24315.VerifyingKey, got %T", vk)
		}
		s.G = sw_bls24315.NewG2AffineFixed(tVk.G)
		s.GRootSigmaNeg = sw_bls24315.NewG2AffineFixed(tVk.GRootSigmaNeg)
	case *VerifyingKey[sw_bw6761.G2Affine]:
		tVk, ok := vk.(*ped_bw6761.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected *ped_bw6761.VerifyingKey, got %T", vk)
		}
		s.G = sw_bw6761.NewG2AffineFixed(tVk.G)
		s.GRootSigmaNeg = sw_bw6761.NewG2AffineFixed(tVk.GRootSigmaNeg)
	case *VerifyingKey[sw_bn254.G2Affine]:
		tVk, ok := vk.(*ped_bn254.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected *ped_bn254.VerifyingKey, got %T", vk)
		}
		s.G = sw_bn254.NewG2AffineFixed(tVk.G)
		s.GRootSigmaNeg = sw_bn254.NewG2AffineFixed(tVk.GRootSigmaNeg)
	default:
		return ret, fmt.Errorf("unknown parametric type: %T", s)
	}
	return ret, nil
}

// ValueOfCommitment returns a Commitment from a native Pedersen commitment. It
// returns an error if the input does not match the expected type.
func ValueOfCommitment[G1El algebra.G1ElementT](cmt any) (Commitment[G1El], error) {
	var ret Commitment[G1El]
	g1el, err := valueOfG1El[G1El](cmt)
	if err != nil {
		return ret, err
	}
	ret.G1El = g1el
	return ret, nil
}

// ValueOfKnowledgeProof returns a KnowledgeProof from a native Pedersen
// knowledge proof. It returns an error if the input does not match the expected
// type.
func ValueOfKnowledgeProof[G1El algebra.G1ElementT](kp any) (KnowledgeProof[G1El], error) {
	var ret KnowledgeProof[G1El]
	g1el, err := valueOfG1El[G1El](kp)
	if err != nil {
		return ret, err
	}
	ret.G1El = g1el
	return ret, nil
}

func valueOfG1El[G1El algebra.G1ElementT](el any) (G1El, error) {
	var ret G1El
	switch s := any(&ret).(type) {
	case *sw_bls12377.G1Affine:
		tEl, ok := el.(bls12377.G1Affine)
		if !ok {
			return ret, fmt.Errorf("expected bls12377.G1Affine, got %T", el)
		}
		*s = sw_bls12377.NewG1Affine(tEl)
	case *sw_bls12381.G1Affine:
		tEl, ok := el.(bls12381.G1Affine)
		if !ok {
			return ret, fmt.Errorf("expected bls12381.G1Affine, got %T", el)
		}
		*s = sw_bls12381.NewG1Affine(tEl)
	case *sw_bls24315.G1Affine:
		tEl, ok := el.(bls24315.G1Affine)
		if !ok {
			return ret, fmt.Errorf("expected bls24315.G1Affine, got %T", el)
		}
		*s = sw_bls24315.NewG1Affine(tEl)
	case *sw_bw6761.G1Affine:
		tEl, ok := el.(bw6761.G1Affine)
		if !ok {
			return ret, fmt.Errorf("expected bw6761.G1Affine, got %T", el)
		}
		*s = sw_bw6761.NewG1Affine(tEl)
	case *sw_bn254.G1Affine:
		tEl, ok := el.(bn254.G1Affine)
		if !ok {
			return ret, fmt.Errorf("expected bn254.G1Affine, got %T", el)
		}
		*s = sw_bn254.NewG1Affine(tEl)
	default:
		return ret, fmt.Errorf("unknown parametric type: %T", s)
	}
	return ret, nil
}
