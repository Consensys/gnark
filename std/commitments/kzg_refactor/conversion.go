package kzg_refactor

import (
	"fmt"

	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"

	kzg_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/kzg"
	kzg_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	kzg_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/kzg"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	kzg_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/kzg"

	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/algebra/native/sw_bls24315"
	"github.com/consensys/gnark/std/math/emulated"
)

// ValueOfScalar initializes a scalar in a witness from a native scalar (Fr) point.
// The scalars are always emulated.
func ValueOfScalar[S emulated.FieldParams](scalar any) (emulated.Element[S], error) {
	var ret emulated.Element[S]
	switch s := any(&ret).(type) {
	case *emulated.Element[emulated.BN254Fr]:
		tScalar, ok := scalar.(fr_bn254.Element)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, tScalar)
		}
		*s = sw_bn254.NewScalar(tScalar)
	case *emulated.Element[emulated.BW6761Fr]:
		tScalar, ok := scalar.(fr_bw6761.Element)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, tScalar)
		}
		*s = sw_bw6761.NewScalar(tScalar)
	case *emulated.Element[emulated.BLS12381Fr]:
		tScalar, ok := scalar.(fr_bls12381.Element)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, tScalar)
		}
		*s = sw_bls12381.NewScalar(tScalar)
	default:
		return ret, fmt.Errorf("unknown type parametrization")
	}
	return ret, nil

}

// ValueOfCommitment initializes a KZG commitment witness from a native
// commitment. It returns an error if there is a conflict between the type
// parameters and provided native commitment type.
func ValueOfCommitment[G1El any](cmt any) (Commitment[G1El], error) {
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

func ValueOfBatchOpeningProof[S emulated.FieldParams, G1El any](proof any) (BatchOpeningProof[S, G1El], error) {

	var ret BatchOpeningProof[S, G1El]
	switch s := any(&ret).(type) {
	case *BatchOpeningProof[emulated.BN254Fr, sw_bn254.G1Affine]:
		tProof, ok := proof.(kzg_bn254.BatchOpeningProof)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, proof)
		}
		s.Quotient = sw_bn254.NewG1Affine(tProof.H)
		s.ClaimedValues = make([]emulated.Element[emulated.BN254Fr], len(tProof.ClaimedValues))
		for i := 0; i < len(s.ClaimedValues); i++ {
			s.ClaimedValues[i] = sw_bn254.NewScalar(tProof.ClaimedValues[i])
		}
	case *BatchOpeningProof[emulated.BLS12381Fr, sw_bls12381.G1Affine]:
		tProof, ok := proof.(kzg_bls12381.BatchOpeningProof)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, proof)
		}
		s.Quotient = sw_bls12381.NewG1Affine(tProof.H)
		s.ClaimedValues = make([]emulated.Element[emulated.BLS12381Fr], len(tProof.ClaimedValues))
		for i := 0; i < len(s.ClaimedValues); i++ {
			s.ClaimedValues[i] = sw_bls12381.NewScalar(tProof.ClaimedValues[i])
		}
	case *BatchOpeningProof[emulated.BW6761Fr, sw_bw6761.G1Affine]:
		tProof, ok := proof.(kzg_bw6761.BatchOpeningProof)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, proof)
		}
		s.Quotient = sw_bw6761.NewG1Affine(tProof.H)
		s.ClaimedValues = make([]emulated.Element[emulated.BW6761Fr], len(tProof.ClaimedValues))
		for i := 0; i < len(s.ClaimedValues); i++ {
			s.ClaimedValues[i] = sw_bw6761.NewScalar(tProof.ClaimedValues[i])
		}
	default:
		return ret, fmt.Errorf("unknown type parametrization")
	}
	return ret, nil
}

// ValueOfOpeningProof initializes an opening proof from the given proof and
// point. It returns an error if there is a mismatch between the type parameters
// and types of the provided point and proof.
func ValueOfOpeningProof[S emulated.FieldParams, G1El any](proof any) (OpeningProof[S, G1El], error) {
	var ret OpeningProof[S, G1El]
	switch s := any(&ret).(type) {
	case *OpeningProof[emulated.BN254Fr, sw_bn254.G1Affine]:
		tProof, ok := proof.(kzg_bn254.OpeningProof)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, proof)
		}
		s.Quotient = sw_bn254.NewG1Affine(tProof.H)
		s.ClaimedValue = sw_bn254.NewScalar(tProof.ClaimedValue)

	// TODO implement BLS12377FR emulated
	// case *OpeningProof[emulated.BLS12377FR, sw_bls12377.G1Affine]:
	// 	tProof, ok := proof.(kzg_bls12377.OpeningProof)
	// 	if !ok {
	// 		return ret, fmt.Errorf("mismatching types %T %T", ret, proof)
	// 	}
	// 	s.Quotient = sw_bls12377.NewG1Affine(tProof.H)
	// 	s.ClaimedValue = tProof.ClaimedValue.String()
	case *OpeningProof[emulated.BLS12381Fr, sw_bls12381.G1Affine]:
		tProof, ok := proof.(kzg_bls12381.OpeningProof)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, proof)
		}
		s.Quotient = sw_bls12381.NewG1Affine(tProof.H)
		s.ClaimedValue = sw_bls12381.NewScalar(tProof.ClaimedValue)
	case *OpeningProof[emulated.BW6761Fr, sw_bw6761.G1Affine]:
		tProof, ok := proof.(kzg_bw6761.OpeningProof)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, proof)
		}
		s.Quotient = sw_bw6761.NewG1Affine(tProof.H)
		s.ClaimedValue = sw_bw6761.NewScalar(tProof.ClaimedValue)

	// TODO implement BLS24315FR emulated
	// case *OpeningProof[emulated.BLS24315, sw_bls24315.G1Affine]:
	// 	tProof, ok := proof.(kzg_bls24315.OpeningProof)
	// 	if !ok {
	// 		return ret, fmt.Errorf("mismatching types %T %T", ret, proof)
	// 	}
	// 	s.Quotient = sw_bls24315.NewG1Affine(tProof.H)
	// 	s.ClaimedValue = tProof.ClaimedValue.String()

	default:
		return ret, fmt.Errorf("unknown type parametrization")
	}
	return ret, nil
}

// ValueOfVerifyingKey initializes verifying key witness from the native
// verifying key. It returns an error if there is a mismatch between the type
// parameters and the provided verifying key type.
func ValueOfVerifyingKey[G1El, G2El any](vk any) (VerifyingKey[G1El, G2El], error) {
	var ret VerifyingKey[G1El, G2El]
	switch s := any(&ret).(type) {
	case *VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine]:
		tVk, ok := vk.(kzg_bn254.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, vk)
		}
		s.G1 = sw_bn254.NewG1Affine(tVk.G1)
		s.G2[0] = sw_bn254.NewG2Affine(tVk.G2[0])
		s.G2[1] = sw_bn254.NewG2Affine(tVk.G2[1])
	case *VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine]:
		tVk, ok := vk.(kzg_bls12377.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, vk)
		}
		s.G1 = sw_bls12377.NewG1Affine(tVk.G1)
		s.G2[0] = sw_bls12377.NewG2Affine(tVk.G2[0])
		s.G2[1] = sw_bls12377.NewG2Affine(tVk.G2[1])
	case *VerifyingKey[sw_bls12381.G1Affine, sw_bls12381.G2Affine]:
		tVk, ok := vk.(kzg_bls12381.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, vk)
		}
		s.G1 = sw_bls12381.NewG1Affine(tVk.G1)
		s.G2[0] = sw_bls12381.NewG2Affine(tVk.G2[0])
		s.G2[1] = sw_bls12381.NewG2Affine(tVk.G2[1])
	case *VerifyingKey[sw_bw6761.G1Affine, sw_bw6761.G2Affine]:
		tVk, ok := vk.(kzg_bw6761.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, vk)
		}
		s.G1 = sw_bw6761.NewG1Affine(tVk.G1)
		s.G2[0] = sw_bw6761.NewG2Affine(tVk.G2[0])
		s.G2[1] = sw_bw6761.NewG2Affine(tVk.G2[1])
	case *VerifyingKey[sw_bls24315.G1Affine, sw_bls24315.G2Affine]:
		tVk, ok := vk.(kzg_bls24315.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("mismatching types %T %T", ret, vk)
		}
		s.G1 = sw_bls24315.NewG1Affine(tVk.G1)
		s.G2[0] = sw_bls24315.NewG2Affine(tVk.G2[0])
		s.G2[1] = sw_bls24315.NewG2Affine(tVk.G2[1])
	default:
		return ret, fmt.Errorf("unknown type parametrization")
	}
	return ret, nil
}
