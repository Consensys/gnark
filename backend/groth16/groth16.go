package groth16

import (
	"errors"

	backend_bls377 "github.com/consensys/gnark/backend/bls377"
	backend_bls381 "github.com/consensys/gnark/backend/bls381"
	backend_bn256 "github.com/consensys/gnark/backend/bn256"
	backend_bw761 "github.com/consensys/gnark/backend/bw761"
	"github.com/consensys/gnark/encoding/gob"
	"github.com/consensys/gurvy"

	groth16_bls377 "github.com/consensys/gnark/backend/bls377/groth16"
	groth16_bls381 "github.com/consensys/gnark/backend/bls381/groth16"
	groth16_bn256 "github.com/consensys/gnark/backend/bn256/groth16"
	groth16_bw761 "github.com/consensys/gnark/backend/bw761/groth16"
	"github.com/consensys/gnark/backend/r1cs"
)

type Groth16 interface {
	Setup(r1cs.R1CS) (ProvingKey, VerifyingKey)
	Prove(r1cs.R1CS, ProvingKey, map[string]interface{}) (Proof, error)
	Verify(Proof, VerifyingKey, map[string]interface{}) error
}

type Proof interface{}

type ProvingKey interface {
	IsDifferent(interface{}) bool
}

type VerifyingKey interface {
	IsDifferent(interface{}) bool
}

// var tBN256 = reflect.TypeOf(backend_bn256.R1CS{})
// var tBLS381 = reflect.TypeOf(backend_bls381.R1CS{})
// var tBLS377 = reflect.TypeOf(backend_bls377.R1CS{})
// var tBW761 = reflect.TypeOf(backend_bw761.R1CS{})

func Verify(proof Proof, vk VerifyingKey, solution map[string]interface{}) error {
	// TODO change Verify signature in Groth16 so that it returns an error = nil if verify failed
	switch _proof := proof.(type) {
	case *groth16_bls377.Proof:
		res, err := groth16_bls377.Verify(_proof, vk.(*groth16_bls377.VerifyingKey), solution)
		if err != nil {
			return err
		} else {
			if !res {
				return errors.New("verify proof failed")
			}
		}
		return nil
	case *groth16_bls381.Proof:
		res, err := groth16_bls381.Verify(_proof, vk.(*groth16_bls381.VerifyingKey), solution)
		if err != nil {
			return err
		} else {
			if !res {
				return errors.New("verify proof failed")
			}
		}
		return nil
	case *groth16_bn256.Proof:
		res, err := groth16_bn256.Verify(_proof, vk.(*groth16_bn256.VerifyingKey), solution)
		if err != nil {
			return err
		} else {
			if !res {
				return errors.New("verify proof failed")
			}
		}
		return nil
	case *groth16_bw761.Proof:
		res, err := groth16_bw761.Verify(_proof, vk.(*groth16_bw761.VerifyingKey), solution)
		if err != nil {
			return err
		} else {
			if !res {
				return errors.New("verify proof failed")
			}
		}
		return nil
	default:
		panic("unrecognized R1CS curve type")
	}
}

func Prove(r1cs r1cs.R1CS, pk ProvingKey, solution map[string]interface{}) (Proof, error) {

	switch _r1cs := r1cs.(type) {
	case *backend_bls377.R1CS:
		return groth16_bls377.Prove(_r1cs, pk.(*groth16_bls377.ProvingKey), solution)
	case *backend_bls381.R1CS:
		return groth16_bls381.Prove(_r1cs, pk.(*groth16_bls381.ProvingKey), solution)
	case *backend_bn256.R1CS:
		return groth16_bn256.Prove(_r1cs, pk.(*groth16_bn256.ProvingKey), solution)
	case *backend_bw761.R1CS:
		return groth16_bw761.Prove(_r1cs, pk.(*groth16_bw761.ProvingKey), solution)
	default:
		panic("unrecognized R1CS curve type")
	}
}

func Setup(r1cs r1cs.R1CS) (ProvingKey, VerifyingKey) {

	switch _r1cs := r1cs.(type) {
	case *backend_bls377.R1CS:
		var pk groth16_bls377.ProvingKey
		var vk groth16_bls377.VerifyingKey
		groth16_bls377.Setup(_r1cs, &pk, &vk)
		return &pk, &vk
	case *backend_bls381.R1CS:
		var pk groth16_bls381.ProvingKey
		var vk groth16_bls381.VerifyingKey
		groth16_bls381.Setup(_r1cs, &pk, &vk)
		return &pk, &vk
	case *backend_bn256.R1CS:
		var pk groth16_bn256.ProvingKey
		var vk groth16_bn256.VerifyingKey
		groth16_bn256.Setup(_r1cs, &pk, &vk)
		return &pk, &vk
	case *backend_bw761.R1CS:
		var pk groth16_bw761.ProvingKey
		var vk groth16_bw761.VerifyingKey
		groth16_bw761.Setup(_r1cs, &pk, &vk)
		return &pk, &vk
	default:
		panic("unrecognized R1CS curve type")
	}
}

// ReadProvingKey
// TODO likely temporary method, need a clean up pass on serialization things
func ReadProvingKey(path string) (ProvingKey, error) {
	curveID, err := gob.PeekCurveID(path)
	if err != nil {
		return nil, err
	}
	var pk ProvingKey
	switch curveID {
	case gurvy.BN256:
		pk = &groth16_bn256.ProvingKey{}
	case gurvy.BLS377:
		pk = &groth16_bls377.ProvingKey{}
	case gurvy.BLS381:
		pk = &groth16_bls381.ProvingKey{}
	case gurvy.BW761:
		pk = &groth16_bw761.ProvingKey{}
	default:
		panic("not implemented")
	}

	if err := gob.Read(path, pk, curveID); err != nil {
		return nil, err
	}
	return pk, err
}

// ReadVerifyingKey
// TODO likely temporary method, need a clean up pass on serialization things
func ReadVerifyingKey(path string) (VerifyingKey, error) {
	curveID, err := gob.PeekCurveID(path)
	if err != nil {
		return nil, err
	}
	var vk VerifyingKey
	switch curveID {
	case gurvy.BN256:
		vk = &groth16_bn256.VerifyingKey{}
	case gurvy.BLS377:
		vk = &groth16_bls377.VerifyingKey{}
	case gurvy.BLS381:
		vk = &groth16_bls381.VerifyingKey{}
	case gurvy.BW761:
		vk = &groth16_bw761.VerifyingKey{}
	default:
		panic("not implemented")
	}

	if err := gob.Read(path, vk, curveID); err != nil {
		return nil, err
	}
	return vk, err
}

// ReadProof
// TODO likely temporary method, need a clean up pass on serialization things
func ReadProof(path string) (Proof, error) {
	curveID, err := gob.PeekCurveID(path)
	if err != nil {
		return nil, err
	}
	var proof Proof
	switch curveID {
	case gurvy.BN256:
		proof = &groth16_bn256.Proof{}
	case gurvy.BLS377:
		proof = &groth16_bls377.Proof{}
	case gurvy.BLS381:
		proof = &groth16_bls381.Proof{}
	case gurvy.BW761:
		proof = &groth16_bw761.Proof{}
	default:
		panic("not implemented")
	}

	if err := gob.Read(path, proof, curveID); err != nil {
		return nil, err
	}
	return proof, err
}
