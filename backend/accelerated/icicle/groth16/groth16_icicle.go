//go:build icicle

package groth16

import (
	"fmt"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bls12377 "github.com/consensys/gnark/backend/groth16/bls12-377"
	groth16_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	groth16_bw6761 "github.com/consensys/gnark/backend/groth16/bw6-761"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs_bls12377 "github.com/consensys/gnark/constraint/bls12-377"
	cs_bls12381 "github.com/consensys/gnark/constraint/bls12-381"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	cs_bw6761 "github.com/consensys/gnark/constraint/bw6-761"
	"github.com/consensys/gnark/logger"

	icicle_bls12377 "github.com/consensys/gnark/backend/accelerated/icicle/groth16/bls12-377"
	icicle_bls12381 "github.com/consensys/gnark/backend/accelerated/icicle/groth16/bls12-381"
	icicle_bn254 "github.com/consensys/gnark/backend/accelerated/icicle/groth16/bn254"
	icicle_bw6761 "github.com/consensys/gnark/backend/accelerated/icicle/groth16/bw6-761"

	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
)

var onceWarmUpDevice sync.Once

func warmUpDevice() {
	onceWarmUpDevice.Do(func() {
		log := logger.Logger()
		err := icicle_runtime.LoadBackendFromEnvOrDefault()
		if err != icicle_runtime.Success {
			panic(fmt.Sprintf("ICICLE backend loading error: %s", err.AsString()))
		}
		device := icicle_runtime.CreateDevice("CUDA", 0)
		log.Debug().Int32("id", device.Id).Str("type", device.GetDeviceType()).Msg("ICICLE device created")
		icicle_runtime.RunOnDevice(&device, func(args ...any) {
			stream, err := icicle_runtime.CreateStream()
			if err != icicle_runtime.Success {
				panic(fmt.Sprintf("ICICLE create stream error: %s", err.AsString()))
			}
			err = icicle_runtime.WarmUpDevice(stream)
			if err != icicle_runtime.Success {
				panic(fmt.Sprintf("ICICLE device warmup error: %s", err.AsString()))
			}
		})
	})
}

func Prove(r1cs constraint.ConstraintSystem, pk groth16.ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (groth16.Proof, error) {
	switch _r1cs := r1cs.(type) {
	case *cs_bls12377.R1CS:
		return icicle_bls12377.Prove(_r1cs, pk.(*icicle_bls12377.ProvingKey), fullWitness, opts...)
	case *cs_bls12381.R1CS:
		return icicle_bls12381.Prove(_r1cs, pk.(*icicle_bls12381.ProvingKey), fullWitness, opts...)
	case *cs_bn254.R1CS:
		return icicle_bn254.Prove(_r1cs, pk.(*icicle_bn254.ProvingKey), fullWitness, opts...)
	case *cs_bw6761.R1CS:
		return icicle_bw6761.Prove(_r1cs, pk.(*icicle_bw6761.ProvingKey), fullWitness, opts...)
	default:
		panic("icicle backend requested but r1cs is not of a supported curve")
	}
}

func Setup(r1cs constraint.ConstraintSystem) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	warmUpDevice()
	switch _r1cs := r1cs.(type) {
	case *cs_bls12377.R1CS:
		var pk icicle_bls12377.ProvingKey
		var vk groth16_bls12377.VerifyingKey
		if err := groth16_bls12377.Setup(_r1cs, &pk.ProvingKey, &vk); err != nil {
			return nil, nil, err
		}
		return &pk, &vk, nil
	case *cs_bls12381.R1CS:
		var pk icicle_bls12381.ProvingKey
		var vk groth16_bls12381.VerifyingKey
		if err := groth16_bls12381.Setup(_r1cs, &pk.ProvingKey, &vk); err != nil {
			return nil, nil, err
		}
		return &pk, &vk, nil
	case *cs_bn254.R1CS:
		var pk icicle_bn254.ProvingKey
		var vk groth16_bn254.VerifyingKey
		if err := groth16_bn254.Setup(_r1cs, &pk.ProvingKey, &vk); err != nil {
			return nil, nil, err
		}
		return &pk, &vk, nil
	case *cs_bw6761.R1CS:
		var pk icicle_bw6761.ProvingKey
		var vk groth16_bw6761.VerifyingKey
		if err := groth16_bw6761.Setup(_r1cs, &pk.ProvingKey, &vk); err != nil {
			return nil, nil, err
		}
		return &pk, &vk, nil
	default:
		panic("icicle backend requested but r1cs is not of a supported curve")
	}
}

func DummySetup(r1cs constraint.ConstraintSystem) (groth16.ProvingKey, error) {
	warmUpDevice()
	switch _r1cs := r1cs.(type) {
	case *cs_bls12377.R1CS:
		var pk icicle_bls12377.ProvingKey
		if err := groth16_bls12377.DummySetup(_r1cs, &pk.ProvingKey); err != nil {
			return nil, err
		}
		return &pk, nil
	case *cs_bls12381.R1CS:
		var pk icicle_bls12381.ProvingKey
		if err := groth16_bls12381.DummySetup(_r1cs, &pk.ProvingKey); err != nil {
			return nil, err
		}
		return &pk, nil
	case *cs_bn254.R1CS:
		var pk icicle_bn254.ProvingKey
		if err := groth16_bn254.DummySetup(_r1cs, &pk.ProvingKey); err != nil {
			return nil, err
		}
		return &pk, nil
	case *cs_bw6761.R1CS:
		var pk icicle_bw6761.ProvingKey
		if err := groth16_bw6761.DummySetup(_r1cs, &pk.ProvingKey); err != nil {
			return nil, err
		}
		return &pk, nil
	default:
		panic("icicle backend requested but r1cs is not of a supported curve")
	}
}

func NewProvingKey(curveID ecc.ID) groth16.ProvingKey {
	warmUpDevice()
	switch curveID {
	case ecc.BLS12_377:
		return &icicle_bls12377.ProvingKey{}
	case ecc.BLS12_381:
		return &icicle_bls12381.ProvingKey{}
	case ecc.BN254:
		return &icicle_bn254.ProvingKey{}
	case ecc.BW6_761:
		return &icicle_bw6761.ProvingKey{}
	default:
		panic("icicle backend requested but curve is not supported")
	}
}
