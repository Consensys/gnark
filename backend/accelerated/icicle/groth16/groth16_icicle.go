//go:build icicle

package groth16

import (
	"fmt"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
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

	"github.com/consensys/gnark/backend/accelerated/icicle"
)

var onceWarmUpDevice sync.Once

// warmUpDevice performs one-time initialization of the ICICLE backend and warms up all available devices.
// This function is called at the beginning of the Prove function to ensure that the devices are ready for use.
// It is safe to call this function multiple times; the initialization will only occur once.
func warmUpDevice(config *icicle.Config) {
	onceWarmUpDevice.Do(func() {
		log := logger.Logger()
		if config.BackendLibs != "" {
			err := icicle_runtime.LoadBackend(config.BackendLibs, true)
			if err != icicle_runtime.Success {
				panic(fmt.Sprintf("custom ICICLE backend loading error: %s", err.AsString()))
			}
		} else {
			err := icicle_runtime.LoadBackendFromEnvOrDefault()
			if err != icicle_runtime.Success {
				panic(fmt.Sprintf("default ICICLE backend loading error: %s", err.AsString()))
			}
		}
		nbDev, err := icicle_runtime.GetDeviceCount()
		if err != icicle_runtime.Success {
			panic(fmt.Sprintf("ICICLE get device count error: %s", err.AsString()))
		}
		log.Info().Int("nbDev", nbDev).Msg("ICICLE devices detected")
		for id := 0; id < nbDev; id++ {
			device := icicle_runtime.CreateDevice(config.Backend.String(), id)
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
		}
	})
}

// Prove generates the proof of knowledge of a r1cs with full witness (secret + public part).
//
// NB! the provided proving key must contain the device pointers required for
// the acceleration. Initialize and deserialize the proving key using
// [NewProvingKey] and the serialization methods.
func Prove(r1cs constraint.ConstraintSystem, pk groth16.ProvingKey, fullWitness witness.Witness, opts ...icicle.Option) (groth16.Proof, error) {
	config, err := icicle.NewConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("initializing config: %w", err)
	}
	warmUpDevice(config)
	switch _r1cs := r1cs.(type) {
	case *cs_bls12377.R1CS:
		return icicle_bls12377.Prove(_r1cs, pk.(*icicle_bls12377.ProvingKey), fullWitness, config)
	case *cs_bls12381.R1CS:
		return icicle_bls12381.Prove(_r1cs, pk.(*icicle_bls12381.ProvingKey), fullWitness, config)
	case *cs_bn254.R1CS:
		return icicle_bn254.Prove(_r1cs, pk.(*icicle_bn254.ProvingKey), fullWitness, config)
	case *cs_bw6761.R1CS:
		return icicle_bw6761.Prove(_r1cs, pk.(*icicle_bw6761.ProvingKey), fullWitness, config)
	default:
		panic("icicle backend requested but r1cs is not of a supported curve")
	}
}

// Setup generates a proving and verifying key for a given r1cs.
//
// The method wraps the [groth16.Setup] method, but the returned proving key
// contains device pointers for acceleration. To convert the key to a standard
// Groth16 proving key, use the serialization methods.
func Setup(r1cs constraint.ConstraintSystem) (groth16.ProvingKey, groth16.VerifyingKey, error) {
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

// DummySetup generates a dummy proving key for a given circuit. It doesn't perform
// the precomputations and thus the returned proving key cannot be used to generate
// proofs. The method is useful for development and testing purposes.
//
// The method wraps the [groth16.DummySetup] method, but the returned proving key
// contains device pointers for acceleration. To convert the key to a standard
// Groth16 proving key, use the serialization methods.
func DummySetup(r1cs constraint.ConstraintSystem) (groth16.ProvingKey, error) {
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

// NewProvingKey creates a new empty proving key for deserializing into.
//
// The method is compatible with [groth16.NewProvingKey], but returns an
// ICICLE proving key with device pointers for acceleration.
func NewProvingKey(curveID ecc.ID) groth16.ProvingKey {
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
