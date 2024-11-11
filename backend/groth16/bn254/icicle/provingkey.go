package icicle

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
	icicle_core "github.com/ingonyama-zk/icicle/v3/wrappers/golang/core"
)

type deviceInfo struct {
	CosetGenerator [fr.Limbs*2]uint32
	G1Device struct {
		A, B, K, Z icicle_core.DeviceSlice
	}
	G2Device struct {
		B icicle_core.DeviceSlice
	}
	DenDevice             icicle_core.DeviceSlice
}

type ProvingKey struct {
	groth16_bn254.ProvingKey
	*deviceInfo
}

func Setup(r1cs *cs.R1CS, pk *ProvingKey, vk *groth16_bn254.VerifyingKey) error {
	return groth16_bn254.Setup(r1cs, &pk.ProvingKey, vk)
}

func DummySetup(r1cs *cs.R1CS, pk *ProvingKey) error {
	return groth16_bn254.DummySetup(r1cs, &pk.ProvingKey)
}
