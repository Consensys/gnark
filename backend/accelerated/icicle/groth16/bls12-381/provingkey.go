//go:build icicle

package bls12381

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	groth16_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	icicle_core "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
)

type deviceInfo struct {
	CosetGenerator [fr.Limbs * 2]uint32
	G1Device       struct {
		A, B, K, Z icicle_core.DeviceSlice
	}
	G2Device struct {
		B icicle_core.DeviceSlice
	}
	DenDevice icicle_core.DeviceSlice

	CommitmentKeysDevice struct {
		Basis         []icicle_core.DeviceSlice
		BasisExpSigma []icicle_core.DeviceSlice // we compute in batch
	}
}

type ProvingKey struct {
	groth16_bls12381.ProvingKey
	*deviceInfo
}
