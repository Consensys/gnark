//go:build icicle

package bn254

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
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
	groth16_bn254.ProvingKey
	*deviceInfo
}
