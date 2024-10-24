package zeknox_bn254

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/okx/cryptography_cuda/wrappers/go/device"
)

type deviceInfo struct {
	G1Device struct {
		A, B, K, Z DevicePoints[bn254.G1Affine]
	}
	G2Device struct {
		B DevicePoints[bn254.G2Affine]
	}
	InfinityPointIndicesK []int
}

type ProvingKey struct {
	groth16_bn254.ProvingKey
	*deviceInfo
}

type DevicePoints[T bn254.G1Affine | bn254.G2Affine] struct {
	*device.HostOrDeviceSlice[T]
	// Gnark points are in Montgomery form
	// After 1 GPU MSM, points in GPU are converted to affine form
	// Pass it to MSM config
	ArePointsInMont bool
}

func Setup(r1cs *cs.R1CS, pk *ProvingKey, vk *groth16_bn254.VerifyingKey) error {
	return groth16_bn254.Setup(r1cs, &pk.ProvingKey, vk)
}

func DummySetup(r1cs *cs.R1CS, pk *ProvingKey) error {
	return groth16_bn254.DummySetup(r1cs, &pk.ProvingKey)
}

// You should call this method to free the GPU memory
//
// pk := groth16.NewProvingKey(ecc.BN254)
// defer pk.(*zeknox_bn254.ProvingKey).Free()
func (pk *ProvingKey) Free() {
	if pk.deviceInfo != nil {
		pk.deviceInfo.G1Device.A.Free()
		pk.deviceInfo.G1Device.B.Free()
		pk.deviceInfo.G1Device.K.Free()
		pk.deviceInfo.G1Device.Z.Free()
		pk.deviceInfo.G2Device.B.Free()
	}
}