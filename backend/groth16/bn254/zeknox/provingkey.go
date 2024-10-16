package zeknox_bn254

import (
	"unsafe"

	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/okx/cryptography_cuda/wrappers/go/device"
)

type deviceInfo struct {
	G1Device struct {
		A, B, K, Z *device.HostOrDeviceSlice[bn254.G1Affine]
	}
	DomainDevice struct {
		Twiddles, TwiddlesInv     unsafe.Pointer
		CosetTable, CosetTableInv unsafe.Pointer
	}
	G2Device struct {
		B *device.HostOrDeviceSlice[bn254.G2Affine]
	}
	DenDevice             unsafe.Pointer
	InfinityPointIndicesK []int
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
