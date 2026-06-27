//go:build cuda

package p2

import (
	"fmt"

	gpu "github.com/consensys/gnark/internal/gpu/bls12381"
)

// Device is the resident-prover GPU handle; its methods (NewFrVector, NewG1MSM,
// RatioBuildZ, KzgDivide) live in the sibling files. Per-stream overlap of the
// resident commits is handled directly in the prover via internal/gpu's
// async-stream MSM, not through this type.
type Device struct{}

// NewDevice selects the GPU on the calling thread and returns a Device.
func NewDevice() (*Device, error) {
	if !gpu.Available() {
		return nil, fmt.Errorf("p2: no CUDA device available")
	}
	gpu.SetDevice()
	return &Device{}, nil
}
