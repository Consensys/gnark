//go:build js && wasm

package bls12381

import (
	"strconv"
	"sync"

	"github.com/consensys/gnark/backend/accelerated/webgpu/groth16/internal/bridge"
	"github.com/consensys/gnark/backend/accelerated/webgpu/groth16/internal/common"
	native "github.com/consensys/gnark/backend/groth16/bls12-381"
)

// ProvingKey wraps gnark's native BLS12-381 Groth16 proving key with
// browser-side cached MSM bases.
type ProvingKey struct {
	native.ProvingKey
	prepareMu      sync.Mutex
	scratchMu      sync.Mutex
	handle         string
	quotientWarmed bool
	g1AIndices     []int
	g1BIndices     []int
	scratch0       []byte
	scratch1       []byte
	scratch2       []byte
}

func (pk *ProvingKey) Prepare() error {
	pk.prepareMu.Lock()
	defer pk.prepareMu.Unlock()

	if pk.handle != "" && pk.quotientWarmed {
		return nil
	}
	if err := bridge.Bridge.Init("bls12_381"); err != nil {
		return err
	}

	if pk.handle == "" {
		payload := bridge.JSObject()
		payload.Set("g1A", bridge.JSUint8Array(packG1AffineJacobianBatch(pk.G1.A)))
		payload.Set("g1ACount", len(pk.G1.A))
		payload.Set("g1B", bridge.JSUint8Array(packG1AffineJacobianBatch(pk.G1.B)))
		payload.Set("g1BCount", len(pk.G1.B))
		payload.Set("g1K", bridge.JSUint8Array(packG1AffineJacobianBatch(pk.G1.K)))
		payload.Set("g1KCount", len(pk.G1.K))
		payload.Set("g1Z", bridge.JSUint8Array(packG1AffineJacobianBatch(pk.G1.Z)))
		payload.Set("g1ZCount", len(pk.G1.Z))
		payload.Set("g2B", bridge.JSUint8Array(packG2AffineJacobianBatch(pk.G2.B)))
		payload.Set("g2BCount", len(pk.G2.B))
		payload.Set("commitmentCount", len(pk.CommitmentKeys))
		for i := range pk.CommitmentKeys {
			suffix := strconv.Itoa(i)
			payload.Set("commitmentBasis"+suffix, bridge.JSUint8Array(packG1AffineJacobianBatch(pk.CommitmentKeys[i].Basis)))
			payload.Set("commitmentBasis"+suffix+"Count", len(pk.CommitmentKeys[i].Basis))
			payload.Set("commitmentBasisExpSigma"+suffix, bridge.JSUint8Array(packG1AffineJacobianBatch(pk.CommitmentKeys[i].BasisExpSigma)))
			payload.Set("commitmentBasisExpSigma"+suffix+"Count", len(pk.CommitmentKeys[i].BasisExpSigma))
		}

		handle, err := bridge.Bridge.PrepareKey("bls12_381", payload)
		if err != nil {
			return err
		}
		pk.handle = handle
		pk.g1AIndices = common.ComputeKeptIndices(pk.InfinityA)
		pk.g1BIndices = common.ComputeKeptIndices(pk.InfinityB)
	}
	if !pk.quotientWarmed {
		if err := bridge.Bridge.PrewarmQuotientDomain("bls12_381", int(pk.Domain.Cardinality)); err != nil {
			return err
		}
		pk.quotientWarmed = true
	}
	return nil
}
