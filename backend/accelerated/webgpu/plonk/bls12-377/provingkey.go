//go:build js && wasm

// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package bls12377

import (
	"sync"

	"github.com/consensys/gnark/backend/accelerated/webgpu/plonk/internal/bridge"
	native "github.com/consensys/gnark/backend/plonk/bls12-377"
	cs "github.com/consensys/gnark/constraint/bls12-377"
)

type ProvingKey struct {
	native.ProvingKey
	prepareMu            sync.Mutex
	handle               string
	staticNumeratorCache *staticNumeratorCache
}

func (pk *ProvingKey) Prepare() error {
	pk.prepareMu.Lock()
	defer pk.prepareMu.Unlock()

	return pk.ensurePreparedLocked()
}

func (pk *ProvingKey) ensurePreparedLocked() error {
	if pk.handle != "" {
		return nil
	}
	if err := bridge.Bridge.Init("bls12_377"); err != nil {
		return err
	}
	payload := bridge.JSObject()
	payload.Set("kzg", bridge.JSUint8Array(packG1AffineJacobianBatch(pk.Kzg.G1)))
	payload.Set("kzgCount", len(pk.Kzg.G1))
	payload.Set("kzgLagrange", bridge.JSUint8Array(packG1AffineJacobianBatch(pk.KzgLagrange.G1)))
	payload.Set("kzgLagrangeCount", len(pk.KzgLagrange.G1))
	handle, err := bridge.Bridge.PrepareKey("bls12_377", payload)
	if err != nil {
		return err
	}
	pk.handle = handle
	return nil
}

func (pk *ProvingKey) PrepareWithCS(spr *cs.SparseR1CS) error {
	pk.prepareMu.Lock()
	defer pk.prepareMu.Unlock()

	if err := pk.ensurePreparedLocked(); err != nil {
		return err
	}
	domain0, domain1 := domainsForSPR(spr)
	trace := native.NewTrace(spr, domain0)
	if err := pk.ensureStaticNumeratorCache(trace, domain0, domain1); err != nil {
		return err
	}
	if err := pk.preloadQuotientStaticCaches(trace, domain0, domain1); err != nil {
		return err
	}
	if err := bridge.Bridge.PrewarmQuotientTransformDomain("bls12_377", int(domain0.Cardinality)); err != nil {
		return err
	}
	if err := bridge.Bridge.PrewarmQuotientEvaluateKernel("bls12_377", len(trace.Qcp)); err != nil {
		return err
	}
	return bridge.Bridge.PrewarmQuotientCanonicalizeDomain("bls12_377", int(domain1.Cardinality))
}
