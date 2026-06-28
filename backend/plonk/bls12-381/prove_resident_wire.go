//go:build cuda

package plonk

import (
	"hash"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	p2 "github.com/consensys/gnark/internal/gpu/bls12381/p2"
)

// Resident wrappers, called from the tag-agnostic prove sites. Each computes the
// resident result on the device-resident p2 layer, falling back to the host path
// on any device error.

func (s *instance) residentCommitMaybe(coeffs []fr.Element, bases []curve.G1Affine) (curve.G1Affine, bool) {
	dev, err := p2.NewDevice()
	if err != nil {
		gpuFatal("residentCommitMaybe: NewDevice", err)
	}
	c, err := residentCommit(dev, coeffs, bases)
	if err != nil {
		gpuFatal("residentCommitMaybe: residentCommit", err)
	}
	return c, true
}

func (s *instance) gpuOpenMaybe(p []fr.Element, point fr.Element, pk kzg.ProvingKey) (kzg.OpeningProof, bool) {
	res, err := gpuOpen(p, point, pk)
	if err != nil {
		gpuFatal("gpuOpenMaybe: gpuOpen", err)
	}
	return res, true
}

func (s *instance) gpuBatchOpenMaybe(polys [][]fr.Element, digests []curve.G1Affine, point fr.Element, hf hash.Hash, pk kzg.ProvingKey, dataTranscript ...[]byte) (kzg.BatchOpeningProof, bool) {
	res, err := gpuBatchOpenUpload(polys, digests, point, hf, pk, dataTranscript...)
	if err != nil {
		gpuFatal("gpuBatchOpenMaybe: gpuBatchOpenUpload", err)
	}
	return res, true
}
