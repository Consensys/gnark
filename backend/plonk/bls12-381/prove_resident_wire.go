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
	if !p2OpeningsEnabled() {
		return curve.G1Affine{}, false
	}
	dev, err := p2.NewDevice()
	if err != nil {
		return curve.G1Affine{}, false
	}
	c, err := residentCommit(dev, coeffs, bases)
	if err != nil {
		return curve.G1Affine{}, false
	}
	return c, true
}

func (s *instance) gpuOpenMaybe(p []fr.Element, point fr.Element, pk kzg.ProvingKey) (kzg.OpeningProof, bool) {
	if !p2OpeningsEnabled() {
		return kzg.OpeningProof{}, false
	}
	res, err := gpuOpen(p, point, pk)
	if err != nil {
		return kzg.OpeningProof{}, false
	}
	return res, true
}

func (s *instance) gpuBatchOpenMaybe(polys [][]fr.Element, digests []curve.G1Affine, point fr.Element, hf hash.Hash, pk kzg.ProvingKey, dataTranscript ...[]byte) (kzg.BatchOpeningProof, bool) {
	if !p2OpeningsEnabled() {
		return kzg.BatchOpeningProof{}, false
	}
	res, err := gpuBatchOpenUpload(polys, digests, point, hf, pk, dataTranscript...)
	if err != nil {
		return kzg.BatchOpeningProof{}, false
	}
	return res, true
}
