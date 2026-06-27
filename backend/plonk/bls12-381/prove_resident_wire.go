//go:build cuda

package plonk

import (
	"hash"
	"os"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	p2 "github.com/consensys/gnark/internal/gpu/bls12381/p2"
)

// Gated shadow wrappers, called from the tag-agnostic prove sites. Each computes
// the resident result and, with GNARK_P2_OPENINGS_SHADOW set, cross-checks it
// against the (fork) kzg.* path, falling back on any mismatch.

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
	if os.Getenv("GNARK_P2_OPENINGS_SHADOW") != "" {
		if ref, e := kzg.Open(p, point, pk); e == nil {
			if !res.H.Equal(&ref.H) || !res.ClaimedValue.Equal(&ref.ClaimedValue) {
				traceProvef("[P2 OPENZ SHADOW] MISMATCH — using CPU result\n")
				return ref, true
			}
			traceProvef("[P2 OPENZ SHADOW] match\n")
		}
	}
	return res, true
}

func (s *instance) gpuBatchOpenMaybe(polys [][]fr.Element, digests []curve.G1Affine, point fr.Element, hf hash.Hash, pk kzg.ProvingKey, dataTranscript ...[]byte) (kzg.BatchOpeningProof, bool) {
	if !p2OpeningsEnabled() {
		return kzg.BatchOpeningProof{}, false
	}
	res, err := gpuBatchOpen(polys, digests, point, hf, pk, dataTranscript...)
	if err != nil {
		return kzg.BatchOpeningProof{}, false
	}
	if os.Getenv("GNARK_P2_OPENINGS_SHADOW") != "" {
		if ref, e := kzg.BatchOpenSinglePoint(polys, digests, point, hf, pk, dataTranscript...); e == nil {
			mism := !res.H.Equal(&ref.H)
			for i := range res.ClaimedValues {
				if !res.ClaimedValues[i].Equal(&ref.ClaimedValues[i]) {
					mism = true
				}
			}
			if mism {
				traceProvef("[P2 BATCHOPEN SHADOW] MISMATCH — using CPU result\n")
				return ref, true
			}
			traceProvef("[P2 BATCHOPEN SHADOW] match\n")
		}
	}
	return res, true
}
