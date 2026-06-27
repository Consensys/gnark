//go:build !cuda

package plonk

import (
	"fmt"
	"hash"
	"math/big"
	"sync"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
)

// proverGPUContext is a no-op placeholder when the GPU prover is not built in
// (the //go:build cuda variant carries the real device-resident context).
type proverGPUContext struct{}

// gpuComputeNumeratorRhoLoop is unavailable without the cuda build tag; the
// caller falls back to the CPU rho-loop on the returned error.
func (s *instance) gpuComputeNumeratorRhoLoop(
	rho, n int,
	scalingVector, scalingVectorRev []fr.Element,
	twiddles0 []fr.Element,
	shifters []fr.Element,
	coset, cosetExpNm1 *fr.Element,
	bn *big.Int,
	one *fr.Element,
	buf, cres []fr.Element,
	mm uint64,
	wgBuf *sync.WaitGroup,
	nbBsbGates int,
) error {
	return fmt.Errorf("GPU not available")
}

func (s *instance) setupGPUResidentContext(n int)             {}
func (s *instance) freeGPUContext()                           {}
func (s *instance) gpuDivideAndCommitQuotient() (bool, error) { return false, nil }
func (s *instance) gpuBuildZ() ([]fr.Element, bool)           { return nil, false }
func (s *instance) gpuCommitLRO() (bool, error)               { return false, nil }
func (s *instance) prewarmGPU() error                         { return nil }

func (s *instance) residentCommitMaybe(coeffs []fr.Element, bases []curve.G1Affine) (curve.G1Affine, bool) {
	return curve.G1Affine{}, false
}
func (s *instance) gpuOpenMaybe(p []fr.Element, point fr.Element, pk kzg.ProvingKey) (kzg.OpeningProof, bool) {
	return kzg.OpeningProof{}, false
}
func (s *instance) gpuBatchOpenMaybe(polys [][]fr.Element, digests []curve.G1Affine, point fr.Element, hf hash.Hash, pk kzg.ProvingKey, dataTranscript ...[]byte) (kzg.BatchOpeningProof, bool) {
	return kzg.BatchOpeningProof{}, false
}

func (s *instance) gpuRestoreLRO(cs fr.Element) error { return nil }

func (s *instance) gpuComputeLinearizedPoly(lZeta, rZeta, oZeta, alpha, beta, gamma, zeta, zu fr.Element, qcpZeta []fr.Element, pi2Canonical [][]fr.Element, blindedZ []fr.Element, pk *ProvingKey) ([]fr.Element, bool) {
	return nil, false
}
