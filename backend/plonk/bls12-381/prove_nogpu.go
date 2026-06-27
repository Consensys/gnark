//go:build !cuda

package plonk

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
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
