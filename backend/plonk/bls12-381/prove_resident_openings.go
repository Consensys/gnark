//go:build cuda

package plonk

import (
	"hash"
	"os"
	"runtime"
	"sync"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	gpu "github.com/consensys/gnark/internal/gpu/bls12381"
	p2 "github.com/consensys/gnark/internal/gpu/bls12381/p2"
)

// parallelExecute splits [0,n) across NumCPU workers — matches gnark-crypto's
// internal parallel.Execute, which the reimplemented openings must mirror to keep
// the host-side eval/fold off the critical path.
func parallelExecute(n int, work func(start, end int)) {
	nbTasks := runtime.NumCPU()
	if nbTasks > n {
		nbTasks = n
	}
	if nbTasks <= 1 {
		work(0, n)
		return
	}
	chunk := (n + nbTasks - 1) / nbTasks
	var wg sync.WaitGroup
	for start := 0; start < n; start += chunk {
		end := start + chunk
		if end > n {
			end = n
		}
		wg.Add(1)
		go func(s, e int) {
			defer wg.Done()
			work(s, e)
		}(start, end)
	}
	wg.Wait()
}

// This file reimplements the KZG commit + opening protocol on the device-resident
// p2 layer so the prover no longer routes those through gnark-crypto's hooked
// kzg/multiexp functions — the last dependency on our gnark-crypto fork. Gated by
// GNARK_P2_OPENINGS, with GNARK_P2_OPENINGS_SHADOW cross-checking byte-identity
// against the (fork) kzg.* path before the vanilla switch.

func p2OpeningsEnabled() bool {
	return gpu.Available() && os.Getenv("GNARK_DISABLE_P2") == ""
}

// evalPoly evaluates p at x by Horner (matches gnark-crypto kzg.eval).
func evalPoly(p []fr.Element, x fr.Element) fr.Element {
	var res fr.Element
	for i := len(p) - 1; i >= 0; i-- {
		res.Mul(&res, &x)
		res.Add(&res, &p[i])
	}
	return res
}

// gpuDeriveGamma is an exact replica of kzg.deriveGamma so the prover's batch-fold
// challenge matches what the verifier recomputes, byte-for-byte.
func gpuDeriveGamma(point fr.Element, digests []curve.G1Affine, claimedValues []fr.Element, hf hash.Hash, dataTranscript ...[]byte) (fr.Element, error) {
	fs := fiatshamir.NewTranscript(hf, "gamma")
	if err := fs.Bind("gamma", point.Marshal()); err != nil {
		return fr.Element{}, err
	}
	for i := range digests {
		if err := fs.Bind("gamma", digests[i].Marshal()); err != nil {
			return fr.Element{}, err
		}
	}
	for i := range claimedValues {
		if err := fs.Bind("gamma", claimedValues[i].Marshal()); err != nil {
			return fr.Element{}, err
		}
	}
	for i := 0; i < len(dataTranscript); i++ {
		if err := fs.Bind("gamma", dataTranscript[i]); err != nil {
			return fr.Element{}, err
		}
	}
	gammaByte, err := fs.ComputeChallenge("gamma")
	if err != nil {
		return fr.Element{}, err
	}
	var gamma fr.Element
	gamma.SetBytes(gammaByte)
	return gamma, nil
}

// residentCommit = MSM(bases[:len(coeffs)], coeffs) via the resident-scalar G1MSM.
func residentCommit(dev *p2.Device, coeffs []fr.Element, bases []curve.G1Affine) (curve.G1Affine, error) {
	var aff curve.G1Affine
	if len(coeffs) == 0 {
		return aff, nil
	}
	msm, err := dev.NewG1MSM(bases)
	if err != nil {
		return aff, err
	}
	v, err := dev.NewFrVector(len(coeffs))
	if err != nil {
		return aff, err
	}
	defer v.Free()
	if err := v.CopyFromHost(coeffs); err != nil {
		return aff, err
	}
	return msm.MultiExp(v)
}

// gpuOpen reimplements kzg.Open on the resident layer.
func gpuOpen(p []fr.Element, point fr.Element, pk kzg.ProvingKey) (kzg.OpeningProof, error) {
	var res kzg.OpeningProof
	res.ClaimedValue = evalPoly(p, point)
	dev, err := p2.NewDevice()
	if err != nil {
		return res, err
	}
	vf, err := dev.NewFrVector(len(p))
	if err != nil {
		return res, err
	}
	defer vf.Free()
	if err := vf.CopyFromHost(p); err != nil {
		return res, err
	}
	q, err := dev.KzgDivide(vf, point)
	if err != nil {
		return res, err
	}
	defer q.Free()
	msm, err := dev.NewG1MSM(pk.G1)
	if err != nil {
		return res, err
	}
	h, err := msm.MultiExp(q)
	if err != nil {
		return res, err
	}
	res.H.Set(&h)
	return res, nil
}

// gpuBatchOpen reimplements kzg.BatchOpenSinglePoint on the resident layer. The
// γ-fold and deriveGamma replicate gnark-crypto exactly; KzgDivide produces the
// same witness as dividePolyByXminusA (it implicitly subtracts the folded eval).
func gpuBatchOpen(polynomials [][]fr.Element, digests []curve.G1Affine, point fr.Element, hf hash.Hash, pk kzg.ProvingKey, dataTranscript ...[]byte) (kzg.BatchOpeningProof, error) {
	var res kzg.BatchOpeningProof
	res.ClaimedValues = make([]fr.Element, len(polynomials))
	largestPoly := 0
	for _, p := range polynomials {
		if len(p) > largestPoly {
			largestPoly = len(p)
		}
	}
	// claimed values: one Horner per polynomial, in parallel
	parallelExecute(len(polynomials), func(start, end int) {
		for i := start; i < end; i++ {
			res.ClaimedValues[i] = evalPoly(polynomials[i], point)
		}
	})
	gamma, err := gpuDeriveGamma(point, digests, res.ClaimedValues, hf, dataTranscript...)
	if err != nil {
		return res, err
	}
	// folded = Σᵢ γⁱ·polynomials[i], parallelized over the coefficient index
	gammas := make([]fr.Element, len(polynomials))
	gammas[0].SetOne()
	for i := 1; i < len(polynomials); i++ {
		gammas[i].Mul(&gammas[i-1], &gamma)
	}
	folded := make([]fr.Element, largestPoly)
	parallelExecute(largestPoly, func(start, end int) {
		var t fr.Element
		for j := start; j < end; j++ {
			var acc fr.Element
			for i := 0; i < len(polynomials); i++ {
				if j < len(polynomials[i]) {
					t.Mul(&polynomials[i][j], &gammas[i])
					acc.Add(&acc, &t)
				}
			}
			folded[j] = acc
		}
	})

	dev, err := p2.NewDevice()
	if err != nil {
		return res, err
	}
	vf, err := dev.NewFrVector(largestPoly)
	if err != nil {
		return res, err
	}
	defer vf.Free()
	if err := vf.CopyFromHost(folded); err != nil {
		return res, err
	}
	q, err := dev.KzgDivide(vf, point)
	if err != nil {
		return res, err
	}
	defer q.Free()
	msm, err := dev.NewG1MSM(pk.G1)
	if err != nil {
		return res, err
	}
	h, err := msm.MultiExp(q)
	if err != nil {
		return res, err
	}
	res.H.Set(&h)
	return res, nil
}
