//go:build cuda

package plonk

import (
	"hash"
	"os"
	"runtime"
	"sync"
	"unsafe"

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

// gpuBatchOpenUpload uploads each (host, canonical) polynomial to device once and runs
// the whole opening on device — claimed values via on-device Horner and the γ-fold via
// on-device accumulation (gpuBatchOpenResident) — replacing the sequential host Horner
// evals + host coefficient-blend fold. Byte-identical to gpuBatchOpen.
func gpuBatchOpenUpload(polys [][]fr.Element, digests []curve.G1Affine, point fr.Element, hf hash.Hash, pk kzg.ProvingKey, dataTranscript ...[]byte) (kzg.BatchOpeningProof, error) {
	dev, err := p2.NewDevice()
	if err != nil {
		return kzg.BatchOpeningProof{}, err
	}
	vecs := make([]*p2.FrVector, 0, len(polys))
	defer func() {
		for _, v := range vecs {
			v.Free()
		}
	}()
	rp := make([]residentPoly, len(polys))
	for i := range polys {
		if len(polys[i]) == 0 {
			continue // rp[i] stays {nil,0}; eval=0, skipped in the fold
		}
		v, err := dev.NewFrVector(len(polys[i]))
		if err != nil {
			return kzg.BatchOpeningProof{}, err
		}
		vecs = append(vecs, v)
		if err := v.CopyFromHost(polys[i]); err != nil {
			return kzg.BatchOpeningProof{}, err
		}
		rp[i] = residentPoly{ptr: v.Ptr(), n: len(polys[i])}
	}
	return gpuBatchOpenResident(rp, digests, point, hf, pk, dataTranscript...)
}

// residentPoly is a device-resident polynomial (canonical coefficients) to be opened.
type residentPoly struct {
	ptr unsafe.Pointer
	n   int
}

// gpuBatchOpenResident is gpuBatchOpen for polynomials that are ALREADY device-resident
// in canonical basis (the wires after restore, S1/S2, Qcp, the linearized poly, Z): the
// claimed values come from on-device Horner (PolyEvalDevice), the γ-fold from on-device
// scalar-mul-accumulate (VecAddScalarMulDevice over the γ powers), then the usual
// KzgDivide + MSM. Only the claimed scalars + the witness point H cross the bus — the
// ~1GB wire download is never paid. Result is byte-identical to gpuBatchOpen.
func gpuBatchOpenResident(polys []residentPoly, digests []curve.G1Affine, point fr.Element, hf hash.Hash, pk kzg.ProvingKey, dataTranscript ...[]byte) (kzg.BatchOpeningProof, error) {
	var res kzg.BatchOpeningProof
	res.ClaimedValues = make([]fr.Element, len(polys))
	dev, err := p2.NewDevice()
	if err != nil {
		return res, err
	}
	// ζ on device for the Horner evaluations
	dPoint, err := dev.NewFrVector(1)
	if err != nil {
		return res, err
	}
	defer dPoint.Free()
	if err := dPoint.CopyFromHost([]fr.Element{point}); err != nil {
		return res, err
	}
	largest := 0
	for i := range polys {
		if polys[i].n > largest {
			largest = polys[i].n
		}
		if polys[i].n == 0 {
			continue // empty polynomial evaluates to 0 (the zero value)
		}
		cv, err := gpu.PolyEvalDevice(polys[i].ptr, polys[i].n, dPoint.Ptr())
		if err != nil {
			return res, err
		}
		res.ClaimedValues[i] = cv
	}
	gamma, err := gpuDeriveGamma(point, digests, res.ClaimedValues, hf, dataTranscript...)
	if err != nil {
		return res, err
	}
	// γ powers, uploaded once as a device vector so the fold reads them per-poly
	gammas := make([]fr.Element, len(polys))
	gammas[0].SetOne()
	for i := 1; i < len(polys); i++ {
		gammas[i].Mul(&gammas[i-1], &gamma)
	}
	dGammas, err := dev.NewFrVector(len(polys))
	if err != nil {
		return res, err
	}
	defer dGammas.Free()
	if err := dGammas.CopyFromHost(gammas); err != nil {
		return res, err
	}
	// folded[j] = Σᵢ γⁱ·polys[i][j], accumulated on device (shorter polys stop early)
	dFolded, err := dev.NewFrVector(largest)
	if err != nil {
		return res, err
	}
	defer dFolded.Free()
	if err := gpu.VecSetZeroDevice(dFolded.Ptr(), largest); err != nil {
		return res, err
	}
	for i := range polys {
		if polys[i].n == 0 {
			continue
		}
		dGi := unsafe.Add(dGammas.Ptr(), i*32) // fr.Element = 32 bytes
		if err := gpu.VecAddScalarMulDevice(dFolded.Ptr(), polys[i].ptr, dGi, polys[i].n); err != nil {
			return res, err
		}
	}
	q, err := dev.KzgDivide(dFolded, point)
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
