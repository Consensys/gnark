//go:build cuda

package plonk

import (
	"hash"
	"math/big"
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

// gpuEvalBlindedMaybe computes blinded_wire(ζ) = wire(ζ) + bp(ζ)·(ζⁿ−1) using the
// device-resident canonical wire (getPoly(id)) instead of the host s.x[id] — so the wires
// never need to come back to the host for the linearized poly's l/r/o(ζ). bpCoeffs is the
// blinding poly's coefficients. Returns false to fall back to the host evaluateBlinded.
func (s *instance) gpuEvalBlindedMaybe(id int, bpEvalAtZeta fr.Element, zeta fr.Element) (fr.Element, bool) {
	var res fr.Element
	if !s.residentOpenings() {
		return res, false
	}
	select {
	case <-s.ctx.Done():
		return res, false
	case <-s.chRestoreLRO:
	}
	dWire := s.gpuCtx.getPoly(id)
	if dWire == nil {
		return res, false
	}
	n := int(s.domain0.Cardinality)
	dPoint := gpu.Malloc(32)
	if dPoint == nil {
		return res, false
	}
	defer gpu.Free(dPoint)
	if err := gpu.MemcpyH2D(dPoint, unsafe.Pointer(&zeta), 32); err != nil {
		return res, false
	}
	wEval, err := gpu.PolyEvalDevice(dWire, n, dPoint)
	if err != nil {
		return res, false
	}
	// blinded(ζ) = wire(ζ) + bp(ζ)·(ζⁿ − 1)
	var t, one fr.Element
	one.SetOne()
	t.Exp(zeta, big.NewInt(int64(n))).Sub(&t, &one)
	t.Mul(&t, &bpEvalAtZeta)
	wEval.Add(&wEval, &t)
	return wEval, true
}

func (s *instance) residentOpenings() bool {
	return p2OpeningsEnabled() && s.gpuCtx != nil && !s.opt.StatisticalZK &&
		os.Getenv("GNARK_DISABLE_RESIDENT_OPENINGS") == ""
}

// gpuBatchOpenResidentMaybe opens batchOpening's polynomials entirely from device-resident
// handles: the wires + S1/S2 are the canonical buffers left in gpuCtx by the restore (no
// host download needed), blinded on-device; only the linearized poly + Qcp are uploaded.
// polysToOpen is used solely for the GNARK_P2_OPENINGS_SHADOW byte-check (valid only while
// the host download is still on). Returns false to fall back to the host/upload paths.
func (s *instance) gpuBatchOpenResidentMaybe(polysToOpen [][]fr.Element, digests []curve.G1Affine, point fr.Element, hf hash.Hash, pk kzg.ProvingKey, dataTranscript ...[]byte) (kzg.BatchOpeningProof, bool) {
	if !s.residentOpenings() {
		return kzg.BatchOpeningProof{}, false
	}
	// the wire/S1/S2 buffers are canonical only after the restore goroutine finishes
	select {
	case <-s.ctx.Done():
		return kzg.BatchOpeningProof{}, false
	case <-s.chRestoreLRO:
	}
	dev, err := p2.NewDevice()
	if err != nil {
		return kzg.BatchOpeningProof{}, false
	}
	n := int(s.domain0.Cardinality)
	var owned []*p2.FrVector
	defer func() {
		for _, v := range owned {
			v.Free()
		}
	}()
	upload := func(coeffs []fr.Element) (residentPoly, bool) {
		if len(coeffs) == 0 {
			return residentPoly{}, true
		}
		v, e := dev.NewFrVector(len(coeffs))
		if e != nil {
			return residentPoly{}, false
		}
		owned = append(owned, v)
		if e := v.CopyFromHost(coeffs); e != nil {
			return residentPoly{}, false
		}
		return residentPoly{ptr: v.Ptr(), n: len(coeffs)}, true
	}
	blind := func(id int, bpCoeffs []fr.Element) (residentPoly, bool) {
		dWire := s.gpuCtx.getPoly(id)
		if dWire == nil {
			return residentPoly{}, false
		}
		v, e := blindResidentWire(dev, dWire, n, bpCoeffs)
		if e != nil {
			return residentPoly{}, false
		}
		owned = append(owned, v)
		return residentPoly{ptr: v.Ptr(), n: v.Len()}, true
	}
	qcp := coefficients(s.trace.Qcp)
	polys := make([]residentPoly, 6+len(qcp))
	var o bool
	if polys[0], o = upload(s.linearizedPolynomial); !o {
		return kzg.BatchOpeningProof{}, false
	}
	if polys[1], o = blind(id_L, s.bp[id_Bl].Coefficients()); !o {
		return kzg.BatchOpeningProof{}, false
	}
	if polys[2], o = blind(id_R, s.bp[id_Br].Coefficients()); !o {
		return kzg.BatchOpeningProof{}, false
	}
	if polys[3], o = blind(id_O, s.bp[id_Bo].Coefficients()); !o {
		return kzg.BatchOpeningProof{}, false
	}
	polys[4] = residentPoly{ptr: s.gpuCtx.getPoly(id_S1), n: n}
	polys[5] = residentPoly{ptr: s.gpuCtx.getPoly(id_S2), n: n}
	if polys[4].ptr == nil || polys[5].ptr == nil {
		return kzg.BatchOpeningProof{}, false
	}
	for i := range qcp {
		if polys[6+i], o = upload(qcp[i]); !o {
			return kzg.BatchOpeningProof{}, false
		}
	}
	res, err := gpuBatchOpenResident(polys, digests, point, hf, pk, dataTranscript...)
	if err != nil {
		return kzg.BatchOpeningProof{}, false
	}
	if os.Getenv("GNARK_P2_OPENINGS_SHADOW") != "" {
		if ref, e := kzg.BatchOpenSinglePoint(polysToOpen, digests, point, hf, pk, dataTranscript...); e == nil {
			mism := !res.H.Equal(&ref.H)
			for i := range res.ClaimedValues {
				if i < len(ref.ClaimedValues) && !res.ClaimedValues[i].Equal(&ref.ClaimedValues[i]) {
					mism = true
				}
			}
			if mism {
				traceProvef("[P2 RESIDENT OPEN SHADOW] MISMATCH — using CPU\n")
				return ref, true
			}
			traceProvef("[P2 RESIDENT OPEN SHADOW] match\n")
		}
	}
	return res, true
}

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

// blindResidentWire builds the blinded wire on device (length n+len(bp)) from the resident
// canonical wire dWire (length n) and the host blinding poly bp, matching getBlindedCoefficients:
//
//	blinded = wire ++ bp ; blinded[i] -= bp[i] for i < len(bp).
//
// The low/high len(bp) coefficients (len(bp)≤3) are patched via a tiny host round-trip.
func blindResidentWire(dev *p2.Device, dWire unsafe.Pointer, n int, bp []fr.Element) (*p2.FrVector, error) {
	lbp := len(bp)
	v, err := dev.NewFrVector(n + lbp)
	if err != nil {
		return nil, err
	}
	if err := gpu.MemcpyD2D(v.Ptr(), dWire, n*32); err != nil {
		v.Free()
		return nil, err
	}
	lo := make([]fr.Element, lbp)
	if err := gpu.MemcpyD2H(unsafe.Pointer(&lo[0]), dWire, lbp*32); err != nil {
		v.Free()
		return nil, err
	}
	hi := make([]fr.Element, lbp)
	for i := 0; i < lbp; i++ {
		lo[i].Sub(&lo[i], &bp[i]) // blinded[i] = wire[i] - bp[i]
		hi[i].Set(&bp[i])         // blinded[n+i] = bp[i]
	}
	if err := gpu.MemcpyH2D(v.Ptr(), unsafe.Pointer(&lo[0]), lbp*32); err != nil {
		v.Free()
		return nil, err
	}
	if err := gpu.MemcpyH2D(unsafe.Add(v.Ptr(), n*32), unsafe.Pointer(&hi[0]), lbp*32); err != nil {
		v.Free()
		return nil, err
	}
	return v, nil
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
