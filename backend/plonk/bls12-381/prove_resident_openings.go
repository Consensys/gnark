//go:build cuda

package plonk

import (
	"fmt"
	"hash"
	"math/big"
	"unsafe"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	gpu "github.com/consensys/gnark/internal/gpu/bls12381"
	p2 "github.com/consensys/gnark/internal/gpu/bls12381/p2"
)

// This file reimplements the KZG commit + opening protocol on the device-resident
// p2 layer so the prover no longer routes those through gnark-crypto's hooked
// kzg/multiexp functions — the last dependency on our gnark-crypto fork.

// gpuEvalBlindedMaybe computes blinded_wire(ζ) = wire(ζ) + bp(ζ)·(ζⁿ−1) using the
// device-resident canonical wire (getPoly(id)) instead of the host s.x[id] — so the wires
// never need to come back to the host for the linearized poly's l/r/o(ζ). bpCoeffs is the
// blinding poly's coefficients. Returns false only when resident openings are not engaged
// (non-resident config or cancellation); a missing resident handle in the resident path aborts.
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
		gpuFatal("gpuEvalBlindedMaybe: resident wire missing", fmt.Errorf("getPoly(%d) returned nil in resident path", id))
	}
	n := int(s.domain0.Cardinality)
	dPoint := gpu.Malloc(32)
	if dPoint == nil {
		gpuFatal("gpuEvalBlindedMaybe: Malloc point", fmt.Errorf("GPU malloc failed"))
	}
	defer gpu.Free(dPoint)
	if err := gpu.MemcpyH2D(dPoint, unsafe.Pointer(&zeta), 32); err != nil {
		gpuFatal("gpuEvalBlindedMaybe: MemcpyH2D point", err)
	}
	wEval, err := gpu.PolyEvalDevice(dWire, n, dPoint)
	if err != nil {
		gpuFatal("gpuEvalBlindedMaybe: PolyEvalDevice", err)
	}
	// blinded(ζ) = wire(ζ) + bp(ζ)·(ζⁿ − 1)
	var t, one fr.Element
	one.SetOne()
	t.Exp(zeta, big.NewInt(int64(n))).Sub(&t, &one)
	t.Mul(&t, &bpEvalAtZeta)
	wEval.Add(&wEval, &t)
	return wEval, true
}

// gpuEvalBlindedBatchMaybe evaluates blinded_wire(ζ) = wire(ζ) + bp(ζ)·(ζⁿ−1) for several
// resident wires in ONE batched device call (shared scratch, one sync) — replacing the
// per-wire gpuEvalBlindedMaybe. bpEvals[i] is bp_i(ζ). Returns false only when resident
// openings are not engaged (non-resident config or cancellation).
func (s *instance) gpuEvalBlindedBatchMaybe(ids []int, bpEvals []fr.Element, zeta fr.Element) ([]fr.Element, bool) {
	if !s.residentOpenings() {
		return nil, false
	}
	select {
	case <-s.ctx.Done():
		return nil, false
	case <-s.chRestoreLRO:
	}
	n := int(s.domain0.Cardinality)
	ptrs := make([]unsafe.Pointer, len(ids))
	lengths := make([]int, len(ids))
	for i, id := range ids {
		if ptrs[i] = s.gpuCtx.getPoly(id); ptrs[i] == nil {
			gpuFatal("gpuEvalBlindedBatchMaybe: resident wire missing", fmt.Errorf("getPoly(%d) returned nil in resident path", id))
		}
		lengths[i] = n
	}
	dPoint := gpu.Malloc(32)
	if dPoint == nil {
		gpuFatal("gpuEvalBlindedBatchMaybe: Malloc point", fmt.Errorf("GPU malloc failed"))
	}
	defer gpu.Free(dPoint)
	if err := gpu.MemcpyH2D(dPoint, unsafe.Pointer(&zeta), 32); err != nil {
		gpuFatal("gpuEvalBlindedBatchMaybe: MemcpyH2D point", err)
	}
	vals, err := gpu.PolyEvalBatchDevice(ptrs, lengths, dPoint)
	if err != nil {
		gpuFatal("gpuEvalBlindedBatchMaybe: PolyEvalBatchDevice", err)
	}
	var t, one fr.Element
	one.SetOne()
	t.Exp(zeta, big.NewInt(int64(n))).Sub(&t, &one) // ζⁿ − 1
	for i := range vals {
		var c fr.Element
		c.Mul(&bpEvals[i], &t)
		vals[i].Add(&vals[i], &c)
	}
	return vals, true
}

func (s *instance) residentOpenings() bool {
	return s.gpuCtx != nil && !s.opt.StatisticalZK
}

// gpuBatchOpenResidentMaybe opens batchOpening's polynomials entirely from device-resident
// handles: the wires + S1/S2 are the canonical buffers left in gpuCtx by the restore (no
// host download needed), blinded on-device; only the linearized poly + Qcp are uploaded.
// Returns false only when resident openings are not engaged (non-resident config or
// cancellation); a structural miss inside the resident path aborts (host buffers are stale).
func (s *instance) gpuBatchOpenResidentMaybe(digests []curve.G1Affine, point fr.Element, hf hash.Hash, pk kzg.ProvingKey, dataTranscript ...[]byte) (kzg.BatchOpeningProof, bool) {
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
		gpuFatal("gpuBatchOpenResidentMaybe: NewDevice", err)
	}
	n := int(s.domain0.Cardinality)
	var owned []*p2.FrVector
	defer func() {
		for _, v := range owned {
			v.Free()
		}
	}()
	upload := func(coeffs []fr.Element) residentPoly {
		if len(coeffs) == 0 {
			return residentPoly{}
		}
		v, e := dev.NewFrVector(len(coeffs))
		if e != nil {
			gpuFatal("gpuBatchOpenResidentMaybe: NewFrVector", e)
		}
		owned = append(owned, v)
		if e := v.CopyFromHost(coeffs); e != nil {
			gpuFatal("gpuBatchOpenResidentMaybe: CopyFromHost", e)
		}
		return residentPoly{ptr: v.Ptr(), n: len(coeffs)}
	}
	// In the resident path the host wire buffers are stale (the rho-loop skipped
	// their download), so a missing resident handle must abort loudly: falling
	// through to the host/upload path would open stale coefficients.
	blind := func(id int, bpCoeffs []fr.Element) residentPoly {
		dWire := s.gpuCtx.getPoly(id)
		if dWire == nil {
			gpuFatal("gpuBatchOpenResidentMaybe: resident wire missing", fmt.Errorf("getPoly(%d) returned nil in resident path", id))
		}
		v, e := blindResidentWire(dev, dWire, n, bpCoeffs)
		if e != nil {
			gpuFatal("gpuBatchOpenResidentMaybe: blindResidentWire", e)
		}
		owned = append(owned, v)
		return residentPoly{ptr: v.Ptr(), n: v.Len()}
	}
	qcp := coefficients(s.trace.Qcp)
	polys := make([]residentPoly, 6+len(qcp))
	polys[0] = upload(s.linearizedPolynomial)
	polys[1] = blind(id_L, s.bp[id_Bl].Coefficients())
	polys[2] = blind(id_R, s.bp[id_Br].Coefficients())
	polys[3] = blind(id_O, s.bp[id_Bo].Coefficients())
	polys[4] = residentPoly{ptr: s.gpuCtx.getPoly(id_S1), n: n}
	polys[5] = residentPoly{ptr: s.gpuCtx.getPoly(id_S2), n: n}
	if polys[4].ptr == nil || polys[5].ptr == nil {
		gpuFatal("gpuBatchOpenResidentMaybe: resident S1/S2 missing", fmt.Errorf("getPoly(S1/S2) returned nil in resident path"))
	}
	for i := range qcp {
		polys[6+i] = upload(qcp[i])
	}
	res, err := gpuBatchOpenResident(polys, digests, point, hf, pk, dataTranscript...)
	if err != nil {
		gpuFatal("gpuBatchOpenResidentMaybe: gpuBatchOpenResident", err)
	}
	return res, true
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
	ptrs := make([]unsafe.Pointer, len(polys))
	lengths := make([]int, len(polys))
	for i := range polys {
		ptrs[i] = polys[i].ptr
		lengths[i] = polys[i].n
		if polys[i].n > largest {
			largest = polys[i].n
		}
	}
	// one batched eval call (shared scratch, one sync) for all claimed values
	vals, err := gpu.PolyEvalBatchDevice(ptrs, lengths, dPoint.Ptr())
	if err != nil {
		return res, err
	}
	copy(res.ClaimedValues, vals)
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
