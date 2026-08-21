//go:build js && wasm

// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package bn254

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/iop"
	"github.com/consensys/gnark/backend/accelerated/webgpu/plonk/internal/bridge"
	native "github.com/consensys/gnark/backend/plonk/bn254"
)

const (
	quotientBaseDynamicVectorCount = 5
	quotientBaseStaticVectorCount  = 7
	quotientEvalScalarCount        = 7
)

var quotientTransformCacheKey int
var quotientStaticMontCacheKey int
var quotientAuxMontCacheKey int
var cacheKeyMu sync.Mutex

type staticNumeratorCache struct {
	domain0Cardinality        uint64
	domain1Cardinality        uint64
	qcpCount                  int
	canonical                 staticNumeratorPolys
	cosets                    []staticNumeratorPolys
	quotientAux               quotientAuxCache
	webgpuStaticMontKeys      []int
	webgpuStaticMontPopulated []bool
	webgpuAuxMontKey          int
	webgpuAuxMontPopulated    bool
}

type staticNumeratorPolys struct {
	ql, qr, qm, qo *iop.Polynomial
	s1, s2, s3     *iop.Polynomial
	qcp            []*iop.Polynomial
}

type quotientAuxCache struct {
	twiddlesPacked     []byte
	scalingPacked      []byte
	denominatorsPacked []byte
	cosets             []fr.Element
	cosetExpMinusOnes  []fr.Element
	lagrangeScales     []fr.Element
	cs, css            fr.Element
}

func nextCacheKey(counter *int) int {
	cacheKeyMu.Lock()
	defer cacheKeyMu.Unlock()

	*counter = *counter + 1
	if *counter <= 0 {
		*counter = 1
	}
	return *counter
}

func (pk *ProvingKey) ensureStaticNumeratorCache(trace *native.Trace, domain0, domain1 *fft.Domain) error {
	qcpCount := len(trace.Qcp)
	if pk.staticNumeratorCache != nil &&
		pk.staticNumeratorCache.domain0Cardinality == domain0.Cardinality &&
		pk.staticNumeratorCache.domain1Cardinality == domain1.Cardinality &&
		pk.staticNumeratorCache.qcpCount == qcpCount {
		if len(pk.staticNumeratorCache.webgpuStaticMontKeys) != len(pk.staticNumeratorCache.cosets) {
			pk.staticNumeratorCache.webgpuStaticMontKeys = make([]int, len(pk.staticNumeratorCache.cosets))
			for i := range pk.staticNumeratorCache.webgpuStaticMontKeys {
				pk.staticNumeratorCache.webgpuStaticMontKeys[i] = nextCacheKey(&quotientStaticMontCacheKey)
			}
			pk.staticNumeratorCache.webgpuStaticMontPopulated = make([]bool, len(pk.staticNumeratorCache.cosets))
		}
		if len(pk.staticNumeratorCache.webgpuStaticMontPopulated) != len(pk.staticNumeratorCache.cosets) {
			pk.staticNumeratorCache.webgpuStaticMontPopulated = make([]bool, len(pk.staticNumeratorCache.cosets))
		}
		if err := pk.staticNumeratorCache.ensureQuotientAuxCache(domain0, domain1); err != nil {
			return err
		}
		pk.staticNumeratorCache.canonical.applyToTrace(trace)
		return nil
	}

	canonical := cloneStaticNumeratorPolys(trace)
	if err := canonicalizePolynomialsRegularWithWebGPU(canonical.polynomials(), int(domain0.Cardinality)); err != nil {
		return err
	}

	rho := int(domain1.Cardinality / domain0.Cardinality)
	cosets := make([]staticNumeratorPolys, rho)
	webgpuStaticMontKeys := make([]int, rho)
	for i := range webgpuStaticMontKeys {
		webgpuStaticMontKeys[i] = nextCacheKey(&quotientStaticMontCacheKey)
	}

	cosetTable, err := domain0.CosetTable()
	if err != nil {
		return err
	}
	scalingVector := cosetTable
	working := canonical.clone()
	for i := 0; i < rho; i++ {
		if i == 1 {
			w := domain1.Generator
			scalingVector = make([]fr.Element, domain0.Cardinality)
			fft.BuildExpTable(w, scalingVector)
		}

		if err := transformPolynomialsToCoset(working.polynomials(), domain0, scalingVector); err != nil {
			return err
		}
		cosets[i] = working.clone()
	}
	quotientAux, err := buildQuotientAuxCache(domain0, domain1)
	if err != nil {
		return err
	}

	pk.staticNumeratorCache = &staticNumeratorCache{
		domain0Cardinality:        domain0.Cardinality,
		domain1Cardinality:        domain1.Cardinality,
		qcpCount:                  qcpCount,
		canonical:                 canonical,
		cosets:                    cosets,
		quotientAux:               quotientAux,
		webgpuStaticMontKeys:      webgpuStaticMontKeys,
		webgpuStaticMontPopulated: make([]bool, rho),
		webgpuAuxMontKey:          nextCacheKey(&quotientAuxMontCacheKey),
	}
	pk.staticNumeratorCache.canonical.applyToTrace(trace)
	return nil
}

func (c *staticNumeratorCache) ensureQuotientAuxCache(domain0, domain1 *fft.Domain) error {
	n := int(domain0.Cardinality)
	rho := int(domain1.Cardinality / domain0.Cardinality)
	if c.webgpuAuxMontKey <= 0 {
		c.webgpuAuxMontKey = nextCacheKey(&quotientAuxMontCacheKey)
		c.webgpuAuxMontPopulated = false
	}
	if c.quotientAux.valid(n, rho) {
		return nil
	}
	aux, err := buildQuotientAuxCache(domain0, domain1)
	if err != nil {
		return err
	}
	c.quotientAux = aux
	c.webgpuAuxMontPopulated = false
	return nil
}

func (a quotientAuxCache) valid(n, rho int) bool {
	vectorBytes := n * frBytes
	return rho > 0 &&
		len(a.twiddlesPacked) == vectorBytes &&
		len(a.scalingPacked) == rho*vectorBytes &&
		len(a.denominatorsPacked) == rho*vectorBytes &&
		len(a.cosets) == rho &&
		len(a.cosetExpMinusOnes) == rho &&
		len(a.lagrangeScales) == rho
}

func buildQuotientAuxCache(domain0, domain1 *fft.Domain) (quotientAuxCache, error) {
	n := int(domain0.Cardinality)
	rho := int(domain1.Cardinality / domain0.Cardinality)
	if n <= 0 || rho <= 0 {
		return quotientAuxCache{}, fmt.Errorf("webgpu plonk bn254: invalid quotient auxiliary domain n=%d rho=%d", n, rho)
	}

	twiddles0 := make([]fr.Element, n)
	if n == 1 {
		twiddles0[0].SetOne()
	} else {
		twiddles, err := domain0.Twiddles()
		if err != nil {
			return quotientAuxCache{}, err
		}
		copy(twiddles0, twiddles[0])
		w := twiddles0[1]
		for i := len(twiddles[0]); i < len(twiddles0); i++ {
			twiddles0[i].Mul(&twiddles0[i-1], &w)
		}
	}

	cosetTable, err := domain0.CosetTable()
	if err != nil {
		return quotientAuxCache{}, err
	}

	vectorBytes := n * frBytes
	aux := quotientAuxCache{
		twiddlesPacked:     packFrVectorRegularLEInto(nil, twiddles0),
		scalingPacked:      make([]byte, rho*vectorBytes),
		denominatorsPacked: make([]byte, rho*vectorBytes),
		cosets:             make([]fr.Element, rho),
		cosetExpMinusOnes:  make([]fr.Element, rho),
		lagrangeScales:     make([]fr.Element, rho),
	}
	aux.cs.Set(&domain1.FrMultiplicativeGen)
	aux.css.Square(&aux.cs)

	shifters := make([]fr.Element, rho)
	shifters[0].Set(&domain1.FrMultiplicativeGen)
	for i := 1; i < rho; i++ {
		shifters[i].Set(&domain1.Generator)
	}

	denominators := make([]fr.Element, n)
	bufBatchInvert := make([]fr.Element, n)
	scalingVector := make([]fr.Element, n)
	var coset, cosetExpMinusOne, one fr.Element
	coset.SetOne()
	one.SetOne()
	bn := big.NewInt(int64(domain0.Cardinality))
	for i := 0; i < rho; i++ {
		coset.Mul(&coset, &shifters[i])
		aux.cosets[i].Set(&coset)
		cosetExpMinusOne.Exp(coset, bn).Sub(&cosetExpMinusOne, &one)
		aux.cosetExpMinusOnes[i].Set(&cosetExpMinusOne)
		aux.lagrangeScales[i].Mul(&cosetExpMinusOne, &domain0.CardinalityInv)

		for j := 0; j < n; j++ {
			denominators[j].Mul(&coset, &twiddles0[j]).Sub(&denominators[j], &one)
		}
		batchInvert(denominators, bufBatchInvert)
		packFrVectorRegularLEInto(aux.denominatorsPacked[i*vectorBytes:(i+1)*vectorBytes], denominators)

		currentScalingVector := scalingVector
		if i == 0 {
			currentScalingVector = cosetTable
		} else {
			fft.BuildExpTable(coset, scalingVector)
		}
		packFrVectorRegularLEInto(aux.scalingPacked[i*vectorBytes:(i+1)*vectorBytes], currentScalingVector)
	}
	return aux, nil
}

func cloneStaticNumeratorPolys(trace *native.Trace) staticNumeratorPolys {
	res := staticNumeratorPolys{
		ql:  trace.Ql.Clone(),
		qr:  trace.Qr.Clone(),
		qm:  trace.Qm.Clone(),
		qo:  trace.Qo.Clone(),
		s1:  trace.S1.Clone(),
		s2:  trace.S2.Clone(),
		s3:  trace.S3.Clone(),
		qcp: make([]*iop.Polynomial, len(trace.Qcp)),
	}
	for i := range trace.Qcp {
		res.qcp[i] = trace.Qcp[i].Clone()
	}
	return res
}

func (p staticNumeratorPolys) clone() staticNumeratorPolys {
	res := staticNumeratorPolys{
		ql:  p.ql.Clone(),
		qr:  p.qr.Clone(),
		qm:  p.qm.Clone(),
		qo:  p.qo.Clone(),
		s1:  p.s1.Clone(),
		s2:  p.s2.Clone(),
		s3:  p.s3.Clone(),
		qcp: make([]*iop.Polynomial, len(p.qcp)),
	}
	for i := range p.qcp {
		res.qcp[i] = p.qcp[i].Clone()
	}
	return res
}

func (p staticNumeratorPolys) polynomials() []*iop.Polynomial {
	res := []*iop.Polynomial{p.ql, p.qr, p.qm, p.qo, p.s1, p.s2, p.s3}
	res = append(res, p.qcp...)
	return res
}

func (p staticNumeratorPolys) applyToTrace(trace *native.Trace) {
	trace.Ql = p.ql
	trace.Qr = p.qr
	trace.Qm = p.qm
	trace.Qo = p.qo
	trace.S1 = p.s1
	trace.S2 = p.s2
	trace.S3 = p.s3
	trace.Qcp = p.qcp
}

func transformPolynomialsToCoset(polys []*iop.Polynomial, domain *fft.Domain, scalingVector []fr.Element) error {
	// shift polynomials to be in the correct coset
	if err := canonicalizePolynomialsRegularWithWebGPU(polys, int(domain.Cardinality)); err != nil {
		return err
	}

	// scale by shifter
	for _, p := range polys {
		cp := p.Coefficients()
		for j := range cp {
			cp[j].Mul(&cp[j], &scalingVector[j])
		}
	}
	return lagrangePolynomialsRegularWithWebGPU(polys, int(domain.Cardinality))
}

func (pk *ProvingKey) ensureStaticNumeratorCacheForTrace(trace *native.Trace, domain0, domain1 *fft.Domain) error {
	pk.prepareMu.Lock()
	defer pk.prepareMu.Unlock()

	return pk.ensureStaticNumeratorCache(trace, domain0, domain1)
}

func (pk *ProvingKey) preloadQuotientStaticCaches(trace *native.Trace, domain0, domain1 *fft.Domain) error {
	staticCache := pk.staticNumeratorCache
	if staticCache == nil {
		return errors.New("webgpu plonk bn254: missing static numerator cache")
	}
	n := int(domain0.Cardinality)
	rho := int(domain1.Cardinality / domain0.Cardinality)
	if len(staticCache.cosets) != rho {
		return fmt.Errorf("webgpu plonk bn254: static numerator cache has %d cosets, expected %d", len(staticCache.cosets), rho)
	}
	quotientAux := staticCache.quotientAux
	if !quotientAux.valid(n, rho) {
		return errors.New("webgpu plonk bn254: invalid quotient auxiliary cache")
	}
	auxMontCacheKey := staticCache.webgpuAuxMontKey
	if auxMontCacheKey <= 0 || int(uint32(auxMontCacheKey)) != auxMontCacheKey {
		return fmt.Errorf("webgpu plonk bn254: invalid quotient auxiliary WebGPU cache key %d", auxMontCacheKey)
	}

	commitmentCount := len(trace.Qcp)
	staticVectorCount := quotientBaseStaticVectorCount + commitmentCount
	vectorBytes := n * frBytes
	staticPacked, err := packStaticNumeratorCosets(staticCache, rho, staticVectorCount, commitmentCount, n, vectorBytes)
	if err != nil {
		return err
	}

	staticMontCacheKeysPacked, err := packStaticMontCacheKeys(staticCache, rho)
	if err != nil {
		return err
	}

	if err := bridge.Bridge.PreloadQuotientStaticAndAux(
		"bn254",
		staticPacked,
		staticMontCacheKeysPacked,
		quotientAux.scalingPacked,
		quotientAux.twiddlesPacked,
		quotientAux.denominatorsPacked,
		n,
		staticVectorCount,
		rho,
		auxMontCacheKey,
	); err != nil {
		return err
	}

	for i := range staticCache.webgpuStaticMontPopulated {
		staticCache.webgpuStaticMontPopulated[i] = true
	}
	staticCache.webgpuAuxMontPopulated = true
	return nil
}

type quotientStaticBridgeInputs struct {
	staticCache               *staticNumeratorCache
	quotientAux               quotientAuxCache
	staticPacked              []byte
	staticMontCacheKeysPacked []byte
	twiddlesPacked            []byte
	scalingPacked             []byte
	denominatorsPacked        []byte
	auxMontCacheKey           int
}

func (pk *ProvingKey) quotientStaticBridgeInputs(rho, staticVectorCount, commitmentCount, n, vectorBytes int) (quotientStaticBridgeInputs, error) {
	pk.prepareMu.Lock()
	defer pk.prepareMu.Unlock()

	staticCache := pk.staticNumeratorCache
	if staticCache == nil || len(staticCache.cosets) != rho {
		return quotientStaticBridgeInputs{}, errors.New("missing static numerator cache")
	}
	quotientAux := staticCache.quotientAux
	if !quotientAux.valid(n, rho) {
		return quotientStaticBridgeInputs{}, errors.New("webgpu plonk bn254: invalid quotient auxiliary cache")
	}
	staticMontCacheKeysPacked, err := packStaticMontCacheKeys(staticCache, rho)
	if err != nil {
		return quotientStaticBridgeInputs{}, err
	}

	reuseStaticMontCache := true
	for i := 0; i < rho; i++ {
		if !staticCache.webgpuStaticMontPopulated[i] {
			reuseStaticMontCache = false
		}
	}
	auxMontCacheKey := staticCache.webgpuAuxMontKey
	if auxMontCacheKey <= 0 || int(uint32(auxMontCacheKey)) != auxMontCacheKey {
		return quotientStaticBridgeInputs{}, fmt.Errorf("webgpu plonk bn254: invalid quotient auxiliary WebGPU cache key %d", auxMontCacheKey)
	}

	var staticPacked []byte
	if !reuseStaticMontCache {
		staticPacked, err = packStaticNumeratorCosets(staticCache, rho, staticVectorCount, commitmentCount, n, vectorBytes)
		if err != nil {
			return quotientStaticBridgeInputs{}, err
		}
	}

	twiddlesPacked := quotientAux.twiddlesPacked
	scalingPacked := quotientAux.scalingPacked
	denominatorsPacked := quotientAux.denominatorsPacked
	if staticCache.webgpuAuxMontPopulated {
		twiddlesPacked = nil
		scalingPacked = nil
		denominatorsPacked = nil
	}

	return quotientStaticBridgeInputs{
		staticCache:               staticCache,
		quotientAux:               quotientAux,
		staticPacked:              staticPacked,
		staticMontCacheKeysPacked: staticMontCacheKeysPacked,
		twiddlesPacked:            twiddlesPacked,
		scalingPacked:             scalingPacked,
		denominatorsPacked:        denominatorsPacked,
		auxMontCacheKey:           auxMontCacheKey,
	}, nil
}

func (pk *ProvingKey) markQuotientStaticBridgeInputsPopulated(staticCache *staticNumeratorCache) {
	pk.prepareMu.Lock()
	defer pk.prepareMu.Unlock()

	for i := range staticCache.webgpuStaticMontPopulated {
		staticCache.webgpuStaticMontPopulated[i] = true
	}
	staticCache.webgpuAuxMontPopulated = true
}

func packStaticMontCacheKeys(staticCache *staticNumeratorCache, rho int) ([]byte, error) {
	if len(staticCache.webgpuStaticMontKeys) != rho || len(staticCache.webgpuStaticMontPopulated) != rho {
		return nil, errors.New("webgpu plonk bn254: invalid static numerator WebGPU cache metadata")
	}
	out := make([]byte, rho*4)
	for i := 0; i < rho; i++ {
		key := staticCache.webgpuStaticMontKeys[i]
		if key <= 0 || int(uint32(key)) != key {
			return nil, fmt.Errorf("webgpu plonk bn254: invalid static numerator WebGPU cache key %d", key)
		}
		binary.LittleEndian.PutUint32(out[i*4:(i+1)*4], uint32(key))
	}
	return out, nil
}

func packStaticNumeratorCosets(staticCache *staticNumeratorCache, rho, staticVectorCount, commitmentCount, n, vectorBytes int) ([]byte, error) {
	staticPacked := make([]byte, rho*staticVectorCount*vectorBytes)
	for i := 0; i < rho; i++ {
		start := i * staticVectorCount * vectorBytes
		if err := packStaticNumeratorPolys(
			staticPacked[start:start+staticVectorCount*vectorBytes],
			staticCache.cosets[i],
			staticVectorCount,
			commitmentCount,
			n,
			vectorBytes,
		); err != nil {
			return nil, err
		}
	}
	return staticPacked, nil
}

func packStaticNumeratorPolys(dst []byte, polys staticNumeratorPolys, staticVectorCount, commitmentCount, n, vectorBytes int) error {
	if len(polys.qcp) != commitmentCount {
		return fmt.Errorf("webgpu plonk bn254: quotient evaluator expected %d qcp vectors, got %d", commitmentCount, len(polys.qcp))
	}
	staticVectors := polys.polynomials()
	if len(staticVectors) != staticVectorCount {
		return fmt.Errorf("webgpu plonk bn254: quotient evaluator expected %d static vectors, got %d", staticVectorCount, len(staticVectors))
	}
	for i, p := range staticVectors {
		if p == nil {
			return fmt.Errorf("webgpu plonk bn254: missing quotient static polynomial %d", i)
		}
		coeffs := p.Coefficients()
		if len(coeffs) != n {
			return fmt.Errorf("webgpu plonk bn254: quotient static polynomial %d has %d coefficients, expected %d", i, len(coeffs), n)
		}
		packFrVectorRegularLEInto(dst[i*vectorBytes:(i+1)*vectorBytes], coeffs)
	}
	return nil
}

// batchInvert modifies in place vec, with vec[i]<-vec[i]^{-1}, using
// the Montgomery batch inversion trick. We don't use gnark-crypto's batchInvert
// because we want to use a buffer preallocated, to avoid wasting memory.
// /!\ it doesn't check that all vec's inputs or non zero, it is ensured by the size
// of the field /!\
func batchInvert(vec, buf []fr.Element) {
	// local function only, vec and buf are of the same size
	copy(buf, vec)
	for i := 1; i < len(vec); i++ {
		vec[i].Mul(&vec[i], &vec[i-1])
	}
	acc := vec[len(vec)-1]
	acc.Inverse(&acc)
	for i := len(vec) - 1; i > 0; i-- {
		vec[i].Mul(&acc, &vec[i-1])
		acc.Mul(&acc, &buf[i])
	}
	vec[0].Set(&acc)
}
