package emulated

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
)

var NB_CHALLENGE_LIMBS = 2

// Represents an element of a polynomial ring over the emulated field.
type Poly[T FieldParams] struct {
	Coeffs     []*Element[T]
	evaluation *Element[T] // nil unless evaluated
}

// polyRingMulCheck represents a polynomial product check in a polynomial
// ring. Instead of computing the product and reducing it where called,
// we compute the result using a hint and return it. Result is stored for
// correctness check later to share the verifier challenge computation.
//
// We store the values poly, irr, r, q. They are as follows:
//   - poly - the input polynomials whose product we are checking. Each
//     polynomial is represented as a slice of [Element] coefficients. Elements
//     have to be reduced.
//   - mod - the polynomial defining the ring, i.e. the modulus for the Euclidean
//     division. Treated as a constant.
//   - r - the product reduced modulo mod, i.e. the remainder. This is the
//     result returned to the caller.
//   - q - the quotient of the product divided by mod.
//
// Given these values, the following holds as an identity of polynomials over
// the emulated field:
//
//	∏_i inputs_i = r + q * mod
//
// For asserting that the previous identity holds, we evaluate both sides at a
// single random challenge point α obtained via commitment to all coefficients.
// If a polynomial f has coefficient elements (f_0, ..., f_n), its evaluation is
//
//	f(α) = ∑_i f_i(α) * α^i,
//
// where each f_i(α) is itself the Schwartz-Zippel evaluation of the limb
// polynomial of the emulated element f_i. The product check then becomes
//
//	∏_i inputs_i(α) = r(α) + q(α) * mod(α),
//
// which can be verified at a single random point.
//
// we verify rlc, ∑_i z^i * ( ∏_j inputs_j(x) - r_i(x) ) == ∑_i z^i * q_i(x) * mod_i(x)
//
// this allows skipping individual q evaluations in the circuit because,
// ∑_i z^i * q_i is computed outside the circuit, and evaluated inside the circuit
// PolyRingGroupChecks binds a specific modulus to all of its checks.
type PolyRingGroupChecks[T FieldParams] struct {
	mod    *Poly[T]              // polynomial defining the ring
	checks []polyRingMulCheck[T] // individual operations to check
	q_acc  *Poly[T]              // random linear combination of quotients ∑_i z^i * q_i
}

// polyRingMulCheck is an individual deferred check.
type polyRingMulCheck[T FieldParams] struct {
	// ∏_i inputs_i = r + q * mod
	inputs []*Poly[T] // input polynomials
	r      *Poly[T]   // remainder
	q      *Poly[T]   // quotient
}

// NewPolyRingCheck registers a new polynomial ring group with the given modulus. The
func (f *Field[T]) NewPolyRingCheck(mod *Poly[T]) *PolyRingGroupChecks[T] {
	groupCheck := &PolyRingGroupChecks[T]{
		mod:    mod,
		checks: []polyRingMulCheck[T]{},
	}
	f.deferredPolyChecks = append(f.deferredPolyChecks, groupCheck)

	return groupCheck
}

// MulPolyRings computes a polynomial product check in a polynomial ring,
// returns the remainder (reduced result) and the quotient. The computation
// is performed inside a hint, so it is the callers responsibility to perform
// the deferred polynomial ring multiplication check.
func (f *Field[T]) MulPolyRings(group *PolyRingGroupChecks[T], inputs ...*Poly[T]) (rem *Poly[T], err error) {
	mod := *group.mod
	nbLimbs, nbBits := int(f.fParams.NbLimbs()), f.fParams.BitsPerLimb()

	// total number of terms for all input polynomials
	nbTerms := 0
	// loop through inputs to compute the number of terms
	for _, inputPoly := range inputs {
		// add degree of each input polynomial
		nbTerms += len(inputPoly.Coeffs)
	}

	// metadata for hint inputs
	nbPoly := len(inputs)
	nbTermsLimbs := nbTerms * nbLimbs
	nbModTermsLimbs := len(mod.Coeffs) * nbLimbs

	// metadata for outputs
	modDegree := len(mod.Coeffs) - 1
	nbRemLimbs := modDegree * nbLimbs
	totalDegree := nbTerms - nbPoly
	// q degree is total degree minus the degree of the modulus polynomial
	qDegree := totalDegree - modDegree
	nbQTermsLimbs := (1 + qDegree) * nbLimbs

	// polynomials serialised as nbTerms|...terms. hintInputs contains
	// serialisation of: nbBits|nbLimbs|nbPoly|fieldMod|...inputs|modPoly,
	// where inputs and mod are serialised as polynomials
	hintInputs := make([]frontend.Variable, 0, 4+(nbPoly+nbTermsLimbs)+(1+nbModTermsLimbs))

	hintInputs = append(hintInputs, nbBits, nbLimbs, nbPoly, *f.fParams.Modulus())

	// loop through inputs to compute the number of terms
	for _, inputPoly := range inputs {
		hintInputs = f.serialisePoly(inputPoly, hintInputs)
	}

	hintInputs = f.serialisePoly(&mod, hintInputs)

	// call
	ret, err := f.api.NewHint(polyRingMulHint, 1+nbQTermsLimbs+1+nbRemLimbs, hintInputs...)

	if err != nil {
		return nil, err
	}

	// unpack quotient: skip nbQTerms header, then read (1+qDegree) terms of nbLimbs each
	quo := &Poly[T]{Coeffs: make([]*Element[T], 1+qDegree)}
	retPtr := 1 // skip nbQTerms
	for i := range quo.Coeffs {
		termLimbs := ret[retPtr : retPtr+nbLimbs]
		retPtr += nbLimbs
		// quotient is only used by the prover to generate the rlc, so don't need
		// rangechecks on these
		quo.Coeffs[i] = f.newInternalElement(termLimbs, 0)
	}

	// unpack remainder: skip nbRemTerms header, then read len(mod)-1 terms of nbLimbs each
	retPtr++ // skip nbRemTerms
	rem = &Poly[T]{Coeffs: make([]*Element[T], len(mod.Coeffs)-1)}
	for i := range rem.Coeffs {
		termLimbs := ret[retPtr : retPtr+nbLimbs]
		retPtr += nbLimbs
		rem.Coeffs[i] = f.packLimbs(termLimbs, true)
	}

	group.checks = append(group.checks, polyRingMulCheck[T]{
		inputs: inputs,
		r:      rem,
		q:      quo,
	})

	return rem, nil
}

// polyRingMulHint computes the multivariate evaluation as a hint. Should not be
// called directly, but rather through [Field.MulPolyRings] method which
// handles the input packing and output unpacking.
func polyRingMulHint(mod *big.Int, inputs, outputs []*big.Int) error {
	nbBits := int(inputs[0].Int64())
	nbLimbs := int(inputs[1].Int64())
	nbPoly := int(inputs[2].Int64())
	fieldMod := new(big.Int).Set(inputs[3])

	// extract the input polynomials
	inputsPolys := make([][]*big.Int, nbPoly)
	ptr := 4

	for i := 0; i < nbPoly; i++ {
		nbTerms := int(inputs[ptr].Int64())
		ptr++
		inputsPolys[i] = make([]*big.Int, nbTerms)
		for j := 0; j < nbTerms; j++ {
			coeffLimbs := inputs[ptr : ptr+nbLimbs]
			ptr += nbLimbs
			val := new(big.Int)
			if err := limbs.Recompose(coeffLimbs, uint(nbBits), val); err != nil {
				return fmt.Errorf("recompose input[%d][%d]: %w", i, j, err)
			}
			inputsPolys[i][j] = val
		}
	}

	nbModPolyTerms := int(inputs[ptr].Int64())
	ptr++
	modPoly := make([]*big.Int, nbModPolyTerms)
	for j := 0; j < nbModPolyTerms; j++ {
		coeffLimbs := inputs[ptr : ptr+nbLimbs]
		ptr += nbLimbs
		val := new(big.Int)
		if err := limbs.Recompose(coeffLimbs, uint(nbBits), val); err != nil {
			return fmt.Errorf("recompose mod polynomial[%d]: %w", j, err)
		}
		modPoly[j] = val
	}

	// multiply inputs and divide by modPoly to obtain quotient and remainder
	q, r, err := polyRingMul(fieldMod, inputsPolys, modPoly)
	if err != nil {
		return fmt.Errorf("polyRingMul: %w", err)
	}

	// serialize outputs: nbQTerms | q limbs... | nbRemTerms | r limbs...
	nbBitsU := uint(nbBits)
	outptr := 0
	outputs[outptr].SetInt64(int64(len(q)))
	outptr++
	for _, coeff := range q {
		coeffLimbs := make([]*big.Int, nbLimbs)
		for i := range coeffLimbs {
			coeffLimbs[i] = new(big.Int)
		}
		if err := limbs.Decompose(coeff, nbBitsU, coeffLimbs); err != nil {
			return fmt.Errorf("decompose quotient coeff: %w", err)
		}
		copy(outputs[outptr:outptr+nbLimbs], coeffLimbs)
		outptr += nbLimbs
	}
	outputs[outptr].SetInt64(int64(len(r)))
	outptr++
	for _, coeff := range r {
		coeffLimbs := make([]*big.Int, nbLimbs)
		for i := range coeffLimbs {
			coeffLimbs[i] = new(big.Int)
		}
		if err := limbs.Decompose(coeff, nbBitsU, coeffLimbs); err != nil {
			return fmt.Errorf("decompose remainder coeff: %w", err)
		}
		copy(outputs[outptr:outptr+nbLimbs], coeffLimbs)
		outptr += nbLimbs
	}

	return nil
}

// polyRingMul multiplies all polynomials in inputs and divides the product
// by modPoly using polynomial Euclidean division. Coefficients are reduced
// modulo fieldMod (the emulated field prime).
func polyRingMul(fieldMod *big.Int, inputs [][]*big.Int, modPoly []*big.Int) (q, r []*big.Int, err error) {
	if len(inputs) == 0 {
		return nil, nil, fmt.Errorf("polyRingMul: no input polynomials")
	}
	if len(modPoly) == 0 {
		return nil, nil, fmt.Errorf("polyRingMul: modulus polynomial is empty")
	}

	// multiply all polynomials in inputs
	product := make([]*big.Int, len(inputs[0]))
	for i, c := range inputs[0] {
		product[i] = new(big.Int).Mod(c, fieldMod)
	}
	for k := 1; k < len(inputs); k++ {
		b := inputs[k]
		result := make([]*big.Int, len(product)+len(b)-1)
		for i := range result {
			result[i] = new(big.Int)
		}
		for i, ci := range product {
			for j, cj := range b {
				term := new(big.Int).Mul(ci, cj)
				result[i+j].Add(result[i+j], term)
				result[i+j].Mod(result[i+j], fieldMod)
			}
		}
		product = result
	}

	// euclidean division: product = quotient * modPoly + remainder
	divisorDeg := len(modPoly) - 1

	// if product has lower degree than modPoly, quotient is 0 and remainder is product
	if len(product)-1 < divisorDeg {
		remainder := make([]*big.Int, divisorDeg)
		for i := range remainder {
			if i < len(product) {
				remainder[i] = new(big.Int).Set(product[i])
			} else {
				remainder[i] = new(big.Int)
			}
		}
		return []*big.Int{new(big.Int)}, remainder, nil
	}

	// leading coefficient inverse of modPoly modulo field modulus
	lcInv := new(big.Int).ModInverse(modPoly[divisorDeg], fieldMod)
	if lcInv == nil {
		return nil, nil, fmt.Errorf("polyRingMul: leading coefficient of modulus polynomial is not invertible")
	}

	dividend := make([]*big.Int, len(product))
	for i, c := range product {
		dividend[i] = new(big.Int).Set(c)
	}

	qDeg := len(product) - 1 - divisorDeg
	quotient := make([]*big.Int, qDeg+1)
	for i := range quotient {
		quotient[i] = new(big.Int)
	}

	for len(dividend) >= len(modPoly) {
		d := len(dividend) - len(modPoly)
		// leading quotient term at degree d
		lc := new(big.Int).Mul(dividend[len(dividend)-1], lcInv)
		lc.Mod(lc, fieldMod)
		quotient[d].Set(lc)
		// subtract lc * x^d * modPoly from dividend
		for i, c := range modPoly {
			term := new(big.Int).Mul(lc, c)
			dividend[i+d].Sub(dividend[i+d], term)
			dividend[i+d].Mod(dividend[i+d], fieldMod)
		}
		// trim leading zeros
		for len(dividend) > 0 && dividend[len(dividend)-1].Sign() == 0 {
			dividend = dividend[:len(dividend)-1]
		}
	}

	// pad remainder to divisorDeg terms
	remainder := make([]*big.Int, divisorDeg)
	for i := range remainder {
		if i < len(dividend) {
			remainder[i] = new(big.Int).Set(dividend[i])
		} else {
			remainder[i] = new(big.Int)
		}
	}

	return quotient, remainder, nil
}

func (f *Field[T]) MakePoly(coeffs []interface{}) *Poly[T] {
	poly := &Poly[T]{}
	poly.Coeffs = make([]*Element[T], len(coeffs))

	for i, coeff := range coeffs {
		if coeff == 0 {
			poly.Coeffs[i] = f.Zero()
			continue
		}
		poly.Coeffs[i] = f.NewElement(coeff)
	}

	return poly
}

// performDeferredRingChecks performs the deferred polynomial checks.
// prover provides results of ring multiplications - remainders and quotients
//  1. commit the remainders to obtain a random challenge z for random
//     linear combination of all quotients
//  2. batch the quotients with adjacent powers RLC using challenge z
//     q_acc = ∑_i z^i * q_i
//  3. commit the quotients rlc with challenge z to obtain challenge x
//  4. assert equality of remainders and quotients rlc polynomials at x
//     i.e. ∑_i z^i * ( ∏_j inputs_j(x) - r_i(x) ) == (∑_i z^i * q_i)(x) * mod_i(x)
//
// savings come from batching quotients outside the circuit – q_acc = ∑_i z^i * q_i
func (f *Field[T]) performDeferredRingChecks(api frontend.API) error {
	// use given api. We are in defer and API may be different to what we have
	// stored.

	if len(f.deferredPolyChecks) == 0 {
		return nil
	}

	// get committer from the api
	committer, ok := api.(frontend.Committer)
	if !ok {
		panic("compiler doesn't implement frontend.Committer")
	}

	// 1. commit the remainders

	// prepare all remainder coefficients to commit to from each group
	var remainderCoeffCommits []frontend.Variable
	for _, group := range f.deferredPolyChecks {
		for _, mulCheck := range group.checks {
			for _, rCoeff := range mulCheck.r.Coeffs {
				remainderCoeffCommits = append(remainderCoeffCommits, rCoeff.Limbs...)
			}
		}
	}

	if len(remainderCoeffCommits) == 0 {
		// nothing to do
		return nil
	}

	// commit all remainders from each group at once
	z, err := committer.Commit(remainderCoeffCommits...) // z = remainderCommitment
	if err != nil {
		return fmt.Errorf("deferredPolyCheck commit error: %w", err)
	}

	// 2. batch and store quotients from each group
	//    and prepare to commit

	// z can be shared across all groups
	quotientbatchesCoeffCommits := []frontend.Variable{z}
	for _, group := range f.deferredPolyChecks {
		quotients := make([]*Poly[T], len(group.checks))
		for i, mulCheck := range group.checks {
			quotients[i] = mulCheck.q
		}

		// q_acc = ∑_i z^i * q_i
		group.q_acc, err = f.callQuotientsRLCHint(quotients, z)

		//
		for _, rCoeff := range group.q_acc.Coeffs {
			if rCoeff == nil {
				println("nil coefficient")
				continue
			}
			quotientbatchesCoeffCommits = append(quotientbatchesCoeffCommits, rCoeff.Limbs...)
		}

		if err != nil {
			return fmt.Errorf("deferredPolyCheck callQuotientsRLCHint error: %w", err)
		}
	}

	// 3. commit the quotients
	x, err := committer.Commit(quotientbatchesCoeffCommits...)
	if err != nil {
		return fmt.Errorf("deferredPolyCheck quotient commit error: %w", err)
	}

	// Decompose challenges into emulated elements (full-width, multi-limb).
	nativesToEl := f.NativeToEmulated(NB_CHALLENGE_LIMBS, z, x)
	zEmulated := nativesToEl[0]
	xEmulated := nativesToEl[1]

	maxTerms := 0
	maxChecks := 0
	for _, group := range f.deferredPolyChecks {
		maxTerms = max(maxTerms, len(group.mod.Coeffs))
		maxTerms = max(maxTerms, len(group.q_acc.Coeffs))
		maxChecks = max(maxChecks, len(group.checks))
	}

	xPowers := make([]*Element[T], maxTerms)
	xPowers[0] = f.One()
	if maxTerms > 1 {
		xPowers[1] = xEmulated
		for i := 2; i < maxTerms; i++ {
			xPowers[i] = f.Mul(xPowers[i-1], xEmulated)
		}
	}

	zPowers := make([]*Element[T], maxChecks)
	zPowers[0] = f.One()
	if maxChecks > 1 {
		zPowers[1] = zEmulated
		for i := 2; i < maxChecks; i++ {
			zPowers[i] = f.Mul(zPowers[i-1], zEmulated)
		}
	}

	// 4. assert the ring check at x for each group
	for _, group := range f.deferredPolyChecks {
		// lhsRlc = ∑_i z^i * (∏_j inputs_i_j(x) - r_i(x))
		lhsEvals := make([]*Element[T], len(group.checks))

		for i, check := range group.checks {
			// lhs = inputs_i_0(x)
			lhs := f.evalPolyWithChallenge(check.inputs[0], xPowers)

			// lhs = ∏_j inputs_j(x)
			for j := 1; j < len(check.inputs); j++ {
				lhs = f.Mul(lhs, f.evalPolyWithChallenge(check.inputs[j], xPowers))
			}

			// compute (∏_j inputs_j(x)) - r(x)
			lhs = f.Sub(lhs, f.evalPolyWithChallenge(check.r, xPowers))
			lhsEvals[i] = lhs
		}

		lhsRlc := f.InnerProductNoReduce(lhsEvals, zPowers)

		// compute q_acc(x) * mod(x)
		rhs := f.MulNoReduce(
			f.evalPolyWithChallenge(group.q_acc, xPowers),
			f.evalPolyWithChallenge(group.mod, xPowers),
		)

		f.AssertIsEqual(lhsRlc, rhs)
	}

	return nil
}

// callQuotientsRLCHint computes the random linear combination ∑_i z^i * q_i of
// the provided quotient polynomials with the scalar challenge z. The result is
// a single Poly[T] whose coefficients are emulated field elements reduced
// modulo the emulated field prime. This is used in the deferred ring check to
// batch multiple quotient polynomials together outside the circuit, saving
// constraints by avoiding individual quotient evaluations.
func (f *Field[T]) callQuotientsRLCHint(quotients []*Poly[T], z frontend.Variable) (*Poly[T], error) {
	if len(quotients) == 0 {
		return nil, fmt.Errorf("BatchPolyQuotients: no quotient polynomials")
	}

	nbLimbs, nbBits := int(f.fParams.NbLimbs()), f.fParams.BitsPerLimb()

	// the output polynomial has the maximum number of terms among all inputs
	maxTerms := 0
	for _, q := range quotients {
		if len(q.Coeffs) > maxTerms {
			maxTerms = len(q.Coeffs)
		}
	}

	nbPolys := len(quotients)

	// hint input layout: nbBits | nbLimbs | nbPolys | fieldMod | z | for each poly: nbTerms | limbs...
	hintInputs := make([]frontend.Variable, 0, 6+nbPolys)
	hintInputs = append(hintInputs, nbBits, nbLimbs, NB_CHALLENGE_LIMBS, nbPolys, *f.fParams.Modulus(), z)

	for _, q := range quotients {
		hintInputs = f.serialisePoly(q, hintInputs)
	}

	nbOutputs := maxTerms * nbLimbs
	ret, err := f.api.NewHint(quotientsRLCHint, nbOutputs, hintInputs...)
	if err != nil {
		return nil, fmt.Errorf("BatchPolyQuotients hint: %w", err)
	}

	result := &Poly[T]{Coeffs: make([]*Element[T], maxTerms)}
	for i := range result.Coeffs {
		termLimbs := ret[i*nbLimbs : (i+1)*nbLimbs]
		result.Coeffs[i] = f.packLimbs(termLimbs, false)
	}

	return result, nil
}

// quotientsRLCHint computes ∑_i z^i * q_i for a list of quotient
// polynomials and a scalar challenge z. Each output coefficient is
// result[j] = ∑_i z^i * q_i[j] mod fieldMod, where fieldMod is the emulated
// field prime. Should not be called directly; use [Field.BatchPolyQuotients].
func quotientsRLCHint(nativeMod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) < 5 {
		return fmt.Errorf("batchPolyQuotientsHint: not enough inputs")
	}
	nbBits := int(inputs[0].Int64())
	nbLimbs := int(inputs[1].Int64())
	nbChallengeLimbs := int(inputs[2].Int64())
	nbPolys := int(inputs[3].Int64())
	fieldMod := new(big.Int).Set(inputs[4])
	zLimbs := make([]*big.Int, nativeMod.BitLen()/(nbBits*nbChallengeLimbs)+1, nbLimbs)
	for k := range zLimbs {
		zLimbs[k] = new(big.Int)
	}
	if err := limbs.Decompose(inputs[5], uint(nbBits*nbChallengeLimbs), zLimbs); err != nil {
		return fmt.Errorf("quotientsRLCHint: z decompose failed: %w", err)
	}
	z := zLimbs[0]
	ptr := 6
	polys := make([][]*big.Int, nbPolys)
	for i := 0; i < nbPolys; i++ {
		nbTerms := int(inputs[ptr].Int64())
		ptr++
		polys[i] = make([]*big.Int, nbTerms)
		for j := 0; j < nbTerms; j++ {
			coeffLimbs := inputs[ptr : ptr+nbLimbs]
			ptr += nbLimbs
			val := new(big.Int)
			if err := limbs.Recompose(coeffLimbs, uint(nbBits), val); err != nil {
				return fmt.Errorf("recompose polys[%d][%d]: %w", i, j, err)
			}
			polys[i][j] = val
		}
	}
	maxTerms := len(outputs) / nbLimbs
	// accumulator: result[j] = ∑_i z^i * q_i[j] mod fieldMod
	result := make([]*big.Int, maxTerms)
	for i := range result {
		result[i] = new(big.Int)
	}
	zPow := new(big.Int).SetInt64(1) // z^0 = 1
	tmp := new(big.Int)
	for _, poly := range polys {
		for j, coeff := range poly {
			tmp.Mul(zPow, coeff)
			tmp.Mod(tmp, fieldMod)
			result[j].Add(result[j], tmp)
			result[j].Mod(result[j], fieldMod)
		}
		zPow.Mul(zPow, z)
		zPow.Mod(zPow, fieldMod)
	}
	// serialize: maxTerms coefficients each decomposed into nbLimbs limbs
	outptr := 0
	for idx, coeff := range result {
		coeffLimbs := make([]*big.Int, nbLimbs)
		for k := range coeffLimbs {
			coeffLimbs[k] = new(big.Int)
		}
		if err := limbs.Decompose(coeff, uint(nbBits), coeffLimbs); err != nil {
			return fmt.Errorf("decompose result[%d]: %w", idx, err)
		}
		copy(outputs[outptr:outptr+nbLimbs], coeffLimbs)
		outptr += nbLimbs
	}
	return nil
}

// evalPolyWithChallenge evaluates p at a point whose powers are given by at,
// where at[i] = at^i. Precomputing and sharing powers across multiple
// polynomial evaluations at the same point avoids redundant multiplications.
func (f *Field[T]) evalPolyWithChallenge(p *Poly[T], at []*Element[T]) *Element[T] {
	if p.evaluation == nil {
		p.evaluation = f.InnerProductNoReduce(p.Coeffs, at)
	}
	return p.evaluation
}

// innerProduct computes the inner product of two vectors of Element.
func (f *Field[T]) innerProduct(a, b []*Element[T]) *Element[T] {
	n := len(a)
	terms := make([][]*Element[T], n)
	scalars := make([]int, n)
	for i := range a {
		if b[i] == nil {
			terms[i] = []*Element[T]{a[i]}
		} else if a[i] == nil {
			terms[i] = []*Element[T]{b[i]}
		} else {
			terms[i] = []*Element[T]{a[i], b[i]}
		}
		scalars[i] = 1
	}
	return f.Eval(terms, scalars)
}

// InnerProductNoReduce computes the inner product of two vectors of
// *Element[T] without performing reduction.
func (f *Field[T]) InnerProductNoReduce(a, b []*Element[T]) *Element[T] {
	n := len(a)
	terms := make([]*Element[T], n)
	for i := 0; i < n; i++ {
		if a[i] == nil || b[i] == nil || len(b[i].Limbs) == 0 || len(a[i].Limbs) == 0 {
			// don't add anything, one of the multiplier is zero
		} else if len(b[i].Limbs) == 1 && b[i].Limbs[0] == 1 {
			terms[i] = a[i]
		} else if len(a[i].Limbs) == 1 && a[i].Limbs[0] == 1 {
			terms[i] = b[i]
		} else {
			terms[i] = f.MulNoReduce(a[i], b[i])
		}
	}
	var eval *Element[T]
	for _, term := range terms {
		if term != nil {
			if eval == nil {
				eval = term
			} else {
				eval = f.add(eval, term, max(eval.overflow, term.overflow)+1)
			}
		}
	}
	if eval == nil {
		return f.Zero()
	}
	return eval
}

// NativeToEmulated decomposes a native field variable into an *Element[T] by
// splitting its binary representation into emulated limbs of BitsPerLimb each.
func (f *Field[T]) NativeToEmulated(nbLimbs int, v ...frontend.Variable) []*Element[T] {
	nbBits := f.fParams.BitsPerLimb()
	hintInputs := make([]frontend.Variable, 0, 2+len(v))
	hintInputs = append(hintInputs, nbBits, nbLimbs)
	hintInputs = append(hintInputs, v...)
	ret, err := f.api.NewHint(splitNativeToLimbsHint, nbLimbs*len(v), hintInputs...)
	if err != nil {
		panic(fmt.Sprintf("NativeToEmulated hint error: %v", err))
	}
	elements := make([]*Element[T], len(v))
	for i := range elements {
		elements[i] = f.packLimbs(ret[i*nbLimbs:(i+1)*nbLimbs], false)
	}
	return elements
}

func splitNativeToLimbsHint(nativeMod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) < 3 {
		return fmt.Errorf("splitNativeToLimbs: not enough inputs")
	}

	nbBits := int(inputs[0].Int64())
	nbLimbs := int(inputs[1].Int64())
	outptr := 0
	for ptr := 2; ptr < len(inputs); ptr++ {
		nativeEl := inputs[ptr]
		coeffLimbs := make([]*big.Int, nativeEl.BitLen()/nbBits+1)
		for k := range coeffLimbs {
			coeffLimbs[k] = new(big.Int)
		}
		if err := limbs.Decompose(nativeEl, uint(nbBits), coeffLimbs); err != nil {
			return fmt.Errorf("decompose result[%d]: %w", ptr-2, err)
		}
		copy(outputs[outptr:outptr+nbLimbs], coeffLimbs[0:nbLimbs])
		outptr += nbLimbs
	}

	return nil
}

// serialisePoly converts a polynomial into a slice of frontend.Variable
// suitable for hints. format is nbTerms|...terms
func (f *Field[T]) serialisePoly(poly *Poly[T], inputs []frontend.Variable) []frontend.Variable {
	nbLimbs := int(f.fParams.NbLimbs())
	inputs = append(inputs, len(poly.Coeffs))
	for _, coeff := range poly.Coeffs {
		if coeff == nil || len(coeff.Limbs) == 0 {
			for i := 0; i < nbLimbs; i++ {
				inputs = append(inputs, 0)
			}
			continue
		}
		inputs = append(inputs, coeff.Limbs...)
		for i := len(coeff.Limbs); i < nbLimbs; i++ {
			inputs = append(inputs, 0)
		}
	}
	return inputs
}

type PolyConv[T FieldParams] interface {
	ToPoly() *Poly[T]
}

func (p *Poly[T]) ToPoly() *Poly[T] {
	return p
}
