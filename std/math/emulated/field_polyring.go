package emulated

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
)

// Represents an element of a polynomial ring over the emulated field.
type Poly[T FieldParams] struct {
	Coeffs     []*Element[T]
	evaluation *big.Int // nil unless evaluated
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

type GroupName string

// polyRingCheckManager manages deferred polynomial ring checks
type polyRingCheckManager[T FieldParams] struct {
	groupsMapOrder []GroupName                     // deterministic order of map
	groups         map[GroupName]*polyRingGroup[T] // groupName -> group -> checks
}

// polyRingGroup binds a specific modulus to all of its checks.
type polyRingGroup[T FieldParams] struct {
	mod    *Poly[T]              // polynomial defining the ring
	rlen   int                   // length of the remainder
	checks []polyRingMulCheck[T] // individual operations to check
}

// polyRingMulCheck is an individual deferred check.
type polyRingMulCheck[T FieldParams] struct {
	// ∏_i inputs_i = r + q * mod
	inputs []*Poly[T] // input polynomials
	r      *Poly[T]   // remainder
	q      *Poly[T]   // quotient
}

// RegisterPolyRing registers a new polynomial ring group with the given name and modulus. The
func (f *Field[T]) RegisterPolyRing(groupName GroupName, mod *Poly[T]) error {
	if f.deferredPolyChecker == nil {
		f.deferredPolyChecker = &polyRingCheckManager[T]{
			groupsMapOrder: []GroupName{},
			groups:         make(map[GroupName]*polyRingGroup[T]),
		}
	}
	if _, exists := f.deferredPolyChecker.groups[groupName]; exists {
		return fmt.Errorf("Ring with name %s already registered", groupName)
	}
	f.deferredPolyChecker.groupsMapOrder = append(f.deferredPolyChecker.groupsMapOrder, groupName)
	f.deferredPolyChecker.groups[groupName] = &polyRingGroup[T]{
		mod:    mod,
		checks: []polyRingMulCheck[T]{},
	}

	return nil
}

// CallPolyRingMulHint computes a polynomial product check in a polynomial ring,
// returns the remainder (reduced result) and the quotient. The computation
// is performed inside a hint, so it is the callers responsibility to perform
// the deferred polynomial ring multiplication check.
func (f *Field[T]) CallPolyRingMulHint(inputs []*Poly[T], groupName GroupName) (quo, rem *Poly[T], err error) {

	group, ringGroupExists := f.deferredPolyChecker.groups[groupName]

	if !ringGroupExists {
		return nil, nil, fmt.Errorf("group with name %s does not exist", groupName)
	}

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
		// serialised as nbTerms|...terms
		// add degree of each input polynomial
		hintInputs = append(hintInputs, len(inputPoly.Coeffs))
		// append each term from inputPoly polynomial
		for _, coeff := range inputPoly.Coeffs {
			hintInputs = append(hintInputs, coeff.Limbs...)
		}
	}

	hintInputs = append(hintInputs, len(mod.Coeffs))
	// append mod terms
	for _, coeff := range mod.Coeffs {
		hintInputs = append(hintInputs, coeff.Limbs...)
	}

	// call
	ret, err := f.api.NewHint(polyRingMulHint, 1+nbQTermsLimbs+1+nbRemLimbs, hintInputs...)

	if err != nil {
		return nil, nil, err
	}

	// unpack quotient: skip nbQTerms header, then read (1+qDegree) terms of nbLimbs each
	quo = &Poly[T]{Coeffs: make([]*Element[T], 1+qDegree)}
	retPtr := 1 // skip nbQTerms
	for i := range quo.Coeffs {
		termLimbs := ret[retPtr : retPtr+nbLimbs]
		retPtr += nbLimbs
		quo.Coeffs[i] = f.packLimbs(termLimbs, false)
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

	return quo, rem, nil
}

// polyRingMulHint computes the multivariate evaluation as a hint. Should not be
// called directly, but rather through [Field.callPolyRingMulHint] method which
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
	nativeMod := f.api.Compiler().Field()

	poly := &Poly[T]{}
	poly.Coeffs = make([]*Element[T], len(coeffs))

	for i, coeff := range coeffs {
		emCoeff_ := ValueOf[T](coeff)
		emCoeff := &emCoeff_
		emCoeff.Initialize(nativeMod)
		poly.Coeffs[i] = emCoeff
	}

	return poly
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
	hintInputs := make([]frontend.Variable, 0, 5+nbPolys)
	hintInputs = append(hintInputs, nbBits, nbLimbs, nbPolys, *f.fParams.Modulus(), z)

	for _, q := range quotients {
		hintInputs = append(hintInputs, len(q.Coeffs))
		for _, coeff := range q.Coeffs {
			hintInputs = append(hintInputs, coeff.Limbs...)
		}
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
	nbPolys := int(inputs[2].Int64())
	fieldMod := new(big.Int).Set(inputs[3])
	z := new(big.Int).Mod(inputs[4], fieldMod)

	ptr := 5
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
	n := len(p.Coeffs)
	terms := make([][]*Element[T], n)
	scalars := make([]int, n)
	for i, coeff := range p.Coeffs {
		if i == 0 {
			terms[i] = []*Element[T]{coeff}
		} else {
			terms[i] = []*Element[T]{coeff, at[i]}
		}
		scalars[i] = 1
	}
	return f.Eval(terms, scalars)
}

// @TODO probably ugly, find something in gnark to do this
// nativeToEmulated decomposes a native field variable into an *Element[T] by
// splitting its binary representation into emulated limbs of BitsPerLimb each.
func (f *Field[T]) nativeToEmulated(v frontend.Variable) *Element[T] {
	nbBitsPerLimb := int(f.fParams.BitsPerLimb())
	nbLimbs := int(f.fParams.NbLimbs())
	nativeBits := f.api.Compiler().FieldBitLen()
	bits := f.api.ToBinary(v, nativeBits)
	limbVars := make([]frontend.Variable, nbLimbs)
	for i := 0; i < nbLimbs; i++ {
		bi := i * nbBitsPerLimb
		if bi+nbBitsPerLimb >= nativeBits {
			limbVars[i] = f.api.FromBinary(bits[bi:]...)
			break
		} else {
			limbVars[i] = f.api.FromBinary(bits[bi : bi+nbBitsPerLimb]...)
		}
	}
	return f.NewElement(limbVars)
}
