package emulated

import (
	"errors"
	"fmt"
	"math/big"
	"math/bits"
	"slices"

	"github.com/consensys/gnark/frontend"
	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
	"github.com/consensys/gnark/std/math/fieldextension"
	"github.com/consensys/gnark/std/multicommit"
)

// deferredChecker is an interface for deferring a check in non-native
// arithmetic. The idea of the deferred check is that we do not compute the
// check immediately, but we store the values and the check to be done later.
// This allows us to share the verifier challenge computation between multiple
// checks.
//
// Currently used for multiplication and multivariate evaluation checks.
//
// The methods [evalRound1], [evalRound2] and [check] may receive as inputs
// either [frontend.Variable] or [fieldextension.Element]. The
// implementation should differentiate on the different input types and use the
// appropriate API (native or extension).
type deferredChecker interface {
	// toCommit outputs the variable which should be committed to. The checker
	// then uses the commitment to obtain the verifier challenge for the
	// Schwartz-Zippel lemma.
	toCommit() []frontend.Variable
	// maxLen returns the maximum number of limbs in the deferred check. This is
	// used for computing the number of powers of the verifier challenge to
	// compute
	maxLen() int

	// evalRound1 evaluates the first round of the check at with the random
	// challenge, given through its powers at. In the first round we do not
	// assume that any of the values is already evaluated as they come directly
	// from hint.
	//
	// The method should store the evaluation result inside the Element and mark
	// it as evaluated. If the method is called for already evaluated input then
	// should assume that the challenge is the same as the one used for the
	// evaluation.
	evalRound1(at []frontend.Variable)
	// evalRound2 evaluates the second round of the check at a given random point
	// at[0]. However, it may happen that some of the values are equal to the
	// result from a previous check. In that case we can reuse the evaluation to
	// save constraints.
	//
	// The method should store the evaluation result inside the Element and mark
	// it as evaluated. If the method is called for already evaluated input then
	// should assume that the challenge is the same as the one used for the
	// evaluation.
	evalRound2(at []frontend.Variable)
	// check checks the correctness of the deferred check. The method should use
	// the stored evaluations. We additionally provide the evaluation of
	// p(challenge) and (2^t-challenge) as they are static over all checks.
	check(api frontend.API, peval frontend.Variable, coef frontend.Variable)
	// cleanEvaluations cleans the cached evaluation values. This is necessary for
	// ensuring the circuit stability over many compilations.
	cleanEvaluations()
}

// mulCheck represents a single multiplication check. Instead of doing a
// multiplication exactly where called, we compute the result using hint and
// return it. Additionally, we store the correctness check for later checking
// (together with every other multiplication) to share the verifier challenge
// computation.
//
// With this approach this is important that we do not change the [Element]
// values after they are returned from [mulMod] as mulCheck keeps pointers and
// the check will fail if the values referred to by the pointers change. By
// following the [Field] public methods this shouldn't happen as we always take
// and return pointers, and to change the values the user has to explicitly
// dereference.
//
// We store the values a, b, r, k, c. They are as follows:
//   - a, b - the inputs what we are multiplying. Do not have to be reduced.
//   - r - the multiplication result reduced modulo the emulation parameter.
//   - k - the quotient for integer multiplication a*b divided by emulation parameter.
//   - c - element representing carry. Used only for aligning the limb widths.
//
// Given these values, the following holds:
//
//	a * b = r + k*p
//
// But for asserting that the previous equation holds, we instead use the
// polynomial representation of the elements. If a non-native element a is given
// by its limbs
//
//	a = (a_0, ..., a_n)
//
// then
//
//	a(X) = \sum_i a_i * X^i.
//
// Now, the multiplication check instead becomes
//
//	a(X) * b(X) = r(X) + k(X) * p(X) + (2^t-X) c(X),
//
// which can be checked only at a single random point. Here we need an
// additional polynomial c(X) which is used for carrying the overflow bits to
// the consecutive limbs. By subtracting 2^t c(X) we can remove the bits from
// the corresponding coefficients in r(X)+k(X)*p(X) and by adding X c(X) we can
// add the bits to X(r(X) + k(X) * p(X)) (i.e. to the next coefficient).
type mulCheck[T FieldParams] struct {
	f *Field[T]
	// a * b = r + k*p + c
	a, b *Element[T] // inputs
	r    *Element[T] // reduced value
	k    *Element[T] // coefficient
	c    *Element[T] // carry
	p    *Element[T] // modulus if non-nil
}

func (mc *mulCheck[T]) toCommit() []frontend.Variable {
	nbToCommit := len(mc.a.Limbs) + len(mc.b.Limbs) + len(mc.r.Limbs) + len(mc.k.Limbs) + len(mc.c.Limbs)
	if mc.p != nil {
		nbToCommit += len(mc.p.Limbs)
	}
	toCommit := make([]frontend.Variable, 0, nbToCommit)
	toCommit = append(toCommit, mc.a.Limbs...)
	toCommit = append(toCommit, mc.b.Limbs...)
	toCommit = append(toCommit, mc.r.Limbs...)
	toCommit = append(toCommit, mc.k.Limbs...)
	toCommit = append(toCommit, mc.c.Limbs...)
	if mc.p != nil {
		toCommit = append(toCommit, mc.p.Limbs...)
	}
	return toCommit
}

func (mc *mulCheck[T]) maxLen() int {
	maxLen := len(mc.a.Limbs)
	maxLen = max(maxLen, len(mc.b.Limbs))
	maxLen = max(maxLen, len(mc.r.Limbs))
	maxLen = max(maxLen, len(mc.k.Limbs))
	maxLen = max(maxLen, len(mc.c.Limbs))
	if mc.p != nil {
		maxLen = max(maxLen, len(mc.p.Limbs))
	}
	return maxLen
}

// evalRound1 evaluates first c(X), r(X) and k(X) at a given random point at[0].
// In the first round we do not assume that any of them is already evaluated as
// they come directly from hint.
func (mc *mulCheck[T]) evalRound1(at []frontend.Variable) {
	mc.c = mc.f.evalWithChallenge(mc.c, at)
	mc.r = mc.f.evalWithChallenge(mc.r, at)
	mc.k = mc.f.evalWithChallenge(mc.k, at)
	if mc.p != nil {
		mc.p = mc.f.evalWithChallenge(mc.p, at)
	}
}

// evalRound2 now evaluates a and b at a given random point at[0]. However, it
// may happen that a or b is equal to r from a previous mulcheck. In that case
// we can reuse the evaluation to save constraints.
func (mc *mulCheck[T]) evalRound2(at []frontend.Variable) {
	mc.a = mc.f.evalWithChallenge(mc.a, at)
	mc.b = mc.f.evalWithChallenge(mc.b, at)
}

// check checks a(ch) * b(ch) = r(ch) + k(ch) * p(ch) + (2^t - ch) c(ch). As the
// computation of p(ch) and (2^t-ch) can be shared over all mulCheck instances,
// then we get them already evaluated as peval and coef.
func (mc *mulCheck[T]) check(api frontend.API, peval, coef frontend.Variable) {
	if mc.p != nil {
		peval = mc.p.evaluation
	}
	// we either have to perform the equality check in the native field or in
	// the extension field. It was already determined at the [Field]
	// initialization time which kind of check needs to be done.
	if mc.f.extensionApi == nil {
		ls := api.Mul(mc.a.evaluation, mc.b.evaluation)
		rs := api.Add(mc.r.evaluation, api.Mul(peval, mc.k.evaluation), api.Mul(mc.c.evaluation, coef))
		api.AssertIsEqual(ls, rs)
	} else {
		// here we use the fact that [frontend.Variable] is defined as any, but
		// we have actually provided [ExtensionVariable]. We type assert to be
		// able to use the fieldextension API.
		//
		// the computations are same as in the previous conditional block, but
		// only in the extension.
		aext := mc.a.evaluation.(fieldextension.Element)
		bext := mc.b.evaluation.(fieldextension.Element)
		ls := mc.f.extensionApi.Mul(aext, bext)

		rext := mc.r.evaluation.(fieldextension.Element)
		pevalext := peval.(fieldextension.Element)
		cext := mc.c.evaluation.(fieldextension.Element)
		kext := mc.k.evaluation.(fieldextension.Element)
		coefext := coef.(fieldextension.Element)
		pkext := mc.f.extensionApi.Mul(pevalext, kext)
		ccoefext := mc.f.extensionApi.Mul(coefext, cext)

		rs := mc.f.extensionApi.Add(rext, pkext)
		rs = mc.f.extensionApi.Add(rs, ccoefext)

		mc.f.extensionApi.AssertIsEqual(ls, rs)
	}
}

// cleanEvaluations cleans the cached evaluation values. This is necessary for
// ensuring the circuit stability over many compilations.
func (mc *mulCheck[T]) cleanEvaluations() {
	mc.a.evaluation = 0
	mc.a.isEvaluated = false
	mc.b.evaluation = 0
	mc.b.isEvaluated = false
	mc.r.evaluation = 0
	mc.r.isEvaluated = false
	mc.k.evaluation = 0
	mc.k.isEvaluated = false
	mc.c.evaluation = 0
	mc.c.isEvaluated = false
	if mc.p != nil {
		mc.p.evaluation = 0
		mc.p.isEvaluated = false
	}
}

// mulMod returns a*b mod r. In practice it computes the result using a hint and
// defers the actual multiplication check.
func (f *Field[T]) mulMod(a, b *Element[T], _ uint, p *Element[T]) *Element[T] {
	// fast path - if one of the inputs is on zero limbs (it is zero), then the result is also zero
	if a.isStrictZero() || b.isStrictZero() {
		return f.Zero()
	}
	f.enforceWidthConditional(a)
	f.enforceWidthConditional(b)
	f.enforceWidthConditional(p)
	k, r, c, err := f.callMulHint(a, b, true, p)
	if err != nil {
		panic(err)
	}
	mc := mulCheck[T]{
		f: f,
		a: a,
		b: b,
		c: c,
		k: k,
		r: r,
		p: p,
	}
	f.deferredChecks = append(f.deferredChecks, &mc)
	return r
}

// checkZero creates multiplication check a * 1 = 0 + k*p.
func (f *Field[T]) checkZero(a *Element[T], p *Element[T]) {
	// fast path - the result is on zero limbs. This means that it is constant zero
	if a.isStrictZero() {
		return
	}
	// the method works similarly to mulMod, but we know that we are multiplying
	// by one and expected result should be zero.
	f.enforceWidthConditional(a)
	f.enforceWidthConditional(p)
	b := f.One()
	k, r, c, err := f.callMulHint(a, b, false, p)
	if err != nil {
		panic(err)
	}
	mc := mulCheck[T]{
		f: f,
		a: a,
		b: b, // one on single limb to speed up the polynomial evaluation
		c: c,
		k: k,
		r: r, // expected to be zero on zero limbs.
		p: p,
	}
	f.deferredChecks = append(f.deferredChecks, &mc)
}

// evalWithChallenge represents element a as a polynomial a(X) and evaluates at
// at[0]. For efficiency, we use already evaluated powers of at[0] given by at.
// It stores the evaluation result inside the Element and marks it as evaluated.
// If the method is called for already evaluated a then returns the known value.
func (f *Field[T]) evalWithChallenge(a *Element[T], at []frontend.Variable) *Element[T] {
	if a.isEvaluated {
		return a
	}
	if len(at) < len(a.Limbs)-1 {
		panic("evaluation powers less than limbs")
	}
	var sum frontend.Variable
	if f.extensionApi != nil {
		sum = f.evalWithChallengeExtension(a, at)
	} else {
		sum = f.evalWithChallengeNative(a, at)
	}
	a.isEvaluated = true
	a.evaluation = sum
	return a
}

func (f *Field[T]) evalWithChallengeNative(a *Element[T], at []frontend.Variable) frontend.Variable {
	var sum frontend.Variable = 0
	if len(a.Limbs) > 0 {
		sum = f.api.Mul(a.Limbs[0], 1) // copy because we use MulAcc
	}
	for i := 1; i < len(a.Limbs); i++ {
		sum = f.api.MulAcc(sum, a.Limbs[i], at[i-1])
	}
	return sum
}

func (f *Field[T]) evalWithChallengeExtension(a *Element[T], at []frontend.Variable) frontend.Variable {
	// even though at is []frontend.Variable, then we abuse the fact that
	// frontend.Variable is defined as any and at is []ExtensionVariable. We
	// type assert it.
	atext := make([]fieldextension.Element, len(at))
	for i := 0; i < len(at); i++ {
		atext[i] = at[i].(fieldextension.Element)
	}
	sum := f.extensionApi.Zero()
	if len(a.Limbs) > 0 {
		sum = f.extensionApi.AsExtensionVariable(a.Limbs[0])
	}
	for i := 1; i < len(a.Limbs); i++ {
		toAdd := f.extensionApi.MulByElement(atext[i-1], a.Limbs[i])
		sum = f.extensionApi.Add(sum, toAdd)
	}
	return sum
}

// performDeferredChecks should be deferred to actually perform all the
// multiplication checks.
func (f *Field[T]) performDeferredChecks(api frontend.API) error {
	// use given api. We are in defer and API may be different to what we have
	// stored.

	// there are no multiplication checks, nothing to do
	if len(f.deferredChecks) == 0 {
		return nil
	}

	// we construct a list of elements we want to commit to. Even though we have
	// committed when doing range checks, do it again here explicitly for safety.
	// TODO: committing is actually expensive in PLONK. We create a constraint
	// for every variable we commit to (to set the selector polynomial). So, it
	// is actually better not to commit again. However, if we would be to use
	// multi-commit and range checks are in different commitment, then we have
	// problem.
	var toCommit []frontend.Variable
	for i := range f.deferredChecks {
		toCommit = append(toCommit, f.deferredChecks[i].toCommit()...)
	}
	if f.extensionApi == nil {
		// we give all the inputs as inputs to obtain random verifier challenge.
		multicommit.WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
			// for efficiency, we compute all powers of the challenge as slice at.
			coefsLen := int(f.fParams.NbLimbs())
			for i := range f.deferredChecks {
				coefsLen = max(coefsLen, f.deferredChecks[i].maxLen())
			}
			at := make([]frontend.Variable, coefsLen)
			at[0] = commitment
			for i := 1; i < len(at); i++ {
				at[i] = api.Mul(at[i-1], commitment)
			}
			// evaluate all r, k, c
			for i := range f.deferredChecks {
				f.deferredChecks[i].evalRound1(at)
			}
			// assuming r is input to some other multiplication, then is already evaluated
			for i := range f.deferredChecks {
				f.deferredChecks[i].evalRound2(at)
			}
			// evaluate p(X) at challenge
			pval := f.evalWithChallenge(f.Modulus(), at)
			// compute (2^t-X) at challenge
			coef := big.NewInt(1)
			coef.Lsh(coef, f.fParams.BitsPerLimb())
			ccoef := api.Sub(coef, commitment)
			// verify all mulchecks
			for i := range f.deferredChecks {
				f.deferredChecks[i].check(api, pval.evaluation, ccoef)
			}
			// clean cached evaluation. Helps in case we compile the same circuit
			// multiple times.
			for i := range f.deferredChecks {
				f.deferredChecks[i].cleanEvaluations()
			}
			return nil
		}, toCommit...)
	} else {
		// this is the same as above, but we have challenges in the extension
		// field. The commitment argument below is actually extension field
		// element, but we give it as []frontend.Variable for interface
		// compatibility.
		multicommit.WithWideCommitment(api, func(api frontend.API, commitment []frontend.Variable) error {
			// for efficiency, we compute all powers of the challenge as slice at.
			coefsLen := int(f.fParams.NbLimbs())
			for i := range f.deferredChecks {
				coefsLen = max(coefsLen, f.deferredChecks[i].maxLen())
			}
			at := make([]fieldextension.Element, coefsLen)
			at[0] = commitment
			for i := 1; i < len(at); i++ {
				at[i] = f.extensionApi.Mul(at[i-1], commitment)
			}
			atv := make([]frontend.Variable, len(at))
			for i := range at {
				atv[i] = at[i]
			}
			// evaluate all r, k, c
			for i := range f.deferredChecks {
				f.deferredChecks[i].evalRound1(atv)
			}
			// assuming r is input to some other multiplication, then is already evaluated
			for i := range f.deferredChecks {
				f.deferredChecks[i].evalRound2(atv)
			}
			// evaluate p(X) at challenge
			pval := f.evalWithChallenge(f.Modulus(), atv)
			// compute (2^t-X) at challenge
			coef := big.NewInt(1)
			coef.Lsh(coef, f.fParams.BitsPerLimb())
			coefext := f.extensionApi.AsExtensionVariable(coef)
			ccoef := f.extensionApi.Sub(coefext, commitment)
			// verify all mulchecks
			for i := range f.deferredChecks {
				f.deferredChecks[i].check(api, pval.evaluation, ccoef)
			}
			// clean cached evaluation. Helps in case we compile the same circuit
			// multiple times.
			for i := range f.deferredChecks {
				f.deferredChecks[i].cleanEvaluations()
			}
			return nil
		}, f.extensionApi.Degree(), toCommit...)
	}
	return nil
}

// callMulHint uses hint to compute r, k and c.
func (f *Field[T]) callMulHint(a, b *Element[T], isMulMod bool, customMod *Element[T]) (quo, rem, carries *Element[T], err error) {
	// compute the expected overflow after the multiplication of a*b to be able
	// to estimate the number of bits required to represent the result.
	nextOverflow, _ := f.mulPreCond(a, b)
	// skip error handle - it happens when we are supposed to reduce. But we
	// already check it as a precondition. We only need the overflow here.
	if !isMulMod {
		// b is one on single limb. We do not increase the overflow
		nextOverflow = a.overflow
	}
	nbLimbs, nbBits := f.fParams.NbLimbs(), f.fParams.BitsPerLimb()
	// we need to compute the number of limbs for the quotient. To compute it,
	// we compute the width of the product of a*b, then we divide it by the
	// width of the modulus. We add 1 to the result to ensure that we have
	// enough space for the quotient.
	modbits := uint(f.fParams.Modulus().BitLen())
	if customMod != nil {
		// when we're using custom modulus, then we do not really know its
		// length ahead of time. We assume worst case scenario and assume that
		// the quotient can be the total length of the multiplication result.
		modbits = 0
	}
	var nbQuoLimbs uint
	if uint(nbMultiplicationResLimbs(len(a.Limbs), len(b.Limbs)))*nbBits+nextOverflow+nbBits > modbits {
		// when the product of a*b is wider than the modulus, then we need
		// non-zero limbs for the quotient. Otherwise the quotient is zero,
		// represented on zero limbs. But we already handle cases when the
		// quotient is zero in the calling functions, this is only for
		// additional safety.
		nbQuoLimbs = (uint(nbMultiplicationResLimbs(len(a.Limbs), len(b.Limbs)))*nbBits + nextOverflow + 1 - //
			modbits + //
			nbBits - 1) /
			nbBits
	}
	// the remainder is always less than modulus so can represent on the same
	// number of limbs as the modulus.
	nbRemLimbs := nbLimbs
	// we need to compute the number of limbs for the carries. It is maximum of
	// the number of limbs of the product of a*b or k*p.
	nbCarryLimbs := max(nbMultiplicationResLimbs(len(a.Limbs), len(b.Limbs)), nbMultiplicationResLimbs(int(nbQuoLimbs), int(nbLimbs))) - 1
	// we encode the computed parameters and widths to the hint function so can
	// know how many limbs to expect.
	modulusLimbs := f.Modulus().Limbs
	if customMod != nil {
		modulusLimbs = customMod.Limbs
	}
	hintInputs := make([]frontend.Variable, 0, 4+len(modulusLimbs)+len(a.Limbs)+len(b.Limbs))
	hintInputs = append(hintInputs, nbBits, nbLimbs, len(a.Limbs), nbQuoLimbs)
	hintInputs = append(hintInputs, modulusLimbs...)
	hintInputs = append(hintInputs, a.Limbs...)
	hintInputs = append(hintInputs, b.Limbs...)
	ret, err := f.api.NewHint(mulHint, int(nbQuoLimbs)+int(nbRemLimbs)+int(nbCarryLimbs), hintInputs...)
	if err != nil {
		err = fmt.Errorf("call hint: %w", err)
		return
	}
	// quotient is always range checked according to how many limbs we expect.
	quo = f.packLimbs(ret[:nbQuoLimbs], false)
	// remainder is always range checked when we use it as a result of
	// multiplication (and it needs to be strictly less than modulus). However,
	// when we use the hint for equality assertion then we assume the result to
	// be 0 which can be represented by 0 limbs.
	if isMulMod {
		rem = f.packLimbs(ret[nbQuoLimbs:nbQuoLimbs+nbRemLimbs], true)
	} else {
		rem = &Element[T]{}
	}
	// pack the carries into element. Used in the deferred multiplication check
	// to align the limbs due to different overflows.
	carries = f.newInternalElement(ret[nbQuoLimbs+nbRemLimbs:], 0)
	return
}

func mulHint(field *big.Int, inputs, outputs []*big.Int) error {
	nbBits := int(inputs[0].Int64())
	nbLimbs := int(inputs[1].Int64())
	nbALen := int(inputs[2].Int64())
	nbQuoLen := int(inputs[3].Int64())
	nbBLen := len(inputs) - 4 - nbLimbs - nbALen
	ptr := 4
	plimbs := inputs[ptr : ptr+nbLimbs]
	ptr += nbLimbs
	alimbs := inputs[ptr : ptr+nbALen]
	ptr += nbALen
	blimbs := inputs[ptr : ptr+nbBLen]

	nbCarryLen := max(nbMultiplicationResLimbs(nbALen, nbBLen), nbMultiplicationResLimbs(nbQuoLen, nbLimbs)) - 1
	outptr := 0
	quoLimbs := outputs[outptr : outptr+nbQuoLen]
	outptr += nbQuoLen
	remLimbs := outputs[outptr : outptr+nbLimbs]
	outptr += nbLimbs
	carryLimbs := outputs[outptr : outptr+nbCarryLen]

	p := new(big.Int)
	a := new(big.Int)
	b := new(big.Int)
	if err := limbs.Recompose(plimbs, uint(nbBits), p); err != nil {
		return fmt.Errorf("recompose p: %w", err)
	}
	if err := limbs.Recompose(alimbs, uint(nbBits), a); err != nil {
		return fmt.Errorf("recompose a: %w", err)
	}
	if err := limbs.Recompose(blimbs, uint(nbBits), b); err != nil {
		return fmt.Errorf("recompose b: %w", err)
	}
	quo := new(big.Int)
	rem := new(big.Int)
	ab := new(big.Int).Mul(a, b)
	if p.Cmp(new(big.Int)) != 0 {
		quo.QuoRem(ab, p, rem)
	}
	if err := limbs.Decompose(quo, uint(nbBits), quoLimbs); err != nil {
		return fmt.Errorf("decompose quo: %w", err)
	}
	if err := limbs.Decompose(rem, uint(nbBits), remLimbs); err != nil {
		return fmt.Errorf("decompose rem: %w", err)
	}
	// to compute the carries, we need to perform multiplication on limbs
	lhs := limbMul(alimbs, blimbs)
	rhs := limbMul(quoLimbs, plimbs)
	// add the remainder to the rhs, it now only has k*p. This is only for very
	// edge cases where by adding the remainder we get additional bits in the
	// carry.
	for i := range remLimbs {
		if i < len(rhs) {
			rhs[i].Add(rhs[i], remLimbs[i])
		} else {
			rhs = append(rhs, new(big.Int).Set(remLimbs[i]))
		}
	}
	carry := new(big.Int)
	for i := range carryLimbs {
		if i < len(lhs) {
			carry.Add(carry, lhs[i])
		}
		if i < len(rhs) {
			carry.Sub(carry, rhs[i])
		}
		carry.Rsh(carry, uint(nbBits))
		carryLimbs[i] = new(big.Int).Set(carry)
	}
	return nil
}

// Mul computes a*b and reduces it modulo the field order. The returned Element
// has default number of limbs and zero overflow. If the result wouldn't fit
// into Element, then locally reduces the inputs first. Doesn't mutate inputs.
//
// For multiplying by a constant, use [Field[T].MulConst] method which is more
// efficient.
func (f *Field[T]) Mul(a, b *Element[T]) *Element[T] {
	// fast path - if one of the inputs is on zero limbs (it is zero), then the result is also zero
	if a.isStrictZero() || b.isStrictZero() {
		return f.Zero()
	}
	return f.reduceAndOp(func(a, b *Element[T], u uint) *Element[T] { return f.mulMod(a, b, u, nil) }, f.mulPreCond, a, b)
}

// MulMod computes a*b and reduces it modulo the field order. The returned Element
// has default number of limbs and zero overflow.
//
// Equivalent to [Field[T].Mul], kept for backwards compatibility.
func (f *Field[T]) MulMod(a, b *Element[T]) *Element[T] {
	// fast path - if one of the inputs is on zero limbs (it is zero), then the result is also zero
	if a.isStrictZero() || b.isStrictZero() {
		return f.Zero()
	}
	return f.reduceAndOp(func(a, b *Element[T], u uint) *Element[T] { return f.mulMod(a, b, u, nil) }, f.mulPreCond, a, b)
}

// MulConst multiplies a by a constant c and returns it. We assume that the
// input constant is "small", so that we can compute the product by multiplying
// all individual limbs with the constant. If it is not small, then use the
// general [Field[T].Mul] or [Field[T].MulMod] with creating new Element from
// the constant on-the-fly.
func (f *Field[T]) MulConst(a *Element[T], c *big.Int) *Element[T] {
	if a.isStrictZero() {
		return f.Zero()
	}
	switch c.Sign() {
	case -1:
		return f.MulConst(f.Neg(a), new(big.Int).Neg(c))
	case 0:
		return f.Zero()
	}
	cbl := uint(c.BitLen())
	if cbl > f.maxOverflow() {
		panic(fmt.Sprintf("constant bit length %d exceeds max %d", cbl, f.maxOverflow()))
	}
	return f.reduceAndOp(
		func(a, _ *Element[T], u uint) *Element[T] {
			if ba, aConst := f.constantValue(a); aConst {
				ba.Mul(ba, c)
				return newConstElement[T](f.api.Compiler().Field(), ba, false)
			}
			limbs := make([]frontend.Variable, len(a.Limbs))
			for i := range a.Limbs {
				limbs[i] = f.api.Mul(a.Limbs[i], c)
			}
			return f.newInternalElement(limbs, a.overflow+cbl)
		},
		func(a, _ *Element[T]) (nextOverflow uint, err error) {
			nextOverflow = a.overflow + uint(cbl)
			if nextOverflow > f.maxOverflow() {
				err = overflowError{op: "mulConst", nextOverflow: nextOverflow, maxOverflow: f.maxOverflow()}
			}
			return
		},
		a, nil,
	)
}

func (f *Field[T]) mulPreCond(a, b *Element[T]) (nextOverflow uint, err error) {
	reduceRight := a.overflow < b.overflow
	nbResLimbs := nbMultiplicationResLimbs(len(a.Limbs), len(b.Limbs))
	nbLimbsOverflow := uint(1)
	if nbResLimbs > 0 {
		nbLimbsOverflow = uint(bits.Len(uint(nbResLimbs)))
	}
	nextOverflow = f.fParams.BitsPerLimb() + nbLimbsOverflow + a.overflow + b.overflow
	if nextOverflow > f.maxOverflow() {
		err = overflowError{op: "mul", nextOverflow: nextOverflow, maxOverflow: f.maxOverflow(), reduceRight: reduceRight}
	}
	return
}

// MulNoReduce computes a*b and returns the result without reducing it modulo
// the field order. The number of limbs of the returned element depends on the
// number of limbs of the inputs.
func (f *Field[T]) MulNoReduce(a, b *Element[T]) *Element[T] {
	// fast path - if one of the inputs is on zero limbs (it is zero), then the result is also zero
	if a.isStrictZero() || b.isStrictZero() {
		return f.Zero()
	}
	return f.reduceAndOp(f.mulNoReduce, f.mulPreCond, a, b)
}

func (f *Field[T]) mulNoReduce(a, b *Element[T], nextoverflow uint) *Element[T] {
	resLimbs := make([]frontend.Variable, nbMultiplicationResLimbs(len(a.Limbs), len(b.Limbs)))
	for i := range resLimbs {
		resLimbs[i] = 0
	}
	for i := range a.Limbs {
		for j := range b.Limbs {
			resLimbs[i+j] = f.api.MulAcc(resLimbs[i+j], a.Limbs[i], b.Limbs[j])
		}
	}
	return f.newInternalElement(resLimbs, nextoverflow)
}

// Exp computes base^exp modulo the field order. The returned Element has default
// number of limbs and zero overflow.
func (f *Field[T]) Exp(base, exp *Element[T]) *Element[T] {
	// fast path - if the base is zero, then the result is also zero
	if base.isStrictZero() {
		return f.Zero()
	}
	expBts := f.ToBits(exp)
	n := len(expBts)
	res := f.Select(expBts[0], base, f.One())
	base = f.Mul(base, base)
	for i := 1; i < n-1; i++ {
		res = f.Select(expBts[i], f.Mul(base, res), res)
		base = f.Mul(base, base)
	}
	res = f.Select(expBts[n-1], f.Mul(base, res), res)
	return res
}

// multivariate represents a multivariate polynomial. It is a list of terms
// where each term is a list of exponents for each variable. The coefficients
// are stored in the same order as the terms.
//
// For example, if there are two inputs x and y and we compute the polynomial
//
//	x^2 + 2xy + y^2
//
// then we have the terms
//
//	[[2, 0], [1, 1], [0, 2]]
//
// and coefficients
//
//	[1, 1, 1].
//
// These definitions differ from how we expose the method in the [Field.Eval]
// method - there as we use pointers to the variables themselves, then we can
// allow to give the inputs directly a la
//
//	f.Eval([][]*Element[T]{{x,x}, {x,y}, {y,y}}, []int{1, 1, 1}),
//
// but we cannot use the references inside the hint function as we work with
// solved values.
type multivariate[T FieldParams] struct {
	Terms        [][]int
	Coefficients []int
}

// Eval evaluates the multivariate polynomial. The elements of the inner slices
// are multiplied together and then summed together with the corresponding
// coefficient.
//
// NB! This is experimental API. It does not support negative coefficients. It
// does not check that computing the term wouldn't overflow the field.
//
// For example, for computing the expression x^2 + 2xy + y^2 we would call
//
//	f.Eval([][]*Element[T]{{x,x}, {x,y}, {y,y}}, []int{1, 2, 1})
//
// The method returns the result of the evaluation.
//
// To overcome the problem of not supporting negative coefficients, we can use a
// constant non-native element -1 as one of the inputs.
func (f *Field[T]) Eval(at [][]*Element[T], coefs []int) *Element[T] {
	if len(at) != len(coefs) {
		panic("terms and coefficients mismatch")
	}
	// it is the obvious case - when we don't have any inputs then we need to
	// evaluate the zero polynomial which is always zero.
	if len(at) == 0 {
		return f.Zero()
	}
	// omit the negative coefficients for now. We don't support it for now.
	for i := range coefs {
		if coefs[i] < 0 {
			panic("negative coefficient")
		}
	}
	// initialize the multivariate struct from the inputs. The current method
	// takes as input references to the elements. However, the hint function
	// works with solved values. So it would be better to work with the exact
	// exponents there.

	// we detect all different elements in the inputs.
	//
	// it would be easier to use a map to store the elements and then use the
	// map to get the inputs in the right order. However, for deterministic
	// circuit compilation we need to use the same order of inputs. So we use
	// slice instead.
	var allElems []*Element[T]
	for i := range at {
	AT_INNER:
		for j := range at[i] {
			for k := range allElems {
				if allElems[k] == at[i][j] {
					continue AT_INNER
				}
			}
			allElems = append(allElems, at[i][j])
		}
	}
	// we already know all different inputs. We now count the number of
	// occurrences in every term.
	terms := make([][]int, 0, len(at))
	for i := range at {
		term := make([]int, len(allElems))
		for j := range at[i] {
			term[slices.Index(allElems, at[i][j])]++
		}
		terms = append(terms, term)
	}

	// ensure that all the elements have the range checks enforced on limbs.
	// Necessary in case the input is a witness.
	for i := range allElems {
		f.enforceWidthConditional(allElems[i])
	}

	// multivariate is used for passing the terms and coefficients to the hint
	// in a compact form.
	mv := &multivariate[T]{
		Terms:        terms,
		Coefficients: coefs,
	}

	// we call the hint to compute the result. The hint returns the reduced
	// result, the quotient and the carries.
	k, r, c, err := f.callPolyMvHint(mv, allElems)
	if err != nil {
		panic(err)
	}

	// finally, we store the deferred check which is performed later. The
	// `mvCheck` implements the deferredChecker interface, so that we use the
	// generic deferred check method.
	mvc := mvCheck[T]{
		f:    f,
		mv:   mv,
		vals: allElems,
		r:    r,
		k:    k,
		c:    c,
	}

	f.deferredChecks = append(f.deferredChecks, &mvc)
	return r
}

// callPolyMvHint computes the multivariate evaluation given by mv at at. It
// returns the remainder (reduced result), the quotient and the carries. The
// computation is performed inside a hint, so it is the callers responsibility to
// perform the deferred multiplication check.
func (f *Field[T]) callPolyMvHint(mv *multivariate[T], at []*Element[T]) (quo, rem, carries *Element[T], err error) {
	// first compute the length of the result so that we know how many bits we need for the quotient.
	nbLimbs, nbBits := f.fParams.NbLimbs(), f.fParams.BitsPerLimb()
	modBits := uint(f.fParams.Modulus().BitLen())
	quoSize := f.polyMvEvalQuoSize(mv, at)
	var nbQuoLimbs uint
	if quoSize+nbBits > modBits {
		nbQuoLimbs = (quoSize - modBits + nbBits) / nbBits
	}
	nbRemLimbs := nbLimbs
	nbCarryLimbs := nbMultiplicationResLimbs(int(nbQuoLimbs), int(nbLimbs)) - 1

	nbHintInputs := 7 + len(at)*len(mv.Terms) + len(mv.Coefficients) + len(f.Modulus().Limbs)
	for i := range at {
		nbHintInputs += len(at[i].Limbs) + 1
	}
	hintInputs := make([]frontend.Variable, 0, nbHintInputs)
	hintInputs = append(hintInputs, nbBits, nbLimbs, len(mv.Terms), len(at), nbQuoLimbs, nbCarryLimbs)
	// store the terms in the hint input. First the exponents
	for i := range mv.Terms {
		for j := range mv.Terms[i] {
			hintInputs = append(hintInputs, mv.Terms[i][j])
		}
	}
	// and now the coefficients
	for i := range mv.Coefficients {
		hintInputs = append(hintInputs, mv.Coefficients[i])
	}
	// finally, we store the modulus and all the inputs
	hintInputs = append(hintInputs, f.Modulus().Limbs...)
	for i := range at {
		// keep in mind that not all inputs may be full length. We need to store
		// the length also.
		hintInputs = append(hintInputs, len(at[i].Limbs))
		hintInputs = append(hintInputs, at[i].Limbs...)
	}
	ret, err := f.api.NewHint(polyMvHint, int(nbQuoLimbs)+int(nbRemLimbs)+int(nbCarryLimbs), hintInputs...)
	if err != nil {
		err = fmt.Errorf("call hint: %w", err)
		return
	}
	quo = f.packLimbs(ret[:nbQuoLimbs], false)
	rem = f.packLimbs(ret[nbQuoLimbs:nbQuoLimbs+nbRemLimbs], true)
	carries = f.newInternalElement(ret[nbQuoLimbs+nbRemLimbs:], 0)
	return quo, rem, carries, nil
}

// mvCheck is a deferred check for multivariate polynomial evaluation. It
// contains the multivariate polynomial, the values at which it is evaluated and
// the reduced result, quotient and carries. Implements deferredChecker and
// follows mulCheck implementation.
type mvCheck[T FieldParams] struct {
	f    *Field[T]
	mv   *multivariate[T]
	vals []*Element[T]
	r    *Element[T] // reduced result
	k    *Element[T] // quotient
	c    *Element[T] // carry
}

func (mc *mvCheck[T]) toCommit() []frontend.Variable {
	nbToCommit := len(mc.r.Limbs) + len(mc.k.Limbs) + len(mc.c.Limbs)
	for j := range mc.vals {
		nbToCommit += len(mc.vals[j].Limbs)
	}
	toCommit := make([]frontend.Variable, 0, nbToCommit)
	toCommit = append(toCommit, mc.r.Limbs...)
	toCommit = append(toCommit, mc.k.Limbs...)
	toCommit = append(toCommit, mc.c.Limbs...)
	for j := range mc.vals {
		toCommit = append(toCommit, mc.vals[j].Limbs...)
	}
	return toCommit
}

func (mc *mvCheck[T]) maxLen() int {
	maxLen := len(mc.r.Limbs)
	maxLen = max(maxLen, len(mc.k.Limbs))
	maxLen = max(maxLen, len(mc.c.Limbs))
	for j := range mc.vals {
		maxLen = max(maxLen, len(mc.vals[j].Limbs))
	}
	return maxLen
}

func (mc *mvCheck[T]) evalRound1(at []frontend.Variable) {
	mc.c = mc.f.evalWithChallenge(mc.c, at)
	mc.r = mc.f.evalWithChallenge(mc.r, at)
	mc.k = mc.f.evalWithChallenge(mc.k, at)
}

func (mc *mvCheck[T]) evalRound2(at []frontend.Variable) {
	for i := range mc.vals {
		mc.vals[i] = mc.f.evalWithChallenge(mc.vals[i], at)
	}
}

// check checks that the multivariate polynomial f(x1(ch), x2(ch), ...) = r(ch)
// + k(ch)*p(ch) + (2^t-ch) c(ch) holds. As p and (2^t-ch) are same over all
// checks then we get them as arguments to this method.
func (mc *mvCheck[T]) check(api frontend.API, peval, coef frontend.Variable) {
	// we either have to perform the equality check in the native field or in
	// the extension field. It was already determined at the [Field]
	// initialization time which kind of check needs to be done.
	if mc.f.extensionApi == nil {
		ls := frontend.Variable(0)
		for i, term := range mc.mv.Terms {
			termProd := frontend.Variable(mc.mv.Coefficients[i])
			for i, pow := range term {
				for j := 0; j < pow; j++ {
					termProd = api.Mul(termProd, mc.vals[i].evaluation)
				}
			}
			ls = api.Add(ls, termProd)
		}
		rs := api.Add(mc.r.evaluation, api.Mul(peval, mc.k.evaluation), api.Mul(mc.c.evaluation, coef))
		api.AssertIsEqual(ls, rs)
	} else {
		// here we use the fact that [frontend.Variable] is defined as any, but
		// we have actually provided [ExtensionVariable]. We type assert to be
		// able to use the fieldextension API.
		//
		// the computations are same as in the previous conditional block, but
		// only in the extension.
		ls := mc.f.extensionApi.Zero()
		for i, term := range mc.mv.Terms {
			termProd := mc.f.extensionApi.AsExtensionVariable(mc.mv.Coefficients[i])
			for i, pow := range term {
				for j := 0; j < pow; j++ {
					valsexti := mc.vals[i].evaluation.(fieldextension.Element)
					termProd = mc.f.extensionApi.Mul(termProd, valsexti)
				}
			}
			ls = mc.f.extensionApi.Add(ls, termProd)
		}
		rext := mc.r.evaluation.(fieldextension.Element)
		pevalext := peval.(fieldextension.Element)
		kext := mc.k.evaluation.(fieldextension.Element)
		cext := mc.c.evaluation.(fieldextension.Element)
		coefext := coef.(fieldextension.Element)

		pkext := mc.f.extensionApi.Mul(pevalext, kext)
		ccoefext := mc.f.extensionApi.Mul(coefext, cext)

		rs := mc.f.extensionApi.Add(rext, pkext)
		rs = mc.f.extensionApi.Add(rs, ccoefext)

		mc.f.extensionApi.AssertIsEqual(ls, rs)
	}
}

func (mc *mvCheck[T]) cleanEvaluations() {
	for i := range mc.vals {
		mc.vals[i].evaluation = 0
		mc.vals[i].isEvaluated = false
	}
	mc.r.evaluation = 0
	mc.r.isEvaluated = false
	mc.k.evaluation = 0
	mc.k.isEvaluated = false
	mc.c.evaluation = 0
	mc.c.isEvaluated = false
}

// polyMvEvalQuoSize compute the length of the quotient in bits when evaluating
// the multivariate polynomial. The method is used to compute the number of bits
// required to represent the quotient in the hint function.
//
// As it only depends on the bit-length of the inputs, then we can precompute it
// regardless of the actual values.
func (f *Field[T]) polyMvEvalQuoSize(mv *multivariate[T], at []*Element[T]) (quoSize uint) {
	if len(mv.Terms) == 0 {
		return 0
	}
	quoSizes := make([]uint, len(mv.Terms))
	for i, term := range mv.Terms {
		// for every term, the result length is the sum of the lengths of the
		// variables and the coefficient.
		var lengths []uint
		for j, pow := range term {
			for k := 0; k < pow; k++ {
				lengths = append(lengths, uint(len(at[j].Limbs))*f.fParams.BitsPerLimb()+at[j].overflow)
			}
		}
		lengths = append(lengths, uint(bits.Len(uint(mv.Coefficients[i]))))
		if lengthSum := sum(lengths...); lengthSum > 0 {
			// in edge case when inputs are zeros and coefficient is zero, we
			// would have a underflow otherwise.
			quoSizes[i] = lengthSum - 1
		}
	}
	// and for the full result, it is maximum of the inputs. We also add a bit
	// for every term for overflow.
	quoSize = slices.Max(quoSizes) + uint(len(quoSizes))
	return quoSize
}

// polyMvHint computes the multivariate evaluation as a hint. Should not be
// called directly, but rather through [Field.callPolyMvHint] method which
// handles the input packing and output unpacking.
func polyMvHint(mod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) < 7 {
		return errors.New("not enough inputs")
	}
	var (
		nbBits       = int(inputs[0].Int64())
		nbLimbs      = int(inputs[1].Int64())
		nbTerms      = int(inputs[2].Int64())
		nbVars       = int(inputs[3].Int64())
		nbQuoLimbs   = int(inputs[4].Int64())
		nbRemLimbs   = nbLimbs
		nbCarryLimbs = int(inputs[5].Int64())
	)
	if len(outputs) != nbQuoLimbs+nbRemLimbs+nbCarryLimbs {
		return errors.New("output length mismatch")
	}
	outPtr := 0
	quoLimbs := outputs[outPtr : outPtr+nbQuoLimbs]
	outPtr += nbQuoLimbs
	remLimbs := outputs[outPtr : outPtr+nbRemLimbs]
	outPtr += nbRemLimbs
	carryLimbs := outputs[outPtr : outPtr+nbCarryLimbs]
	terms := make([][]int, nbTerms)
	ptr := 6
	// read the terms
	for i := range terms {
		terms[i] = make([]int, nbVars)
		for j := range terms[i] {
			terms[i][j] = int(inputs[ptr].Int64())
			ptr++
		}
	}
	// read the coefficients
	coeffs := make([]*big.Int, nbTerms)
	for i := range coeffs {
		coeffs[i] = inputs[ptr]
		ptr++
	}
	// read the modulus
	plimbs := inputs[ptr : ptr+nbLimbs]
	ptr += nbLimbs
	p := new(big.Int)
	if err := limbs.Recompose(plimbs, uint(nbBits), p); err != nil {
		return fmt.Errorf("recompose p: %w", err)
	}
	// read the inputs
	varsLimbs := make([][]*big.Int, nbVars)
	for i := range varsLimbs {
		varsLimbs[i] = make([]*big.Int, int(inputs[ptr].Int64()))
		ptr++
		for j := range varsLimbs[i] {
			varsLimbs[i][j] = inputs[ptr]
			ptr++
		}
	}
	if ptr != len(inputs) {
		return errors.New("inputs not exhausted")
	}
	// recompose the inputs in limb-form to *big.Int form
	vars := make([]*big.Int, nbVars)
	for i := range vars {
		vars[i] = new(big.Int)
		if err := limbs.Recompose(varsLimbs[i], uint(nbBits), vars[i]); err != nil {
			return fmt.Errorf("recompose vars[%d]: %w", i, err)
		}
	}

	// compute the result on full inputs
	fullLhs := new(big.Int)
	for i, term := range terms {
		termRes := new(big.Int).Set(coeffs[i])
		for i, pow := range term {
			for j := 0; j < pow; j++ {
				termRes.Mul(termRes, vars[i])
			}
		}
		fullLhs.Add(fullLhs, termRes)
	}

	// compute the result as r + k*p for now
	var (
		quo = new(big.Int)
		rem = new(big.Int)
	)
	if p.Cmp(new(big.Int)) != 0 {
		quo.QuoRem(fullLhs, p, rem)
	}
	// write the remainder and quotient to output
	if err := limbs.Decompose(quo, uint(nbBits), quoLimbs); err != nil {
		return fmt.Errorf("decompose quo: %w", err)
	}
	if err := limbs.Decompose(rem, uint(nbBits), remLimbs); err != nil {
		return fmt.Errorf("decompose rem: %w", err)
	}

	// compute the result on limbs
	tmp := new(big.Int)
	var lhs []*big.Int
	for i, term := range terms {
		// collect the variables to be multiplied together
		var termVarLimbs [][]*big.Int
		for i, pow := range term {
			for j := 0; j < pow; j++ {
				termVarLimbs = append(termVarLimbs, varsLimbs[i])
			}
		}
		if len(termVarLimbs) == 0 {
			continue
		}
		termRes := []*big.Int{new(big.Int).Set(coeffs[i])}
		// perform limbwise multiplication
		for _, toMul := range termVarLimbs {
			termRes = limbMul(termRes, toMul)
		}
		// add current term to the result. Increase the length of necessary when
		// required.
		for i := len(lhs); i < len(termRes); i++ {
			lhs = append(lhs, new(big.Int))
		}
		for i := range termRes {
			lhs[i].Add(lhs[i], termRes[i])
		}
	}

	// compute the result as r + k*p on limbs
	rhs := make([]*big.Int, max(nbLimbs, nbMultiplicationResLimbs(nbQuoLimbs, nbLimbs)))
	for i := range rhs {
		rhs[i] = new(big.Int)
	}
	for i := 0; i < nbLimbs; i++ {
		rhs[i].Add(rhs[i], remLimbs[i])
		for j := 0; j < nbQuoLimbs; j++ {
			tmp.Mul(quoLimbs[j], plimbs[i])
			rhs[i+j].Add(rhs[i+j], tmp)
		}
	}

	// compute the carries
	carry := new(big.Int)
	for i := range carryLimbs {
		if i < len(lhs) {
			carry.Add(carry, lhs[i])
		}
		if i < len(rhs) {
			carry.Sub(carry, rhs[i])
		}
		carry.Rsh(carry, uint(nbBits))
		carryLimbs[i] = new(big.Int).Set(carry)
	}

	return nil
}

func limbMul(lhs []*big.Int, rhs []*big.Int) []*big.Int {
	tmp := new(big.Int)
	res := make([]*big.Int, nbMultiplicationResLimbs(len(lhs), len(rhs)))
	for i := range res {
		res[i] = new(big.Int)
	}
	for i := 0; i < len(lhs); i++ {
		for j := 0; j < len(rhs); j++ {
			res[i+j].Add(res[i+j], tmp.Mul(lhs[i], rhs[j]))
		}
	}
	return res
}
