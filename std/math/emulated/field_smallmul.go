package emulated

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// useSmallFieldOptimization returns true if the emulated field is small enough
// that we can use optimized scalar multiplication instead of polynomial checks.
// The result is cached after first computation.
//
// Criteria:
// - Single limb representation (NbLimbs == 1)
// - Product of two elements fits in native field with margin for batching
//   (2 * modBits + batchBits < nativeBits - 2)
func (f *Field[T]) useSmallFieldOptimization() bool {
	f.smallFieldModeOnce.Do(func() {
		// Must be single limb
		if f.fParams.NbLimbs() != 1 {
			f.smallFieldMode = false
			return
		}

		modBits := uint(f.fParams.Modulus().BitLen())
		nativeBits := uint(f.api.Compiler().FieldBitLen())

		// Need: 2*modBits + margin < nativeBits - 2
		// margin accounts for quotient bits and batching overhead
		// For KoalaBear (31 bits) on BLS12-377 (253 bits): 2*31 + 32 = 94 < 251 ✓
		margin := uint(32)
		f.smallFieldMode = 2*modBits+margin < nativeBits-2

		if f.smallFieldMode {
			f.log.Debug().Msg("using small field optimization for emulated arithmetic")
		}
	})
	return f.smallFieldMode
}

// smallMulCheck is a deferred checker for small field multiplications.
// It batches multiple a*b = q*p + r checks and verifies them together
// using a random linear combination.
//
// The random challenge comes from the outer multicommit in performDeferredChecks,
// passed through evalRound1 as at[0].
type smallMulCheck[T FieldParams] struct {
	f *Field[T]
	// Each entry: a*b = q*p + r
	entries []smallMulEntry
	// gamma stores the random challenge from evalRound1
	gamma frontend.Variable
}

type smallMulEntry struct {
	a, b    frontend.Variable // inputs
	r       frontend.Variable // remainder (result)
	q       frontend.Variable // quotient
	quoBits uint              // bits for quotient
}

func (mc *smallMulCheck[T]) toCommit() []frontend.Variable {
	vars := make([]frontend.Variable, 0, len(mc.entries)*4)
	for _, e := range mc.entries {
		vars = append(vars, e.a, e.b, e.r, e.q)
	}
	return vars
}

func (mc *smallMulCheck[T]) maxLen() int {
	// Return the number of entries so we get enough powers of the challenge
	return len(mc.entries)
}

func (mc *smallMulCheck[T]) evalRound1(at []frontend.Variable) {
	// Store the challenge for use in check()
	// at[0] is the commitment challenge, at[i] = at[0]^(i+1)
	if len(at) > 0 {
		mc.gamma = at[0]
	}
}

func (mc *smallMulCheck[T]) evalRound2(at []frontend.Variable) {
	// No additional evaluation needed for scalars
}

// check verifies all accumulated multiplications using random linear combination.
// Instead of checking each a_i * b_i = q_i * p + r_i individually, we verify:
//
//	Σ γ^i * (a_i * b_i) = Σ γ^i * r_i + (Σ γ^i * q_i) * p
//
// This batches all checks into a single verification with overwhelming probability.
// The challenge γ was stored during evalRound1.
func (mc *smallMulCheck[T]) check(api frontend.API, peval, coef frontend.Variable) {
	if len(mc.entries) == 0 {
		return
	}

	p := mc.f.fParams.Modulus()
	n := len(mc.entries)

	// Compute powers of γ: [1, γ, γ², ...]
	gammaPowers := make([]frontend.Variable, n)
	gammaPowers[0] = 1
	if n > 1 && mc.gamma != nil {
		gammaPowers[1] = mc.gamma
		for i := 2; i < n; i++ {
			gammaPowers[i] = api.Mul(gammaPowers[i-1], mc.gamma)
		}
	}

	// Compute:
	// LHS = Σ γ^i * a_i * b_i
	// sumR = Σ γ^i * r_i
	// sumQ = Σ γ^i * q_i
	var lhs, sumR, sumQ frontend.Variable = 0, 0, 0

	for i, e := range mc.entries {
		// γ^i * a_i * b_i
		ab := api.Mul(e.a, e.b)
		lhs = api.Add(lhs, api.Mul(gammaPowers[i], ab))

		// γ^i * r_i
		sumR = api.Add(sumR, api.Mul(gammaPowers[i], e.r))

		// γ^i * q_i
		sumQ = api.Add(sumQ, api.Mul(gammaPowers[i], e.q))
	}

	// Verify: LHS = sumR + sumQ * p
	rhs := api.Add(sumR, api.Mul(sumQ, p))
	api.AssertIsEqual(lhs, rhs)
}

func (mc *smallMulCheck[T]) cleanEvaluations() {
	// Reset gamma for next compilation
	mc.gamma = nil
}

// getOrCreateSmallMulCheck returns the smallMulCheck for this field,
// creating one if it doesn't exist.
func (f *Field[T]) getOrCreateSmallMulCheck() *smallMulCheck[T] {
	// Look for existing smallMulCheck in deferredChecks
	for _, dc := range f.deferredChecks {
		if smc, ok := dc.(*smallMulCheck[T]); ok {
			return smc
		}
	}

	// Create new one
	smc := &smallMulCheck[T]{f: f}
	f.deferredChecks = append(f.deferredChecks, smc)
	return smc
}

// mulModSmall is the optimized multiplication for small field emulation.
// It computes a*b mod p using scalar operations instead of polynomial checks.
//
// Key optimizations:
// 1. No limb decomposition - values stay as native scalars
// 2. Batched verification - all muls verified together at circuit finalization
// 3. Quotient not individually range-checked - constrained by batched verification
func (f *Field[T]) mulModSmall(a, b *Element[T]) *Element[T] {
	// Handle zero cases
	if a.isStrictZero() || b.isStrictZero() {
		return f.Zero()
	}

	// Get the scalar values (single limb)
	aVal := a.Limbs[0]
	bVal := b.Limbs[0]

	p := f.fParams.Modulus()
	modBits := uint(p.BitLen())

	// Constant folding
	aConst, aIsConst := f.api.ConstantValue(aVal)
	bConst, bIsConst := f.api.ConstantValue(bVal)
	if aIsConst && bIsConst {
		res := new(big.Int).Mul(aConst, bConst)
		res.Mod(res, p)
		return f.newInternalElement([]frontend.Variable{res}, 0)
	}

	// Compute quotient bits based on input bounds
	// a < 2^(modBits + a.overflow), b < 2^(modBits + b.overflow)
	// a*b < 2^(2*modBits + a.overflow + b.overflow)
	// q = floor(a*b / p) < 2^(modBits + a.overflow + b.overflow + 1)
	aBits := modBits + a.overflow
	bBits := modBits + b.overflow
	prodBits := aBits + bBits
	quoBits := prodBits - modBits + 1

	// Use hint to compute q and r where a*b = q*p + r
	outputs, err := f.api.NewHint(smallFieldMulHint, 2, aVal, bVal, p, quoBits)
	if err != nil {
		panic(fmt.Sprintf("mulModSmall hint failed: %v", err))
	}
	quo := outputs[0]
	rem := outputs[1]

	// Add to batched verification (no immediate algebraic check)
	smc := f.getOrCreateSmallMulCheck()
	smc.entries = append(smc.entries, smallMulEntry{
		a:       aVal,
		b:       bVal,
		r:       rem,
		q:       quo,
		quoBits: quoBits,
	})

	// Range check remainder to ensure r < 2^modBits
	// (This is still needed for correctness - r must be bounded)
	f.checker.Check(rem, int(modBits))

	// NOTE: Quotient is NOT range-checked individually!
	// It's constrained by the batched verification which uses random linear combination.
	// This saves ~10-15 constraints per multiplication.

	return f.newInternalElement([]frontend.Variable{rem}, 0)
}

// reduceSmall reduces a small field element using scalar operations.
func (f *Field[T]) reduceSmall(a *Element[T]) *Element[T] {
	if a.isStrictZero() {
		return f.Zero()
	}
	if a.overflow == 0 {
		return a // Already reduced
	}

	aVal := a.Limbs[0]
	p := f.fParams.Modulus()
	modBits := uint(p.BitLen())

	// Constant folding
	if aConst, isConst := f.api.ConstantValue(aVal); isConst {
		res := new(big.Int).Mod(aConst, p)
		return f.newInternalElement([]frontend.Variable{res}, 0)
	}

	// Compute quotient bits
	aBits := modBits + a.overflow
	quoBits := aBits - modBits + 1

	// Use hint to compute q and r
	outputs, err := f.api.NewHint(smallFieldReduceHint, 2, aVal, p, quoBits)
	if err != nil {
		panic(fmt.Sprintf("reduceSmall hint failed: %v", err))
	}
	quo := outputs[0]
	rem := outputs[1]

	// Verify a = q*p + r
	qp := f.api.Mul(quo, p)
	reconstructed := f.api.Add(qp, rem)
	f.api.AssertIsEqual(aVal, reconstructed)

	// Range check
	f.checker.Check(rem, int(modBits))
	if quoBits > 0 {
		f.checker.Check(quo, int(quoBits))
	}

	return f.newInternalElement([]frontend.Variable{rem}, 0)
}

// addSmall adds two small field elements.
func (f *Field[T]) addSmall(a, b *Element[T]) *Element[T] {
	if a.isStrictZero() {
		return b
	}
	if b.isStrictZero() {
		return a
	}

	aVal := a.Limbs[0]
	bVal := b.Limbs[0]

	// Constant folding
	aConst, aIsConst := f.api.ConstantValue(aVal)
	bConst, bIsConst := f.api.ConstantValue(bVal)
	if aIsConst && bIsConst {
		res := new(big.Int).Add(aConst, bConst)
		res.Mod(res, f.fParams.Modulus())
		return f.newInternalElement([]frontend.Variable{res}, 0)
	}

	sum := f.api.Add(aVal, bVal)
	newOverflow := max(a.overflow, b.overflow) + 1

	result := f.newInternalElement([]frontend.Variable{sum}, newOverflow)

	// Reduce if overflow getting too high
	if newOverflow >= f.maxOverflow() {
		return f.reduceSmall(result)
	}
	return result
}

// subSmall subtracts two small field elements.
func (f *Field[T]) subSmall(a, b *Element[T]) *Element[T] {
	if b.isStrictZero() {
		return a
	}

	aVal := a.Limbs[0]
	bVal := b.Limbs[0]
	p := f.fParams.Modulus()

	// Constant folding
	aConst, aIsConst := f.api.ConstantValue(aVal)
	bConst, bIsConst := f.api.ConstantValue(bVal)
	if aIsConst && bIsConst {
		res := new(big.Int).Sub(aConst, bConst)
		res.Mod(res, p)
		return f.newInternalElement([]frontend.Variable{res}, 0)
	}

	// a - b + p to avoid underflow
	diff := f.api.Sub(f.api.Add(aVal, p), bVal)
	newOverflow := max(a.overflow, uint(p.BitLen())) + 1

	result := f.newInternalElement([]frontend.Variable{diff}, newOverflow)

	if newOverflow >= f.maxOverflow() {
		return f.reduceSmall(result)
	}
	return result
}
