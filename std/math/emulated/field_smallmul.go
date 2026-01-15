package emulated

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// smallMulEntry represents a single multiplication entry for batched verification.
// For each multiplication a * b = q * p + r, we store:
//   - a, b: the operands (single limb each since NbLimbs == 1)
//   - r: the remainder (reduced result, single limb)
//   - q: the quotient (single limb)
type smallMulEntry struct {
	a, b frontend.Variable // operands
	r    frontend.Variable // remainder
	q    frontend.Variable // quotient
}

// smallMulCheck implements the deferredChecker interface for small field
// multiplication verification. Instead of using polynomial identity testing,
// it uses batched scalar verification:
//
//	Σ γ^i * (a_i * b_i) = Σ γ^i * r_i + (Σ γ^i * q_i) * p
//
// This approach is much cheaper for single-limb emulation because:
//   - No polynomial evaluation needed
//   - No carry polynomial needed
//   - Quotients don't need individual range checks (constrained algebraically)
//   - Only remainders need range checks
type smallMulCheck[T FieldParams] struct {
	f       *Field[T]
	entries []smallMulEntry
	// gamma stores the random challenge received during eval rounds
	gamma frontend.Variable
}

// addEntry adds a new multiplication entry to the batch.
func (mc *smallMulCheck[T]) addEntry(a, b, r, q frontend.Variable) {
	mc.entries = append(mc.entries, smallMulEntry{a: a, b: b, r: r, q: q})
}

// toCommit returns all variables that should be committed to for the random challenge.
func (mc *smallMulCheck[T]) toCommit() []frontend.Variable {
	vars := make([]frontend.Variable, 0, len(mc.entries)*4)
	for _, e := range mc.entries {
		vars = append(vars, e.a, e.b, e.r, e.q)
	}
	return vars
}

// maxLen returns the maximum number of limbs (always 1 for small field mode).
func (mc *smallMulCheck[T]) maxLen() int {
	return 1
}

// evalRound1 stores the random challenge for later use in check.
func (mc *smallMulCheck[T]) evalRound1(at []frontend.Variable) {
	// Store the challenge (at[0] = γ) for use in check
	if len(at) > 0 {
		mc.gamma = at[0]
	}
}

// evalRound2 is a no-op for small field check since we don't use polynomial evaluation.
func (mc *smallMulCheck[T]) evalRound2(at []frontend.Variable) {
	// No polynomial evaluation needed for small field optimization
}

// check performs the batched verification:
// Σ γ^i * (a_i * b_i) = Σ γ^i * r_i + (Σ γ^i * q_i) * p
func (mc *smallMulCheck[T]) check(api frontend.API, peval, coef frontend.Variable) {
	if len(mc.entries) == 0 {
		return
	}

	// Use the stored random challenge γ from evalRound1
	gamma := mc.gamma
	if gamma == nil {
		panic("smallMulCheck: gamma not set, evalRound1 was not called")
	}

	// Compute the three sums using Horner's method for efficiency:
	// sumAB = Σ γ^i * (a_i * b_i)
	// sumR  = Σ γ^i * r_i
	// sumQ  = Σ γ^i * q_i
	//
	// Using Horner's method: a_0 + γ(a_1 + γ(a_2 + ...))
	// We iterate backwards from the last entry.

	n := len(mc.entries)

	// Start with the last entry
	lastEntry := mc.entries[n-1]
	sumAB := api.Mul(lastEntry.a, lastEntry.b)
	sumR := lastEntry.r
	sumQ := lastEntry.q

	// Process remaining entries using Horner's method (backwards)
	for i := n - 2; i >= 0; i-- {
		e := mc.entries[i]

		// sumAB = a_i * b_i + γ * sumAB
		ab := api.Mul(e.a, e.b)
		sumAB = api.MulAcc(ab, gamma, sumAB)

		// sumR = r_i + γ * sumR
		sumR = api.MulAcc(e.r, gamma, sumR)

		// sumQ = q_i + γ * sumQ
		sumQ = api.MulAcc(e.q, gamma, sumQ)
	}

	// Verify: sumAB == sumR + sumQ * p
	p := mc.f.fParams.Modulus()
	rhs := api.MulAcc(sumR, sumQ, p)
	api.AssertIsEqual(sumAB, rhs)
}

// cleanEvaluations cleans cached evaluation values.
func (mc *smallMulCheck[T]) cleanEvaluations() {
	// Reset gamma for clean circuit recompilation
	mc.gamma = nil
}

// smallMulMod performs multiplication using the small field optimization.
// It computes a * b mod p using a hint and defers the batched verification.
func (f *Field[T]) smallMulMod(a, b *Element[T]) *Element[T] {
	// For small field mode, both a and b should have exactly 1 limb
	if len(a.Limbs) != 1 || len(b.Limbs) != 1 {
		panic("smallMulMod requires single-limb elements")
	}

	// Get or create the small mul checker
	smc := f.getOrCreateSmallMulCheck()

	// Call hint to get quotient and remainder
	q, r, err := f.callSmallMulHint(a.Limbs[0], b.Limbs[0])
	if err != nil {
		panic(fmt.Sprintf("small mul hint: %v", err))
	}

	// Range check the remainder (quotient is constrained algebraically by the batch)
	modBits := f.fParams.Modulus().BitLen()
	f.checker.Check(r, modBits)

	// Add entry to the batch
	smc.addEntry(a.Limbs[0], b.Limbs[0], r, q)

	// Return result as single-limb element
	return f.newInternalElement([]frontend.Variable{r}, 0)
}

// getOrCreateSmallMulCheck returns the existing smallMulCheck or creates a new one.
func (f *Field[T]) getOrCreateSmallMulCheck() *smallMulCheck[T] {
	// Look for existing smallMulCheck in deferred checks
	for _, dc := range f.deferredChecks {
		if smc, ok := dc.(*smallMulCheck[T]); ok {
			return smc
		}
	}

	// Create new smallMulCheck
	smc := &smallMulCheck[T]{f: f}
	f.deferredChecks = append(f.deferredChecks, smc)
	return smc
}

// callSmallMulHint computes q and r such that a * b = q * p + r using a hint.
func (f *Field[T]) callSmallMulHint(a, b frontend.Variable) (q, r frontend.Variable, err error) {
	p := f.fParams.Modulus()
	nbBits := f.fParams.BitsPerLimb()

	// Hint returns [q, r]
	ret, err := f.api.NewHint(smallMulHint, 2, nbBits, p, a, b)
	if err != nil {
		return nil, nil, fmt.Errorf("call hint: %w", err)
	}

	return ret[0], ret[1], nil
}

// smallMulHint computes q and r such that a * b = q * p + r.
func smallMulHint(mod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 4 {
		return fmt.Errorf("expected 4 inputs, got %d", len(inputs))
	}
	if len(outputs) != 2 {
		return fmt.Errorf("expected 2 outputs, got %d", len(outputs))
	}

	// inputs[0] = nbBits (unused here but kept for consistency)
	// inputs[1] = p (modulus)
	// inputs[2] = a
	// inputs[3] = b
	p := inputs[1]
	a := inputs[2]
	b := inputs[3]

	// Compute a * b
	ab := new(big.Int).Mul(a, b)

	// Compute q and r such that a * b = q * p + r
	q := new(big.Int)
	r := new(big.Int)
	if p.Sign() != 0 {
		q.QuoRem(ab, p, r)
	} else {
		r.Set(ab)
	}

	outputs[0].Set(q)
	outputs[1].Set(r)
	return nil
}

// smallCheckZero creates a check that a ≡ 0 (mod p).
// This is done by verifying a = q * p + 0.
func (f *Field[T]) smallCheckZero(a *Element[T]) {
	if len(a.Limbs) != 1 {
		panic("smallCheckZero requires single-limb element")
	}

	smc := f.getOrCreateSmallMulCheck()

	// Call hint to get quotient (remainder should be 0)
	q, r, err := f.callSmallCheckZeroHint(a.Limbs[0])
	if err != nil {
		panic(fmt.Sprintf("small check zero hint: %v", err))
	}

	// Range check r (should be 0 but we range check anyway for safety)
	modBits := f.fParams.Modulus().BitLen()
	f.checker.Check(r, modBits)

	// Add entry: a * 1 = q * p + r (expecting r = 0)
	smc.addEntry(a.Limbs[0], 1, r, q)
}

// callSmallCheckZeroHint computes q and r such that a = q * p + r.
func (f *Field[T]) callSmallCheckZeroHint(a frontend.Variable) (q, r frontend.Variable, err error) {
	p := f.fParams.Modulus()
	nbBits := f.fParams.BitsPerLimb()

	ret, err := f.api.NewHint(smallCheckZeroHint, 2, nbBits, p, a)
	if err != nil {
		return nil, nil, fmt.Errorf("call hint: %w", err)
	}

	return ret[0], ret[1], nil
}

// smallCheckZeroHint computes q and r such that a = q * p + r.
func smallCheckZeroHint(mod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 3 {
		return fmt.Errorf("expected 3 inputs, got %d", len(inputs))
	}
	if len(outputs) != 2 {
		return fmt.Errorf("expected 2 outputs, got %d", len(outputs))
	}

	// inputs[0] = nbBits (unused)
	// inputs[1] = p (modulus)
	// inputs[2] = a
	p := inputs[1]
	a := inputs[2]

	// Compute q and r such that a = q * p + r
	q := new(big.Int)
	r := new(big.Int)
	if p.Sign() != 0 {
		q.QuoRem(a, p, r)
	} else {
		r.Set(a)
	}

	outputs[0].Set(q)
	outputs[1].Set(r)
	return nil
}

// smallReduce reduces an element in small field mode.
// For single-limb elements with overflow, we compute r = a mod p.
func (f *Field[T]) smallReduce(a *Element[T]) *Element[T] {
	if len(a.Limbs) != 1 {
		panic("smallReduce requires single-limb element")
	}

	// If no overflow, return as-is
	if a.overflow == 0 {
		return a
	}

	// Use multiplication by 1 to reduce
	return f.smallMulMod(a, f.One())
}

// smallAdd adds two elements in small field mode.
// For single-limb elements, this is just native addition.
func (f *Field[T]) smallAdd(a, b *Element[T]) *Element[T] {
	if len(a.Limbs) == 0 {
		return b
	}
	if len(b.Limbs) == 0 {
		return a
	}

	// For small fields, both elements are single limb
	var aLimb, bLimb frontend.Variable = 0, 0
	if len(a.Limbs) > 0 {
		aLimb = a.Limbs[0]
	}
	if len(b.Limbs) > 0 {
		bLimb = b.Limbs[0]
	}

	sum := f.api.Add(aLimb, bLimb)
	newOverflow := max(a.overflow, b.overflow) + 1
	return f.newInternalElement([]frontend.Variable{sum}, newOverflow)
}

// smallSub subtracts b from a in small field mode.
// We add padding multiples of p to ensure no underflow.
func (f *Field[T]) smallSub(a, b *Element[T]) *Element[T] {
	// For small field mode, we need to ensure a - b doesn't underflow.
	// We add k*p to a where k is large enough that a + k*p - b >= 0.

	// The padding needs to cover the maximum possible value of b.
	// b < 2^(modBits + overflow) so we need k*p >= 2^(modBits + overflow)
	// Since p ≈ 2^modBits, k ≈ 2^overflow suffices.

	p := f.fParams.Modulus()
	modBits := uint(p.BitLen())

	// Compute padding: we need at least 2^(b.overflow) * p
	var padding *big.Int
	if b.overflow > 0 {
		k := new(big.Int).Lsh(big.NewInt(1), b.overflow+1)
		padding = new(big.Int).Mul(k, p)
	} else {
		padding = new(big.Int).Set(p)
	}

	var aLimb, bLimb frontend.Variable = 0, 0
	if len(a.Limbs) > 0 {
		aLimb = a.Limbs[0]
	}
	if len(b.Limbs) > 0 {
		bLimb = b.Limbs[0]
	}

	// result = a + padding - b
	result := f.api.Add(aLimb, padding)
	result = f.api.Sub(result, bLimb)

	// The overflow accounts for the padding
	newOverflow := max(modBits+b.overflow+2, max(a.overflow, b.overflow)+1)
	// Cap overflow at maxOverflow
	if newOverflow > f.maxOverflow() {
		// Need to reduce instead
		return f.smallReduce(f.newInternalElement([]frontend.Variable{result}, newOverflow))
	}

	return f.newInternalElement([]frontend.Variable{result}, newOverflow)
}

// smallAssertIsEqual asserts a ≡ b (mod p) in small field mode.
func (f *Field[T]) smallAssertIsEqual(a, b *Element[T]) {
	// Compute diff = b - a and check that diff ≡ 0 (mod p)
	diff := f.smallSub(b, a)
	f.smallCheckZero(diff)
}

// toSingleLimb converts an Element to a single-limb representation if possible.
// For elements with more limbs, it recomposes them into a single native value.
func (f *Field[T]) toSingleLimb(a *Element[T]) frontend.Variable {
	if len(a.Limbs) == 0 {
		return 0
	}
	if len(a.Limbs) == 1 {
		return a.Limbs[0]
	}

	// Recompose multiple limbs into single value
	nbBits := f.fParams.BitsPerLimb()
	result := a.Limbs[0]
	coef := new(big.Int).Lsh(big.NewInt(1), nbBits)
	for i := 1; i < len(a.Limbs); i++ {
		result = f.api.MulAcc(result, a.Limbs[i], coef)
		coef.Lsh(coef, nbBits)
	}
	return result
}

// toSingleLimbElement converts an Element to a single-limb Element.
// For small field mode, elements should be single limb, but witness
// initialization might create multi-limb elements. This function
// handles that case by recomposing the limbs.
func (f *Field[T]) toSingleLimbElement(a *Element[T]) *Element[T] {
	if len(a.Limbs) == 0 {
		return f.Zero()
	}
	if len(a.Limbs) == 1 {
		return a
	}

	// Recompose multiple limbs into a single limb
	singleLimb := f.toSingleLimb(a)
	return f.newInternalElement([]frontend.Variable{singleLimb}, a.overflow)
}

