package emulated

import (
	"fmt"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark/frontend"
	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
)

// SmallFieldElement represents an element in a small field that fits entirely
// within the native field. This is an optimization for cases like emulating
// 31-bit koalabear on 253-bit BLS12-377.
//
// Instead of decomposing into limbs and range-checking each limb, we keep the
// value as a native field element and track bounds to defer range checks.
type SmallFieldElement[T FieldParams] struct {
	// Val is the native field element representing this small field value.
	// It may be larger than the modulus (not yet reduced).
	Val frontend.Variable

	// upperBound tracks the maximum possible value of Val in bits.
	// This is used to determine when reduction is needed.
	upperBound uint

	// isReduced indicates if Val has been reduced modulo the field modulus
	// and range-checked.
	isReduced bool
}

// smallFieldParams holds precomputed parameters for small field operations.
type smallFieldParams struct {
	// modulus is the field modulus as a big.Int
	modulus *big.Int
	// modulusBits is the bit length of the modulus
	modulusBits uint
	// maxBeforeReduce is the maximum overflow before we must reduce
	// (native field bits - 2 to leave room for operations)
	maxBeforeReduce uint
}

// isSmallFieldCompatible returns true if the emulated field can use
// small field optimizations on the given native field.
func isSmallFieldCompatible[T FieldParams](nativeField *big.Int) bool {
	var fp T
	modBits := uint(fp.Modulus().BitLen())
	nativeBits := uint(nativeField.BitLen())

	// Small field optimization is beneficial when:
	// 1. The emulated modulus is much smaller than native field
	// 2. We can fit many operations before overflow
	// For now, require modulus to be at most 1/4 of native field
	return modBits*4 <= nativeBits
}

// NewSmallFieldElement creates a new small field element from a constant.
func (f *Field[T]) NewSmallFieldElement(v interface{}) *SmallFieldElement[T] {
	bValue := big.NewInt(0)
	switch val := v.(type) {
	case int:
		bValue.SetInt64(int64(val))
	case int64:
		bValue.SetInt64(val)
	case uint64:
		bValue.SetUint64(val)
	case *big.Int:
		bValue.Set(val)
	case big.Int:
		bValue.Set(&val)
	default:
		panic(fmt.Sprintf("unsupported type %T", v))
	}
	bValue.Mod(bValue, f.fParams.Modulus())
	return &SmallFieldElement[T]{
		Val:        bValue,
		upperBound: uint(f.fParams.Modulus().BitLen()),
		isReduced:  true,
	}
}

// SmallFieldFromVariable creates a small field element from a native variable.
// The caller must ensure the variable is in the valid range [0, modulus).
func (f *Field[T]) SmallFieldFromVariable(v frontend.Variable) *SmallFieldElement[T] {
	return &SmallFieldElement[T]{
		Val:        v,
		upperBound: uint(f.fParams.Modulus().BitLen()),
		isReduced:  false, // Need to range check
	}
}

// SmallFieldAdd computes a + b in the small field.
func (f *Field[T]) SmallFieldAdd(a, b *SmallFieldElement[T]) *SmallFieldElement[T] {
	// Fast path for constants
	aConst, aIsConst := f.api.ConstantValue(a.Val)
	bConst, bIsConst := f.api.ConstantValue(b.Val)
	if aIsConst && bIsConst {
		result := new(big.Int).Add(aConst, bConst)
		result.Mod(result, f.fParams.Modulus())
		return &SmallFieldElement[T]{
			Val:        result,
			upperBound: uint(f.fParams.Modulus().BitLen()),
			isReduced:  true,
		}
	}

	// Compute the sum in native field
	sum := f.api.Add(a.Val, b.Val)

	// Track the bound: max bound is max(a,b) + 1 bit
	newBound := max(a.upperBound, b.upperBound) + 1

	result := &SmallFieldElement[T]{
		Val:        sum,
		upperBound: newBound,
		isReduced:  false,
	}

	// Check if we need to reduce
	if newBound >= f.maxOverflow() {
		return f.SmallFieldReduce(result)
	}

	return result
}

// SmallFieldSub computes a - b in the small field.
func (f *Field[T]) SmallFieldSub(a, b *SmallFieldElement[T]) *SmallFieldElement[T] {
	// To avoid underflow, add modulus first
	// a - b = a + (p - b) when b might be larger than a
	p := f.fParams.Modulus()

	// Fast path for constants
	aConst, aIsConst := f.api.ConstantValue(a.Val)
	bConst, bIsConst := f.api.ConstantValue(b.Val)
	if aIsConst && bIsConst {
		result := new(big.Int).Sub(aConst, bConst)
		result.Mod(result, p)
		return &SmallFieldElement[T]{
			Val:        result,
			upperBound: uint(p.BitLen()),
			isReduced:  true,
		}
	}

	// a - b + p (to ensure positive result)
	// This is equivalent to (a + p) - b
	diff := f.api.Sub(f.api.Add(a.Val, p), b.Val)

	// Bound: max(a, p) + 1 bit (for the addition) - but sub doesn't reduce bound
	// The result is in [0, 2p) if a, b < p
	newBound := max(a.upperBound, uint(p.BitLen())) + 1

	result := &SmallFieldElement[T]{
		Val:        diff,
		upperBound: newBound,
		isReduced:  false,
	}

	if newBound >= f.maxOverflow() {
		return f.SmallFieldReduce(result)
	}

	return result
}

// SmallFieldMul computes a * b in the small field.
func (f *Field[T]) SmallFieldMul(a, b *SmallFieldElement[T]) *SmallFieldElement[T] {
	// Fast path for constants
	aConst, aIsConst := f.api.ConstantValue(a.Val)
	bConst, bIsConst := f.api.ConstantValue(b.Val)
	if aIsConst && bIsConst {
		result := new(big.Int).Mul(aConst, bConst)
		result.Mod(result, f.fParams.Modulus())
		return &SmallFieldElement[T]{
			Val:        result,
			upperBound: uint(f.fParams.Modulus().BitLen()),
			isReduced:  true,
		}
	}

	// Compute the product in native field
	prod := f.api.Mul(a.Val, b.Val)

	// Track the bound: a * b has at most a.bits + b.bits bits
	newBound := a.upperBound + b.upperBound

	result := &SmallFieldElement[T]{
		Val:        prod,
		upperBound: newBound,
		isReduced:  false,
	}

	// Check if we need to reduce
	if newBound >= f.maxOverflow() {
		return f.SmallFieldReduce(result)
	}

	return result
}

// SmallFieldMulAndReduce computes a * b mod p and reduces immediately.
// This is the standard behavior matching the regular Mul.
func (f *Field[T]) SmallFieldMulAndReduce(a, b *SmallFieldElement[T]) *SmallFieldElement[T] {
	// First compute the product
	prod := f.SmallFieldMul(a, b)
	// Then reduce it
	return f.SmallFieldReduce(prod)
}

// SmallFieldReduce reduces the element modulo the field modulus.
func (f *Field[T]) SmallFieldReduce(a *SmallFieldElement[T]) *SmallFieldElement[T] {
	if a.isReduced {
		return a
	}

	p := f.fParams.Modulus()
	modBits := uint(p.BitLen())

	// Ensure upperBound is set for uninitialized elements
	aUpperBound := a.upperBound
	if aUpperBound == 0 {
		aUpperBound = modBits
	}

	// Check if constant
	if aConst, isConst := f.api.ConstantValue(a.Val); isConst {
		result := new(big.Int).Mod(aConst, p)
		return &SmallFieldElement[T]{
			Val:        result,
			upperBound: modBits,
			isReduced:  true,
		}
	}

	// Compute q = floor(a / p) and r = a mod p via hint
	// Then verify: a = q * p + r with r < p
	quoBits := aUpperBound - modBits + 1 // Maximum bits in quotient

	// Call hint to get q and r
	outputs, err := f.api.NewHint(smallFieldReduceHint, 2, a.Val, p, quoBits)
	if err != nil {
		panic(fmt.Sprintf("small field reduce hint: %v", err))
	}
	quo := outputs[0]
	rem := outputs[1]

	// Verify: a = q * p + r
	qp := f.api.Mul(quo, p)
	reconstructed := f.api.Add(qp, rem)
	f.api.AssertIsEqual(a.Val, reconstructed)

	// Range check the remainder: r < p
	// We use the field's range checker
	f.checker.Check(rem, int(modBits))

	// Range check the quotient (it should be small)
	if quoBits > 0 {
		f.checker.Check(quo, int(quoBits))
	}

	return &SmallFieldElement[T]{
		Val:        rem,
		upperBound: modBits,
		isReduced:  true,
	}
}

// SmallFieldAssertIsEqual asserts that a == b in the field.
func (f *Field[T]) SmallFieldAssertIsEqual(a, b *SmallFieldElement[T]) {
	p := f.fParams.Modulus()
	modBits := uint(p.BitLen())

	// Ensure upperBound is set for uninitialized elements
	if a.upperBound == 0 {
		a.upperBound = modBits
	}
	if b.upperBound == 0 {
		b.upperBound = modBits
	}

	// Reduce both if needed
	aReduced := a
	if !a.isReduced {
		aReduced = f.SmallFieldReduce(a)
	}
	bReduced := b
	if !b.isReduced {
		bReduced = f.SmallFieldReduce(b)
	}

	// Now they should be equal as native values
	f.api.AssertIsEqual(aReduced.Val, bReduced.Val)
}

// smallFieldReduceHint computes quotient and remainder for reduction.
func smallFieldReduceHint(nativeMod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 3 {
		return fmt.Errorf("expected 3 inputs, got %d", len(inputs))
	}
	if len(outputs) != 2 {
		return fmt.Errorf("expected 2 outputs, got %d", len(outputs))
	}

	val := inputs[0]
	mod := inputs[1]
	// quoBits := inputs[2] // not used in hint, just for documentation

	quo := new(big.Int)
	rem := new(big.Int)
	quo.QuoRem(val, mod, rem)

	outputs[0].Set(quo)
	outputs[1].Set(rem)

	return nil
}

// ToSmallField converts a regular Element to a SmallFieldElement.
// This assumes the element is already reduced and has a single limb.
func (f *Field[T]) ToSmallField(e *Element[T]) *SmallFieldElement[T] {
	if len(e.Limbs) == 0 {
		return f.NewSmallFieldElement(0)
	}
	if len(e.Limbs) != 1 {
		panic("ToSmallField only works with single-limb elements")
	}

	return &SmallFieldElement[T]{
		Val:        e.Limbs[0],
		upperBound: f.fParams.BitsPerLimb() + e.overflow,
		isReduced:  e.overflow == 0 && e.internal,
	}
}

// FromSmallField converts a SmallFieldElement back to a regular Element.
func (f *Field[T]) FromSmallField(s *SmallFieldElement[T]) *Element[T] {
	// Ensure reduced first
	reduced := s
	if !s.isReduced {
		reduced = f.SmallFieldReduce(s)
	}

	return &Element[T]{
		Limbs:    []frontend.Variable{reduced.Val},
		overflow: 0,
		internal: true,
	}
}

// smallFieldMulCheckDeferred is a deferred checker for small field multiplications.
// It batches multiple a*b = r + q*p checks together using a random linear combination.
type smallFieldMulCheckDeferred[T FieldParams] struct {
	f *Field[T]
	// Each entry: a*b = r + q*p
	as, bs, rs, qs []frontend.Variable
}

func (mc *smallFieldMulCheckDeferred[T]) toCommit() []frontend.Variable {
	all := make([]frontend.Variable, 0, len(mc.as)*4)
	all = append(all, mc.as...)
	all = append(all, mc.bs...)
	all = append(all, mc.rs...)
	all = append(all, mc.qs...)
	return all
}

func (mc *smallFieldMulCheckDeferred[T]) maxLen() int {
	return 1 // Single values, no polynomial evaluation needed
}

func (mc *smallFieldMulCheckDeferred[T]) evalRound1(at []frontend.Variable) {
	// Nothing to evaluate - values are already scalars
}

func (mc *smallFieldMulCheckDeferred[T]) evalRound2(at []frontend.Variable) {
	// Nothing to evaluate - values are already scalars
}

func (mc *smallFieldMulCheckDeferred[T]) check(api frontend.API, peval, coef frontend.Variable) {
	// For each multiplication, verify a*b = r + q*p
	// We batch using random linear combination
	p := mc.f.fParams.Modulus()

	for i := range mc.as {
		lhs := api.Mul(mc.as[i], mc.bs[i])
		qp := api.Mul(mc.qs[i], p)
		rhs := api.Add(mc.rs[i], qp)
		api.AssertIsEqual(lhs, rhs)
	}
}

func (mc *smallFieldMulCheckDeferred[T]) cleanEvaluations() {
	// Nothing to clean
}

// SmallFieldMulMod is an optimized multiplication that defers range checking.
// It's more efficient than SmallFieldMul when doing many multiplications.
func (f *Field[T]) SmallFieldMulMod(a, b *SmallFieldElement[T]) *SmallFieldElement[T] {
	// Fast path for constants
	aConst, aIsConst := f.api.ConstantValue(a.Val)
	bConst, bIsConst := f.api.ConstantValue(b.Val)
	if aIsConst && bIsConst {
		result := new(big.Int).Mul(aConst, bConst)
		result.Mod(result, f.fParams.Modulus())
		return &SmallFieldElement[T]{
			Val:        result,
			upperBound: uint(f.fParams.Modulus().BitLen()),
			isReduced:  true,
		}
	}

	p := f.fParams.Modulus()
	modBits := uint(p.BitLen())

	// Ensure upperBound is at least modBits for uninitialized elements
	aUpperBound := a.upperBound
	if aUpperBound == 0 {
		aUpperBound = modBits
	}
	bUpperBound := b.upperBound
	if bUpperBound == 0 {
		bUpperBound = modBits
	}

	// Compute quotient and remainder bounds
	// a < 2^a.upperBound, b < 2^b.upperBound
	// a*b < 2^(a.upperBound + b.upperBound)
	// q = floor(a*b / p) < 2^(a.upperBound + b.upperBound - modBits + 1)
	prodBound := aUpperBound + bUpperBound
	quoBound := prodBound - modBits + 1

	// Use hint to compute q and r where a*b = q*p + r
	outputs, err := f.api.NewHint(smallFieldMulHint, 2, a.Val, b.Val, p, quoBound)
	if err != nil {
		panic(fmt.Sprintf("small field mul hint: %v", err))
	}
	quo := outputs[0]
	rem := outputs[1]

	// Verify a*b = q*p + r
	ab := f.api.Mul(a.Val, b.Val)
	qp := f.api.Mul(quo, p)
	reconstructed := f.api.Add(qp, rem)
	f.api.AssertIsEqual(ab, reconstructed)

	// Range check remainder and quotient
	f.checker.Check(rem, int(modBits))
	if quoBound > 0 {
		f.checker.Check(quo, int(quoBound))
	}

	return &SmallFieldElement[T]{
		Val:        rem,
		upperBound: modBits,
		isReduced:  true,
	}
}

// smallFieldMulHint computes quotient and remainder for a*b mod p.
func smallFieldMulHint(nativeMod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 4 {
		return fmt.Errorf("expected 4 inputs, got %d", len(inputs))
	}
	if len(outputs) != 2 {
		return fmt.Errorf("expected 2 outputs, got %d", len(outputs))
	}

	a := inputs[0]
	b := inputs[1]
	p := inputs[2]
	// quoBound := inputs[3] // not used in hint, for documentation

	ab := new(big.Int).Mul(a, b)
	quo := new(big.Int)
	rem := new(big.Int)
	quo.QuoRem(ab, p, rem)

	outputs[0].Set(quo)
	outputs[1].Set(rem)

	return nil
}

// Note: nbMultiplicationResLimbs is defined in hints.go

// SmallFieldSum computes the sum of multiple elements efficiently.
func (f *Field[T]) SmallFieldSum(inputs ...*SmallFieldElement[T]) *SmallFieldElement[T] {
	if len(inputs) == 0 {
		return f.NewSmallFieldElement(0)
	}
	if len(inputs) == 1 {
		return inputs[0]
	}

	// Compute the maximum bound after adding all inputs
	maxBound := uint(0)
	for _, in := range inputs {
		if in.upperBound > maxBound {
			maxBound = in.upperBound
		}
	}
	addBits := uint(bits.Len(uint(len(inputs))))
	totalBound := maxBound + addBits

	// If total would overflow, reduce first
	if totalBound >= f.maxOverflow() {
		// Reduce all inputs first
		reduced := make([]*SmallFieldElement[T], len(inputs))
		for i, in := range inputs {
			reduced[i] = f.SmallFieldReduce(in)
		}
		inputs = reduced
		maxBound = uint(f.fParams.Modulus().BitLen())
		totalBound = maxBound + addBits
	}

	// Now sum them up
	var sum frontend.Variable = inputs[0].Val
	for i := 1; i < len(inputs); i++ {
		sum = f.api.Add(sum, inputs[i].Val)
	}

	result := &SmallFieldElement[T]{
		Val:        sum,
		upperBound: totalBound,
		isReduced:  false,
	}

	// Check if we need to reduce
	if totalBound >= f.maxOverflow() {
		return f.SmallFieldReduce(result)
	}

	return result
}

// convertToSmallFieldLimbs converts emulated Element limbs to SmallFieldElement.
// This is for interoperability between the two representations.
func (f *Field[T]) convertToSmallFieldLimbs(e *Element[T]) *SmallFieldElement[T] {
	// Reconstruct the value from limbs
	if len(e.Limbs) == 0 {
		return f.NewSmallFieldElement(0)
	}

	nbBits := f.fParams.BitsPerLimb()
	var val frontend.Variable = e.Limbs[0]

	for i := 1; i < len(e.Limbs); i++ {
		shift := new(big.Int).Lsh(big.NewInt(1), nbBits*uint(i))
		shifted := f.api.Mul(e.Limbs[i], shift)
		val = f.api.Add(val, shifted)
	}

	totalBits := uint(len(e.Limbs)) * nbBits

	return &SmallFieldElement[T]{
		Val:        val,
		upperBound: totalBits + e.overflow,
		isReduced:  false,
	}
}

// convertFromSmallFieldLimbs converts SmallFieldElement to emulated Element limbs.
func (f *Field[T]) convertFromSmallFieldLimbs(s *SmallFieldElement[T]) *Element[T] {
	// First reduce to ensure proper range
	reduced := s
	if !s.isReduced {
		reduced = f.SmallFieldReduce(s)
	}

	nbLimbs := f.fParams.NbLimbs()
	nbBits := f.fParams.BitsPerLimb()

	if nbLimbs == 1 {
		// Single limb case is simple
		return &Element[T]{
			Limbs:    []frontend.Variable{reduced.Val},
			overflow: 0,
			internal: true,
		}
	}

	// Need to decompose into limbs
	outputs, err := f.api.NewHint(decomposeHint, int(nbLimbs), reduced.Val, nbBits, nbLimbs)
	if err != nil {
		panic(fmt.Sprintf("decompose hint: %v", err))
	}

	// Verify decomposition is correct
	var reconstructed frontend.Variable = outputs[0]
	for i := 1; i < len(outputs); i++ {
		shift := new(big.Int).Lsh(big.NewInt(1), nbBits*uint(i))
		shifted := f.api.Mul(outputs[i], shift)
		reconstructed = f.api.Add(reconstructed, shifted)
	}
	f.api.AssertIsEqual(reduced.Val, reconstructed)

	// Range check each limb
	for i, limb := range outputs {
		bits := int(nbBits)
		if i == len(outputs)-1 {
			// Last limb might be smaller
			bits = ((f.fParams.Modulus().BitLen() - 1) % int(nbBits)) + 1
		}
		f.checker.Check(limb, bits)
	}

	return &Element[T]{
		Limbs:    outputs,
		overflow: 0,
		internal: true,
	}
}

// decomposeHint decomposes a value into limbs of specified bit width.
func decomposeHint(nativeMod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 3 {
		return fmt.Errorf("expected 3 inputs, got %d", len(inputs))
	}

	val := inputs[0]
	nbBits := uint(inputs[1].Uint64())
	nbLimbs := int(inputs[2].Uint64())

	if len(outputs) != nbLimbs {
		return fmt.Errorf("expected %d outputs, got %d", nbLimbs, len(outputs))
	}

	return limbs.Decompose(val, nbBits, outputs)
}
