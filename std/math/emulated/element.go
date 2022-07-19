package emulated

// TODO: add checks which ensure that constants are not used as receivers
// TODO: add sanity checks before the operations (e.g. that overflow is
// sufficient and do not need to reduce)
// TODO: think about different "operation modes". Probably hand-optimized code
// is better than reducing eagerly, but the user should be at least aware during
// compile-time that values need to be reduced. But there should be an easy-mode
// where the user does not need to manually reduce and the library does it as
// necessary.
// TODO: check that the parameters coincide for elements.
// TODO: less equal than
// TODO: simple exponentiation before we implement Wesolowsky

import (
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/compiled"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/math/bits"
	"golang.org/x/exp/constraints"
)

type errOverflow struct {
	op           string
	nextOverflow uint
	maxOverflow  uint
	reduceRight  bool
}

func (e errOverflow) Error() string {
	return fmt.Sprintf("op %s overflow %d exceeds max %d", e.op, e.nextOverflow, e.maxOverflow)
}

// Element defines an element in the ring of integers modulo n. The integer
// value of the element is split into limbs of nbBits lengths and represented as
// a slice of limbs.
type Element[T FieldParams] struct {
	Limbs []frontend.Variable `gnark:"limbs"` // in little-endian (least significant limb first) encoding

	// overflow indicates the number of additions on top of the normal form. To
	// ensure that none of the limbs overflow the scalar field of the snark
	// curve, we must check that nbBits+overflow < floor(log2(fr modulus))
	overflow uint `gnark:"-"`

	// f carries the ring parameters
	fParams T
}

// NewElement builds a new emulated element from input
// if input is a Element[T], this functions clones and return a new Element[T]
// else, it attemps to convert to big.Int , mod reduce if necessary and return a cannonical Element[T]
func NewElement[T FieldParams](v interface{}) Element[T] {
	r := Element[T]{}
	r.Limbs = make([]frontend.Variable, r.fParams.NbLimbs())
	for i := 0; i < len(r.Limbs); i++ {
		r.Limbs[i] = 0
	}

	if v == nil {
		return r
	}
	switch tv := v.(type) {
	case Element[T]:
		copy(r.Limbs, tv.Limbs)
		r.overflow = tv.overflow
		return r
	case *Element[T]:
		copy(r.Limbs, tv.Limbs)
		r.overflow = tv.overflow
		return r
	case compiled.LinearExpression:
		// TODO @gbotrel don't like that
		// return f.PackLimbs([]frontend.Variable{in})
		r.Limbs = []frontend.Variable{v}
		return r
	case compiled.Term:
		// TODO @gbotrel don't like that
		// return f.PackLimbs([]frontend.Variable{in})
		r.Limbs = []frontend.Variable{v}
		return r
	}

	// convert to big.Int
	bValue := utils.FromInterface(v)

	// mod reduce
	if r.fParams.Modulus().Cmp(&bValue) != 0 {
		bValue.Mod(&bValue, r.fParams.Modulus())
	}

	// decompose into limbs
	// TODO @gbotrel use big.Int pool here
	limbs := make([]*big.Int, r.fParams.NbLimbs())
	for i := range limbs {
		limbs[i] = new(big.Int)
	}
	if err := decompose(&bValue, r.fParams.BitsPerLimb(), limbs); err != nil {
		panic(fmt.Errorf("decompose value: %w", err))
	}

	// assign limb values
	for i := range limbs {
		r.Limbs[i] = frontend.Variable(limbs[i])
	}

	return r
}

// toBits returns the bit representation of the Element in little-endian (LSB
// first) order. The returned bits are constrained to be 0-1. The number of
// returned bits is nbLimbs*nbBits+overflow. To obtain the bits of the canonical
// representation of Element, reduce Element first and take less significant
// bits corresponding to the bitwidth of the emulated modulus.
func (f *field[T]) toBits(e Element[T]) []frontend.Variable {
	var carry frontend.Variable = 0
	var fullBits []frontend.Variable
	var limbBits []frontend.Variable
	for i := 0; i < len(e.Limbs); i++ {
		limbBits = bits.ToBinary(f.api, f.api.Add(e.Limbs[i], carry), bits.WithNbDigits(int(e.fParams.BitsPerLimb()+e.overflow)))
		fullBits = append(fullBits, limbBits[:e.fParams.BitsPerLimb()]...)
		if e.overflow > 0 {
			carry = bits.FromBinary(f.api, limbBits[e.fParams.BitsPerLimb():])
		}
	}
	fullBits = append(fullBits, limbBits[e.fParams.BitsPerLimb():e.fParams.BitsPerLimb()+e.overflow]...)
	return fullBits
}

// maxOverflow returns the maximal possible overflow for the element. If the
// overflow of the next operation exceeds the value returned by this method,
// then the limbs may overflow the native field.
func (f *field[T]) maxOverflow() uint {
	f.maxOfOnce.Do(func() {
		f.maxOf = uint(f.api.Compiler().FieldBitLen()-1) - f.fParams.BitsPerLimb()
	})
	return f.maxOf
}

// assertLimbsEqualitySlow is the main routine in the package. It asserts that the
// two slices of limbs represent the same integer value. This is also the most
// costly operation in the package as it does bit decomposition of the limbs.
func assertLimbsEqualitySlow(api frontend.API, l, r []frontend.Variable, nbBits, nbCarryBits uint) {
	nbLimbs := len(l)
	if len(r) > nbLimbs {
		nbLimbs = len(r)
	}
	maxValue := new(big.Int).Lsh(big.NewInt(1), nbBits+nbCarryBits)
	maxValueShift := new(big.Int).Lsh(big.NewInt(1), nbCarryBits)

	var carry frontend.Variable = 0
	for i := 0; i < nbLimbs; i++ {
		diff := api.Add(maxValue, carry)
		if i < len(l) {
			diff = api.Add(diff, l[i])
		}
		if i < len(r) {
			diff = api.Sub(diff, r[i])
		}
		if i > 0 {
			diff = api.Sub(diff, maxValueShift)
		}
		// TODO: more efficient methods for splitting a variable? Because we are
		// splitting the value into two, then maybe we do not need the whole
		// binary decomposition \sum_{i=0}^n a_i 2^i, but can use a * 2^nbits +
		// b. Then we can also omit the FromBinary call.
		diffBits := bits.ToBinary(api, diff, bits.WithNbDigits(int(nbBits+nbCarryBits+1)), bits.WithUnconstrainedOutputs())
		for j := uint(0); j < nbBits; j++ {
			api.AssertIsEqual(diffBits[j], 0)
		}
		carry = bits.FromBinary(api, diffBits[nbBits:nbBits+nbCarryBits+1])
	}
	api.AssertIsEqual(carry, maxValueShift)
}

// AssertLimbsEquality asserts that the limbs represent a same integer value (up
// to overflow). This method does not ensure that the values are equal modulo
// the field order. For strict equality, use AssertIsEqual.
func (f *field[T]) AssertLimbsEquality(a, b Element[T]) {

	// first, we check if we can compact the e and other; they could be using 8 limbs of 32bits
	// but with our snark field, we could express them in 2 limbs of 128bits, which would make bit decomposition
	// and limbs equality in-circuit (way) cheaper
	ca, cb, bitsPerLimb := f.compact(a, b)
	// slow path -- the overflows are different. Need to compare with carries.
	// TODO: we previously assumed that one side was "larger" than the other
	// side, but I think this assumption is not valid anymore
	if a.overflow > b.overflow {
		assertLimbsEqualitySlow(f.api, ca, cb, bitsPerLimb, a.overflow)
	} else {
		assertLimbsEqualitySlow(f.api, cb, ca, bitsPerLimb, b.overflow)
	}
}

// EnforceWidth enforces that the bitlength of the value is exactly the
// bitlength of the modulus. Any newly initialized variable should be
// constrained to ensure correct operations.
func (f *field[T]) EnforceWidth(e Element[T]) {
	for i := range e.Limbs {
		limbNbBits := int(e.fParams.BitsPerLimb())
		if i == len(e.Limbs)-1 {
			// take only required bits from the most significant limb
			limbNbBits = ((e.fParams.Modulus().BitLen() - 1) % int(e.fParams.BitsPerLimb())) + 1
		}
		// bits.ToBinary restricts the least significant NbDigits to be equal to
		// the limb value. This is sufficient to restrict for the bitlength and
		// we can discard the bits themselves.
		bits.ToBinary(f.api, e.Limbs[i], bits.WithNbDigits(limbNbBits))
	}
}

func (f *field[T]) addPreCond(a, b Element[T]) (nextOverflow uint, err error) {
	reduceRight := a.overflow < b.overflow

	nextOverflow = max(a.overflow, b.overflow) + 1

	if nextOverflow > f.maxOverflow() {
		err = errOverflow{op: "add", nextOverflow: nextOverflow, maxOverflow: f.maxOverflow(), reduceRight: reduceRight}
	}
	return
}

func (f *field[T]) add(a, b Element[T], nextOverflow uint) Element[T] {
	// TODO: figure out case when one element is a constant. If one addend is a
	// constant, then we do not reduce it (but this is always case as the
	// constant's overflow never increases?)
	// TODO: check that the target is a variable (has an API)
	// TODO: if both are constants, then add big ints
	nbLimbs := max(len(a.Limbs), len(b.Limbs))
	limbs := make([]frontend.Variable, nbLimbs)
	for i := range limbs {
		limbs[i] = 0
		if i < len(a.Limbs) {
			limbs[i] = f.api.Add(limbs[i], a.Limbs[i])
		}
		if i < len(b.Limbs) {
			limbs[i] = f.api.Add(limbs[i], b.Limbs[i])
		}
	}
	e := Element[T]{
		Limbs:    limbs,
		overflow: nextOverflow,
	}
	return e
}

func (f *field[T]) mulPreCond(a, b Element[T]) (nextOverflow uint, err error) {
	reduceRight := a.overflow < b.overflow
	nbResLimbs := nbMultiplicationResLimbs(len(a.Limbs), len(b.Limbs))
	nextOverflow = f.fParams.BitsPerLimb() + uint(math.Log2(float64(2*nbResLimbs-1))) + 1 + a.overflow + b.overflow
	if nextOverflow > f.maxOverflow() {
		err = errOverflow{op: "mul", nextOverflow: nextOverflow, maxOverflow: f.maxOverflow(), reduceRight: reduceRight}
	}
	return
}

func (f *field[T]) mul(a, b Element[T], nextOverflow uint) Element[T] {
	// TODO: when one element is constant.
	// TODO: if both are constants, then do big int mul

	// mulResult contains the result (out of circuit) of a * b school book multiplication
	// len(mulResult) == len(a) + len(b) - 1
	mulResult, err := computeMultiplicationHint(f.api, f, a.Limbs, b.Limbs)
	if err != nil {
		panic(fmt.Sprintf("multiplication hint: %s", err))
	}

	// we computed the result of the mul outside the circuit (mulResult)
	// and we want to constrain inside the circuit that this injected value
	// actually matches the in-circuit a * b values
	// create constraints (\sum_{i=0}^{m-1} a_i c^i) * (\sum_{i=0}^{m-1} b_i
	// c^i) = (\sum_{i=0}^{2m-2} z_i c^i) for c \in {1, 2m-1}
	w := new(big.Int)
	for c := 1; c <= len(mulResult); c++ {
		w.SetInt64(1) // c^i
		l := a.Limbs[0]
		r := b.Limbs[0]
		o := mulResult[0]

		for i := 1; i < len(mulResult); i++ {
			w.Lsh(w, uint(c))
			if i < len(a.Limbs) {
				l = f.api.Add(l, f.api.Mul(a.Limbs[i], w))
			}
			if i < len(b.Limbs) {
				r = f.api.Add(r, f.api.Mul(b.Limbs[i], w))
			}
			o = f.api.Add(o, f.api.Mul(mulResult[i], w))
		}
		f.api.AssertIsEqual(f.api.Mul(l, r), o)
	}

	return Element[T]{
		Limbs:    mulResult,
		overflow: nextOverflow,
	}
}

// reduce reduces a modulo modulus and assigns e to the reduced value.
func (f *field[T]) reduce(a Element[T]) Element[T] {
	if a.overflow == 0 {
		// fast path - already reduced, omit reduction.
		return a
	}
	// slow path - use hint to reduce value
	e, err := f.computeRemHint(a, f.Modulus())
	if err != nil {
		panic(fmt.Sprintf("reduction hint: %v", err))
	}
	f.assertIsEqual(a, e)
	return e
}

// Assign a value to self (witness assignment)
func (e *Element[T]) Assign(val interface{}) {
	*e = NewElement[T](val)
}

func (e *Element[T]) GnarkInitHook() {
	if e.Limbs == nil {
		*e = NewElement[T](nil)
	}
}

// Set sets e to a and returns e. If a is constant, then it also enforces the
// widths of the limbs.
func (e *Element[T]) Set(a Element[T]) {
	e.Limbs = make([]frontend.Variable, len(a.Limbs))
	e.overflow = a.overflow
	copy(e.Limbs, a.Limbs)
	// TODO @gbotrel this shouldn't happen anymore
	// if a.f.api == nil {
	// 	// we are setting from constant -- ensure that the widths of the limbs
	// 	// are restricted
	// 	e.EnforceWidth()
	// }
}

// AssertIsEqual ensures that a is equal to b modulo the modulus.
func (f *field[T]) assertIsEqual(a, b Element[T]) Element[T] {
	diff := (f.Sub(b, a)).(Element[T])

	// we compute k such that diff / p == k
	// so essentially, we say "I know an element k such that k*p == diff"
	// hence, diff == 0 mod p
	p := f.Modulus()
	k, err := f.computeQuoHint(diff, p)
	if err != nil {
		panic(fmt.Sprintf("hint error: %v", err))
	}

	kp := (f.Mul(k, p)).(Element[T])
	f.AssertLimbsEquality(diff, kp)

	// TODO @gbotrel improve useless alloc
	// we have this so that the signature of assertIsEqual matches expected in reduceAndOp
	return NewElement[T](nil)
}

// AssertIsEqualLessThan ensures that e is less or equal than e.
func (f *field[T]) AssertIsLessEqualThan(e, a Element[T]) {
	if e.overflow+a.overflow > 0 {
		panic("inputs must have 0 overflow")
	}
	eBits := f.toBits(e)
	aBits := f.toBits(a)
	ff := func(xbits, ybits []frontend.Variable) []frontend.Variable {
		diff := len(xbits) - len(ybits)
		ybits = append(ybits, make([]frontend.Variable, diff)...)
		for i := len(ybits) - diff - 1; i < len(ybits); i++ {
			ybits[i] = 0
		}
		return ybits
	}
	if len(eBits) > len(aBits) {
		aBits = ff(eBits, aBits)
	} else {
		eBits = ff(aBits, eBits)
	}
	p := make([]frontend.Variable, len(eBits)+1)
	p[len(eBits)] = 1
	for i := len(eBits) - 1; i >= 0; i-- {
		v := f.api.Mul(p[i+1], eBits[i])
		p[i] = f.api.Select(aBits[i], v, p[i+1])
		t := f.api.Select(aBits[i], 0, p[i+1])
		l := f.api.Sub(1, t, eBits[i])
		ll := f.api.Mul(l, eBits[i])
		f.api.AssertIsEqual(ll, 0)
	}
}

func (f *field[T]) subPreCond(a, b Element[T]) (nextOverflow uint, err error) {
	reduceRight := a.overflow < b.overflow+2
	nextOverflow = b.overflow + 2
	if a.overflow > nextOverflow {
		nextOverflow = a.overflow
	}
	if nextOverflow > f.maxOverflow() {
		err = errOverflow{op: "sub", nextOverflow: nextOverflow, maxOverflow: f.maxOverflow(), reduceRight: reduceRight}
	}
	return
}

func (f *field[T]) sub(a, b Element[T], nextOverflow uint) Element[T] {
	// first we have to compute padding to ensure that the subtraction does not
	// underflow.
	nbLimbs := max(len(a.Limbs), len(b.Limbs))
	limbs := make([]frontend.Variable, nbLimbs)
	padLimbs := subPadding[T](b.overflow, uint(nbLimbs))
	for i := range limbs {
		limbs[i] = padLimbs[i]
		if i < len(a.Limbs) {
			limbs[i] = f.api.Add(limbs[i], a.Limbs[i])
		}
		if i < len(b.Limbs) {
			limbs[i] = f.api.Sub(limbs[i], b.Limbs[i])
		}
	}
	e := Element[T]{
		Limbs:    limbs,
		overflow: nextOverflow,
	}
	return e
}

// Select sets e to a if selector == 0 and to b otherwise.
// assumes a overflow == b overflow
func (f *field[T]) _select(selector frontend.Variable, a, b Element[T]) Element[T] {
	e := NewElement[T](nil)
	e.overflow = a.overflow
	for i := range a.Limbs {
		e.Limbs[i] = f.api.Select(selector, a.Limbs[i], b.Limbs[i])
	}
	return e
}

// Lookup2 performs two-bit lookup between a, b, c, d based on lookup bits b1
// and b2. Sets e to a if b0=b1=0, b if b0=1 and b1=0, c if b0=0 and b1=1, d if b0=b1=1.
func (f *field[T]) lookup2(b0, b1 frontend.Variable, a, b, c, d Element[T]) Element[T] {
	if len(a.Limbs) != len(b.Limbs) || len(a.Limbs) != len(c.Limbs) || len(a.Limbs) != len(d.Limbs) {
		panic("unequal limb counts for lookup")
	}
	if a.overflow != b.overflow || a.overflow != c.overflow || a.overflow != d.overflow {
		panic("unequal overflows for lookup")
	}
	e := NewElement[T](nil)
	e.Limbs = make([]frontend.Variable, len(a.Limbs))
	e.overflow = a.overflow
	for i := range a.Limbs {
		e.Limbs[i] = f.api.Lookup2(b0, b1, a.Limbs[i], b.Limbs[i], c.Limbs[i], d.Limbs[i])
	}
	return e
}

// reduceAndOp applies op on the inputs. If the pre-condition check preCond
// errs, then first reduces the input arguments. The reduction is done
// one-by-one with the element with highest overflow reduced first.
func (f *field[T]) reduceAndOp(op func(Element[T], Element[T], uint) Element[T], preCond func(Element[T], Element[T]) (uint, error), a, b Element[T]) Element[T] {
	var nextOverflow uint
	var err error
	var target errOverflow
	for nextOverflow, err = preCond(a, b); errors.As(err, &target); nextOverflow, err = preCond(a, b) {
		if !target.reduceRight {
			a = f.reduce(a)
		} else {
			b = f.reduce(b)
		}
	}
	return op(a, b, nextOverflow)
}

func max[T constraints.Ordered](a, b T) T {
	if a > b {
		return a
	}
	return b
}

func min[T constraints.Ordered](a, b T) T {
	if a < b {
		return a
	}
	return b
}
