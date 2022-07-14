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
	"github.com/consensys/gnark/std/math/bits"
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
type Element struct {
	Limbs []frontend.Variable `gnark:"limbs"` // in little-endian (least significant limb first) encoding

	// params carries the ring parameters
	params *field `gnark:"-"`
	// overflow indicates the number of additions on top of the normal form. To
	// ensure that none of the limbs overflow the scalar field of the snark
	// curve, we must check that nbBits+overflow < floor(log2(fr modulus))
	overflow uint `gnark:"-"`
	// api references the API for variable elements
	api frontend.API `gnark:"-"`
}

// Element returns initialized element in the field. The value of this element
// is not constrained and it only safe to use as a receiver in operations. For
// elements initialized to values use Zero(), One() or Modulus().
func (fp *field) Element(api frontend.API) Element {
	if uint(api.Compiler().FieldBitLen()) < 2*fp.limbSize+1 {
		panic(fmt.Sprintf("elements with limb length %d does not fit into scalar field", fp.limbSize))
	}
	e := Element{
		Limbs:    make([]frontend.Variable, fp.nbLimbs),
		params:   fp,
		overflow: 0,
		api:      api,
	}
	return e
}

// Modulus returns the modulus of the emulated ring as a constant. The returned
// element is not safe to use as an operation receiver.
func (fp *field) Modulus() Element {
	fp.nConstOnce.Do(func() {
		element, err := fp.ConstantFromBig(fp.r)
		if err != nil {
			// should not err for fp.order
			panic(fmt.Sprintf("witness from order: %v", err))
		}
		fp.nConst = &element
	})
	return *fp.nConst
}

// Zero returns zero as a constant. The returned element is not safe to use as
// an operation receiver.
func (fp *field) Zero() Element {
	fp.zeroConstOnce.Do(func() {
		element, err := fp.ConstantFromBig(big.NewInt(0))
		if err != nil {
			panic(fmt.Sprintf("witness from zero: %v", err))
		}
		fp.zeroConst = &element
	})
	return *fp.zeroConst
}

// One returns one as a constant. The returned element is not safe to use as an
// operation receiver.
func (fp *field) One() Element {
	fp.oneConstOnce.Do(func() {
		element, err := fp.ConstantFromBig(big.NewInt(1))
		if err != nil {
			panic(fmt.Sprintf("witness from one: %v", err))
		}
		fp.oneConst = &element
	})
	return *fp.oneConst
}

// ConstantFromBig returns a constant element from the value. The returned
// element is not safe to use as an operation receiver.
func (fp *field) ConstantFromBig(value *big.Int) (Element, error) {
	constValue := new(big.Int).Set(value)
	if fp.r.Cmp(value) != 0 {
		constValue.Mod(constValue, fp.r)
	}
	limbs := make([]*big.Int, fp.nbLimbs)
	for i := range limbs {
		limbs[i] = new(big.Int)
	}
	if err := decompose(constValue, fp.limbSize, limbs); err != nil {
		return Element{}, fmt.Errorf("decompose value: %w", err)
	}
	limbVars := make([]frontend.Variable, len(limbs))
	for i := range limbs {
		limbVars[i] = frontend.Variable(limbs[i])
	}
	e := Element{
		Limbs:    limbVars,
		params:   fp,
		overflow: 0,
		api:      nil,
	}
	return e, nil
}

// ConstantFromBigOrPanic returns a constant from value or panics if value does
// not define a valid element in the ring.
func (fp *field) ConstantFromBigOrPanic(value *big.Int) Element {
	el, err := fp.ConstantFromBig(value)
	if err != nil {
		panic(err)
	}
	return el
}

// PackLimbs returns a constant element from the given limbs. The
// returned element is not safe to use as an operation receiver.
func (fp *field) PackLimbs(limbs []frontend.Variable) Element {
	// TODO: check that every limb does not overflow the expected width
	return Element{
		Limbs:    limbs,
		params:   fp,
		overflow: 0,
		api:      nil,
	}
}

func newElement(f *field) Element {
	return Element{
		params: f,
		Limbs:  make([]frontend.Variable, f.nbLimbs),
	}
}

// From returns an element by regrouping the limbs to these parameters.
func (fp *field) From(api frontend.API, a Element) Element {
	return Element{
		api:      api,
		params:   fp,
		overflow: a.overflow,
		Limbs:    regroupLimbs(api, a.params, fp, a.Limbs),
	}
}

// isEqual returns if fp is equivalent to other.
func (fp *field) isEqual(other *field) bool {
	return fp.r.Cmp(other.r) == 0 && fp.limbSize == other.limbSize
}

// ToBits returns the bit representation of the Element in little-endian (LSB
// first) order. The returned bits are constrained to be 0-1. The number of
// returned bits is nbLimbs*nbBits+overflow. To obtain the bits of the canonical
// representation of Element, reduce Element first and take less significant
// bits corresponding to the bitwidth of the emulated modulus.
func (e *Element) ToBits() []frontend.Variable {
	var carry frontend.Variable = 0
	var fullBits []frontend.Variable
	var limbBits []frontend.Variable
	for i := 0; i < len(e.Limbs); i++ {
		limbBits = bits.ToBinary(e.api, e.api.Add(e.Limbs[i], carry), bits.WithNbDigits(int(e.params.limbSize+e.overflow)))
		fullBits = append(fullBits, limbBits[:e.params.limbSize]...)
		if e.overflow > 0 {
			carry = bits.FromBinary(e.api, limbBits[e.params.limbSize:])
		}
	}
	fullBits = append(fullBits, limbBits[e.params.limbSize:e.params.limbSize+e.overflow]...)
	return fullBits
}

// FromBits sets the value of e from the given boolean variables in. The method
// assumes that the bits are given from the canonical representation of element
// (less than modulus).
func (e *Element) FromBits(in []frontend.Variable) {
	nbLimbs := (uint(len(in)) + e.params.limbSize - 1) / e.params.limbSize
	limbs := make([]frontend.Variable, nbLimbs)
	for i := uint(0); i < nbLimbs-1; i++ {
		limbs[i] = bits.FromBinary(e.api, in[i*e.params.limbSize:(i+1)*e.params.limbSize])
	}
	limbs[nbLimbs-1] = bits.FromBinary(e.api, in[(nbLimbs-1)*e.params.limbSize:])
	e.overflow = 0
	e.Limbs = limbs
}

// maxOverflow returns the maximal possible overflow for the element. If the
// overflow of the next operation exceeds the value returned by this method,
// then the limbs may overflow the native field.
func (e Element) maxOverflow() uint {
	e.params.maxOfOnce.Do(func() {
		e.params.maxOf = uint(e.api.Compiler().FieldBitLen()-1) - e.params.limbSize
	})
	return e.params.maxOf
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
func (e *Element) AssertLimbsEquality(a Element) {
	maxOverflow := e.overflow
	if a.overflow > e.overflow {
		maxOverflow = a.overflow
	}
	rgpar := regroupParams(e.params, uint(e.api.Compiler().FieldBitLen()), maxOverflow)
	rge := rgpar.From(e.api, *e)
	rga := rgpar.From(e.api, a)
	// slow path -- the overflows are different. Need to compare with carries.
	// TODO: we previously assumed that one side was "larger" than the other
	// side, but I think this assumption is not valid anymore
	if e.overflow > a.overflow {
		assertLimbsEqualitySlow(rge.api, rge.Limbs, rga.Limbs, rge.params.limbSize, rge.overflow)
	} else {
		assertLimbsEqualitySlow(rge.api, rga.Limbs, rge.Limbs, rga.params.limbSize, rga.overflow)
	}
}

// EnforceWidth enforces that the bitlength of the value is exactly the
// bitlength of the modulus. Any newly initialized variable should be
// constrained to ensure correct operations.
func (e *Element) EnforceWidth() {
	for i := range e.Limbs {
		limbNbBits := int(e.params.limbSize)
		if i == len(e.Limbs)-1 {
			// take only required bits from the most significant limb
			limbNbBits = ((e.params.r.BitLen() - 1) % int(e.params.limbSize)) + 1
		}
		// bits.ToBinary restricts the least significant NbDigits to be equal to
		// the limb value. This is sufficient to restrict for the bitlength and
		// we can discard the bits themselves.
		bits.ToBinary(e.api, e.Limbs[i], bits.WithNbDigits(limbNbBits))
	}
}

// Add sets e to a+b and returns e. The returned element may not be reduced to
// be less than the ring modulus.
func (e *Element) Add(a, b Element) *Element {
	// variable case only
	// TODO: figure out case when one element is a constant. If one addend is a
	// constant, then we do not reduce it (but this is always case as the
	// constant's overflow never increases?)
	// TODO: check that the target is a variable (has an API)
	// TODO: if both are constants, then add big ints
	overflow, err := e.addPreCond(a, b)
	if err != nil {
		panic(err)
	}
	e.add(a, b, overflow)
	return e
}

func (e Element) addPreCond(a, b Element) (nextOverflow uint, err error) {
	nextOverflow = 1
	reduceRight := a.overflow < b.overflow
	if a.overflow > b.overflow {
		nextOverflow += a.overflow
	} else {
		nextOverflow += b.overflow
	}
	if nextOverflow > e.maxOverflow() {
		err = errOverflow{op: "add", nextOverflow: nextOverflow, maxOverflow: e.maxOverflow(), reduceRight: reduceRight}
	}
	return
}

func (e *Element) add(a, b Element, nextOverflow uint) {
	nbLimbs := len(a.Limbs)
	if len(b.Limbs) > nbLimbs {
		nbLimbs = len(b.Limbs)
	}
	limbs := make([]frontend.Variable, nbLimbs)
	for i := range limbs {
		limbs[i] = 0
		if i < len(a.Limbs) {
			limbs[i] = e.api.Add(limbs[i], a.Limbs[i])
		}
		if i < len(b.Limbs) {
			limbs[i] = e.api.Add(limbs[i], b.Limbs[i])
		}
	}
	e.Limbs = limbs
	e.overflow = nextOverflow
}

// Mul sets e to a*b and returns e. The returned element may not be reduced to
// be less than the ring modulus.
func (e *Element) Mul(a, b Element) *Element {
	// XXX: currently variable case only
	// TODO: when one element is constant.
	// TODO: check that target is initialized (has an API)
	// TODO: if both are constants, then do big int mul
	overflow, err := e.mulPreCond(a, b)
	if err != nil {
		panic(err)
	}
	e.mul(a, b, overflow)
	return e
}

func (e Element) mulPreCond(a, b Element) (nextOverflow uint, err error) {
	reduceRight := a.overflow < b.overflow
	nbResLimbs := nbMultiplicationResLimbs(len(a.Limbs), len(b.Limbs))
	nextOverflow = e.params.limbSize + uint(math.Log2(float64(2*nbResLimbs-1))) + 1 + a.overflow + b.overflow
	if nextOverflow > e.maxOverflow() {
		err = errOverflow{op: "mul", nextOverflow: nextOverflow, maxOverflow: e.maxOverflow(), reduceRight: reduceRight}
	}
	return
}

func (e *Element) mul(a, b Element, nextOverflow uint) {
	limbs, err := computeMultiplicationHint(e.api, e.params, a.Limbs, b.Limbs)
	if err != nil {
		panic(fmt.Sprintf("multiplication hint: %s", err))
	}
	// create constraints (\sum_{i=0}^{m-1} a_i c^i) * (\sum_{i=0}^{m-1} b_i
	// c^i) = (\sum_{i=0}^{2m-2} z_i c^i) for c \in {1, 2m-1}
	for c := 1; c <= len(limbs); c++ {
		cb := big.NewInt(int64(c)) // c
		bit := big.NewInt(1)       // c^i
		l := e.api.Mul(a.Limbs[0], bit)
		for i := 1; i < len(a.Limbs); i++ {
			bit.Mul(bit, cb)
			l = e.api.Add(l, e.api.Mul(a.Limbs[i], bit))
		}
		bit.SetInt64(1)
		r := e.api.Mul(b.Limbs[0], bit)
		for i := 1; i < len(b.Limbs); i++ {
			bit.Mul(bit, cb)
			r = e.api.Add(r, e.api.Mul(b.Limbs[i], bit))
		}
		bit.SetInt64(1)
		o := e.api.Mul(limbs[0], bit)
		for i := 1; i < len(limbs); i++ {
			bit.Mul(bit, cb)
			o = e.api.Add(o, e.api.Mul(limbs[i], bit))
		}
		e.api.AssertIsEqual(e.api.Mul(l, r), o)
	}
	e.Limbs = limbs
	e.overflow = nextOverflow
}

// Reduce reduces a modulo modulus and assigns e to the reduced value.
func (e *Element) Reduce(a Element) *Element {
	if a.overflow == 0 {
		// fast path - already reduced, omit reduction.
		e.Set(a)
		return e
	}
	// slow path - use hint to reduce value
	r, err := computeReductionHint(e.api, a.params, a.Limbs)
	if err != nil {
		panic(fmt.Sprintf("reduction hint: %v", err))
	}
	e.Limbs = r
	e.overflow = 0
	e.AssertIsEqual(a)
	return e
}

// Set sets e to a and returns e. If a is constant, then it also enforces the
// widths of the limbs.
func (e *Element) Set(a Element) {
	e.Limbs = make([]frontend.Variable, len(a.Limbs))
	e.overflow = a.overflow
	copy(e.Limbs, a.Limbs)
	if a.api == nil {
		// we are setting from constant -- ensure that the widths of the limbs
		// are restricted
		e.EnforceWidth()
	}
}

// AssertIsEqual ensures that a is equal to e modulo the modulus.
func (e *Element) AssertIsEqual(a Element) {
	diff := e.params.Element(e.api)
	diff.Sub(a, *e)
	kLimbs, err := computeEqualityHint(e.api, e.params, diff)
	if err != nil {
		panic(fmt.Sprintf("hint error: %v", err))
	}
	k := e.params.PackLimbs(kLimbs)
	p := e.params.Modulus()
	kp := e.params.Element(e.api)
	kp.Mul(k, p)
	diff.AssertLimbsEquality(kp)
}

// AssertIsEqualLessThan ensures that e is less or equal than e.
func (e *Element) AssertIsLessEqualThan(a Element) {
	if e.overflow+a.overflow > 0 {
		panic("inputs must have 0 overflow")
	}
	eBits := e.ToBits()
	aBits := a.ToBits()
	f := func(xbits, ybits []frontend.Variable) []frontend.Variable {
		diff := len(xbits) - len(ybits)
		ybits = append(ybits, make([]frontend.Variable, diff)...)
		for i := len(ybits) - diff - 1; i < len(ybits); i++ {
			ybits[i] = 0
		}
		return ybits
	}
	if len(eBits) > len(aBits) {
		aBits = f(eBits, aBits)
	} else {
		eBits = f(aBits, eBits)
	}
	p := make([]frontend.Variable, len(eBits)+1)
	p[len(eBits)] = 1
	for i := len(eBits) - 1; i >= 0; i-- {
		v := e.api.Mul(p[i+1], eBits[i])
		p[i] = e.api.Select(aBits[i], v, p[i+1])
		t := e.api.Select(aBits[i], 0, p[i+1])
		l := e.api.Sub(1, t, eBits[i])
		ll := e.api.Mul(l, eBits[i])
		e.api.AssertIsEqual(ll, 0)
	}
}

// Sub sets e to a-b and returns e. The returned element may not be reduced to
// be less than the ring modulus.
func (e *Element) Sub(a, b Element) *Element {
	overflow, err := e.subPreCond(a, b)
	if err != nil {
		panic(err)
	}
	e.sub(a, b, overflow)
	return e
}

func (e Element) subPreCond(a, b Element) (nextOverflow uint, err error) {
	reduceRight := a.overflow < b.overflow+2
	nextOverflow = b.overflow + 2
	if a.overflow > nextOverflow {
		nextOverflow = a.overflow
	}
	if nextOverflow > e.maxOverflow() {
		err = errOverflow{op: "sub", nextOverflow: nextOverflow, maxOverflow: e.maxOverflow(), reduceRight: reduceRight}
	}
	return
}

func (e *Element) sub(a, b Element, nextOverflow uint) {
	// first we have to compute padding to ensure that the subtraction does not
	// underflow.
	nbLimbs := len(a.Limbs)
	if len(b.Limbs) > nbLimbs {
		nbLimbs = len(b.Limbs)
	}
	limbs := make([]frontend.Variable, nbLimbs)
	padLimbs := subPadding(e.params, b.overflow, uint(nbLimbs))
	for i := range limbs {
		limbs[i] = padLimbs[i]
		if i < len(a.Limbs) {
			limbs[i] = e.api.Add(limbs[i], a.Limbs[i])
		}
		if i < len(b.Limbs) {
			limbs[i] = e.api.Sub(limbs[i], b.Limbs[i])
		}
	}
	e.Limbs = limbs
	e.overflow = nextOverflow
}

// Div sets e to a/b and returns e. If modulus is not a prime, it panics. The
// result is less than the modulus. This method is more efficient than inverting
// b and multiplying it by a.
func (e *Element) Div(a, b Element) *Element {
	if !e.params.hasInverses {
		panic("modulus not a prime")
	}
	div, err := computeDivisionHint(e.api, e.params, a.Limbs, b.Limbs)
	if err != nil {
		panic(fmt.Sprintf("compute division: %v", err))
	}
	e.Limbs = div
	e.overflow = 0
	e.EnforceWidth()
	res := e.params.Element(e.api)
	res.Mul(*e, b)
	res.AssertIsEqual(a)
	return e
}

// Inverse sets e to 1/a and returns e. If modulus is not a prime, it panics.
// The result is less than the modulus.
func (e *Element) Inverse(a Element) *Element {
	if !e.params.hasInverses {
		panic("modulus not a prime")
	}
	k, err := computeInverseHint(e.api, e.params, a.Limbs)
	if err != nil {
		panic(fmt.Sprintf("compute inverse: %v", err))
	}
	e.Limbs = k
	e.overflow = 0
	e.EnforceWidth()
	res := e.params.Element(e.api)
	res.Mul(*e, a)
	one := e.params.One()
	res.AssertIsEqual(one)
	return e
}

// Negate sets e to -a and returns e. The returned element may be larger than
// the modulus.
func (e *Element) Negate(a Element) *Element {
	z := e.params.Zero()
	return e.Sub(z, a)
}

// Select sets e to a if selector == 0 and to b otherwise.
func (e *Element) Select(selector frontend.Variable, a, b Element) *Element {
	if len(a.Limbs) != len(b.Limbs) {
		panic("unequal limb counts for select")
	}
	if a.overflow != b.overflow {
		panic("unequal overflows for select")
	}
	e.Limbs = make([]frontend.Variable, len(a.Limbs))
	e.overflow = a.overflow
	for i := range a.Limbs {
		e.Limbs[i] = e.api.Select(selector, a.Limbs[i], b.Limbs[i])
	}
	return e
}

// Lookup2 performs two-bit lookup between a, b, c, d based on lookup bits b1
// and b2. Sets e to a if b0=b1=0, b if b0=1 and b1=0, c if b0=0 and b1=1, d if b0=b1=1.
func (e *Element) Lookup2(b0, b1 frontend.Variable, a, b, c, d Element) *Element {
	if len(a.Limbs) != len(b.Limbs) || len(a.Limbs) != len(c.Limbs) || len(a.Limbs) != len(d.Limbs) {
		panic("unequal limb counts for lookup")
	}
	if a.overflow != b.overflow || a.overflow != c.overflow || a.overflow != d.overflow {
		panic("unequal overflows for lookup")
	}
	e.Limbs = make([]frontend.Variable, len(a.Limbs))
	e.overflow = a.overflow
	for i := range a.Limbs {
		e.Limbs[i] = e.api.Lookup2(b0, b1, a.Limbs[i], b.Limbs[i], c.Limbs[i], d.Limbs[i])
	}
	return e
}

// reduceAndOp applies op on the inputs. If the pre-condition check preCond
// errs, then first reduces the input arguments. The reduction is done
// one-by-one with the element with highest overflow reduced first.
func (e *Element) reduceAndOp(op func(Element, Element, uint), preCond func(Element, Element) (uint, error), a, b *Element) {
	var nextOverflow uint
	var err error
	var target errOverflow
	for nextOverflow, err = preCond(*a, *b); errors.As(err, &target); nextOverflow, err = preCond(*a, *b) {
		if !target.reduceRight {
			a.Reduce(*a)
		} else {
			b.Reduce(*b)
		}
	}
	op(*a, *b, nextOverflow)
}
