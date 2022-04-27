// package nonnative implements operations modulo an integer
package nonnative

// TODO: add checks which ensure that constants are not used as receivers
// TODO: add sanity checks before the operations (e.g. that overflow is
// sufficient and do not need to reduce)
// TODO: think about different "operation modes". Probably hand-optimized code
// is better than reducing eagerly, but the user should be at least aware during
// compile-time that values need to be reduced. But there should be an easy-mode
// where the user does not need to manually reduce and the library does it as necessary.

import (
	"fmt"
	"math"
	"math/big"
	"sync"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

// Params defines the parameters of the emulated ring of integers modulo n. If
// n is prime, then the ring is also a finite field where inverse and division
// are allowed.
type Params struct {
	// n is the modulus
	n *big.Int
	// hasInverses indicates if order is prime
	hasInverses bool
	// nbLimbs is the number of limbs which fit reduced element
	nbLimbs uint
	// nbBits is number of bits per limb. Top limb may contain less than
	// nbBits bits.
	nbBits uint

	// constants for often used elements n, 0 and 1. Allocated only once
	nConstOnce    sync.Once
	nConst        *Element
	zeroConstOnce sync.Once
	zeroConst     *Element
	oneConstOnce  sync.Once
	oneConst      *Element
}

// NewParams initializes the parameters for emulating operations modulo n where
// every limb of the element contains up to nbBits bits. Returns error if sanity
// checks fail.
//
// This method checks the primality of n to detect if parameters define a finite
// field. As such, invociation of this method is expensive and should be done
// once.
func NewParams(nbBits int, n *big.Int) (*Params, error) {
	if n.Cmp(big.NewInt(1)) < 1 {
		return nil, fmt.Errorf("n must be at least 2")
	}
	if nbBits < 3 {
		// even three is way too small, but it should probably work.
		return nil, fmt.Errorf("nbBits must be at least 3")
	}
	nbLimbs := (n.BitLen() + nbBits - 1) / nbBits
	fp := &Params{
		n:           n,
		nbLimbs:     uint(nbLimbs),
		nbBits:      uint(nbBits),
		hasInverses: n.ProbablyPrime(20),
	}
	return fp, nil
}

// Element defines an element in the ring of integers modulo n. The integer
// value of the element is split into limbs of nbBits lengths and represented as
// a slice of limbs.
type Element struct {
	Limbs []frontend.Variable // in little-endian (least significant limb first) encoding

	// params carries the ring parameters
	params *Params
	// overflow indicates the number of additions on top of the normal form. To
	// ensure that none of the limbs overflow the scalar field of the snark
	// curve, we must check that nbBits+overflow < floor(log2(fr modulus))
	overflow uint
	// api references the API for variable elements
	api frontend.API
}

// Element returns initialized element in the field. The value of this element
// is not constrained and it only safe to use as a reciver in operations. For
// elements initialized to values use Zero(), One() or Modulus().
func (fp *Params) Element(api frontend.API) Element {
	if uint(api.Curve().Info().Fr.Bits) < 2*fp.nbBits+1 {
		panic(fmt.Sprintf("elements with limb length %d does not fit into %s", fp.nbBits, api.Curve().String()))
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
func (fp *Params) Modulus() Element {
	fp.nConstOnce.Do(func() {
		element, err := fp.ConstantFromBig(fp.n)
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
func (fp *Params) Zero() Element {
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
func (fp *Params) One() Element {
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
func (fp *Params) ConstantFromBig(value *big.Int) (Element, error) {
	if fp.n.Cmp(value) == -1 {
		return Element{}, fmt.Errorf("value larger than order of the field")
	}
	limbs := make([]*big.Int, fp.nbLimbs)
	for i := range limbs {
		limbs[i] = new(big.Int)
	}
	if err := Decompose(value, fp.nbBits, limbs); err != nil {
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

func (fp *Params) ConstantFromBigOrPanic(value *big.Int) Element {
	el, err := fp.ConstantFromBig(value)
	if err != nil {
		panic(err)
	}
	return el
}

// ConstantFromLimbs returns a constant element from the given limbs. The
// returned element is not safe to use as an operation receiver.
func (fp *Params) ConstantFromLimbs(limbs []frontend.Variable) Element {
	// TODO: check that every limb does not overflow the expected width
	return Element{
		Limbs:    limbs,
		params:   fp,
		overflow: 0,
		api:      nil,
	}
}

// Placeholder returns a constant which is safe to use as a placeholder when
// compiling a circuit.
func (fp *Params) Placeholder() Element {
	e, err := fp.ConstantFromBig(big.NewInt(0))
	if err != nil {
		panic(err)
	}
	return e
}

// ToBits returns the bit representation of the Element in little-endian (LSB
// first) order. The returned bits are constrained to be 0-1.
func (e *Element) ToBits() []frontend.Variable {
	var fullBits []frontend.Variable
	for i := 0; i < len(e.Limbs)-1; i++ {
		limbBits := bits.ToBinary(e.api, e.Limbs[i], bits.WithNbDigits(int(e.params.nbBits)))
		fullBits = append(fullBits, limbBits...)
	}
	limbBits := bits.ToBinary(e.api, e.Limbs[e.params.nbLimbs-1], bits.WithNbDigits((e.params.n.BitLen()-1)%int(e.params.nbBits)+1))
	fullBits = append(fullBits, limbBits...)
	return fullBits
}

// maxWidth returns the maximum width of the limb value + overflow which fits
// into the scalar field widthout overflow. If next operation exceeds the value,
// then the element should be reduced before the operation.
func (e *Element) maxWidth() uint {
	return uint(e.api.Curve().Info().Fr.Modulus().BitLen()) - 1
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

	// TODO: group carries. xjsnark paper describes that we can actually compute
	// a carry over multiple limbs (assuming the limbs are small enough).
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
		// TODO: instead of full binary decomposition, do unconstrained
		// decomposition and check that the bits are zeros. Does not make
		// difference for R1CS but should require fever constraints for PLONK.
		// TODO: more efficient methods for splitting a variable? Because we are
		// splitting the value into two, then maybe we do not need the whole
		// binary decomposition \sum_{i=0}^n a_i 2^i, but can use a * 2^nbits +
		// b. Then we can also omit the FromBinary call.
		diffBits := bits.ToBinary(api, diff, bits.WithNbDigits(int(nbBits+nbCarryBits+1)))
		diffMain := bits.FromBinary(api, diffBits[:nbBits])
		api.AssertIsEqual(diffMain, 0)
		carry = bits.FromBinary(api, diffBits[nbBits:nbBits+nbCarryBits+1])
	}
	api.AssertIsEqual(carry, maxValueShift)
}

// AssertLimbsEquality asserts that the limbs represent a same integer value (up
// to overflow). This method does not ensure that the values are equal modulo
// the field order. For strict equality, use AssertIsEqual.
func (e *Element) AssertLimbsEquality(a Element) {
	// fast path -- no overflow -- can just compare limb-wise
	if a.overflow == e.overflow {
		// TODO: not complete - we should also ensure that len(e.Limbs) <=
		// len(a.Limbs) and ensure that rest of e.Limbs are zero
		for i := range a.Limbs {
			e.api.AssertIsEqual(a.Limbs[i], e.Limbs[i])
		}
		return
	}
	// slow path -- the overflows are different. Need to compare with carries.
	// TODO: we previously assumed that one side was "larger" than the other
	// side, but I think this assumption is not valid anymore
	if e.overflow > a.overflow {
		assertLimbsEqualitySlow(e.api, e.Limbs, a.Limbs, e.params.nbBits, e.overflow)
	} else {
		assertLimbsEqualitySlow(e.api, a.Limbs, e.Limbs, a.params.nbBits, a.overflow)
	}
}

// EnforceWidth enforces that the bitlength of the value is exactly the
// bitlength of the modulus. Any newly initialized variable should be
// constrained to ensure correct operations.
func (e *Element) EnforceWidth() {
	for i := range e.Limbs {
		limbNbBits := int(e.params.nbBits)
		if i == len(e.Limbs)-1 {
			// take only required bits from the most significant limb
			limbNbBits = ((e.params.n.BitLen() - 1) % int(e.params.nbBits)) + 1
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
	if a.overflow+e.params.nbBits == e.maxWidth() {
		a.Reduce(a)
	}
	if b.overflow+e.params.nbBits == e.maxWidth() {
		b.Reduce(b)
	}
	e.overflow = 1
	if a.overflow > b.overflow {
		e.overflow += a.overflow
	} else {
		e.overflow += b.overflow
	}
	for i := range e.Limbs {
		e.Limbs[i] = e.api.Add(a.Limbs[i], b.Limbs[i])
	}
	return e
}

// Mul sets e to a*b and returns e. The returned element may not be reduced to
// be less than the ring modulus.
func (e *Element) Mul(a, b Element) *Element {
	// variable case only
	// TODO: when one element is constant.
	// TODO: check that target is initialized (has an API)
	// TODO: if both are constants, then do big int mul
	limbs, err := computeMultiplicationHint(e.api, e.params, a.Limbs, b.Limbs)
	if err != nil {
		panic(fmt.Sprintf("multiplication hint: %s", err))
	}
	// create constraints (\sum_{i=0}^{m-1} a_i c^i) * (\sum_{i=0}^{m-1} b_i
	// c^i) = (\sum_{i=0}^{2m-2} z_i c^i) for c \in {1, 2m-1}
	for c := 1; c < len(limbs); c++ {
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
	e.overflow = e.params.nbBits + uint(math.Log2(float64(e.params.nbLimbs))+1)
	// result is not reduced
	return e
}

// Reduce reduces a modulo modulus and assigns e to the reduced value.
func (e *Element) Reduce(a Element) *Element {
	if e.overflow == 0 {
		// fast path - already reduced, omit reduction.
		return e
	}
	// slow path - use hint to reduce value
	r, err := computeReductionHint(e.api, e.params, e.Limbs)
	if err != nil {
		panic(fmt.Sprintf("reduction hint: %v", err))
	}
	e.Limbs = r
	e.EnforceWidth()
	e.AssertIsEqual(a)
	return e
}

// Set sets e to a and returns e. If a is constant, then it also enforces the
// widths of the limbs.
func (e *Element) Set(a Element) {
	e.Limbs = make([]frontend.Variable, e.params.nbLimbs)
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
	kLimbs, err := computeEqualityHint(e.api, e.params, diff.Limbs)
	if err != nil {
		panic(fmt.Sprintf("hint error: %v", err))
	}
	k := e.params.ConstantFromLimbs(kLimbs)
	p := e.params.Modulus()
	kp := e.params.Element(e.api)
	kp.Mul(k, p)
	diff.AssertLimbsEquality(kp)
}

// Sub sets e to a-b and returns e. The returned element may not be reduced to
// be less than the ring modulus.
func (e *Element) Sub(a, b Element) *Element {
	// first we have to compute padding to ensure that the subtraction does not
	// underflow.
	if a.overflow+e.params.nbBits+2 == e.maxWidth() {
		a.Reduce(a)
	}
	if b.overflow+e.params.nbBits+2 == e.maxWidth() {
		b.Reduce(b)
	}
	nbLimbs := len(a.Limbs)
	if len(b.Limbs) > nbLimbs {
		nbLimbs = len(b.Limbs)
	}
	limbs := make([]frontend.Variable, nbLimbs)
	padLimbs := subPadding(e.params, b.overflow, uint(nbLimbs))
	e.overflow = b.overflow + 2
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
	return nil
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
	return nil
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
	return nil
}

// Negate sets e to -a and returns e. The returned element may not be less than
// the modulus.
func (e *Element) Negate(a Element) *Element {
	z := e.params.Zero()
	return e.Sub(z, a)
}

// Select sets e to a is selector == 0 and to b otherwise.
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
	return nil
}

func (e *Element) Exp(s, a Element) *Element {
	panic("not implemented")
	// return nil
}
