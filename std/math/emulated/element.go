package emulated

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/utils"
	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
)

// Element defines an element in the ring of integers modulo n. The integer
// value of the element is split into limbs of nbBits lengths and represented as
// a slice of limbs. The type parameter defines the field this element belongs
// to.
type Element[T FieldParams] struct {
	// Limbs is the decomposition of the integer value into limbs in the native
	// field. To enforce that the limbs are of expected width, use Pack...
	// methods on the Field. Uses little-endian (least significant limb first)
	// encoding.
	Limbs []frontend.Variable

	// overflow indicates the number of additions on top of the normal form. To
	// ensure that none of the limbs overflow the scalar field of the snark
	// curve, we must check that nbBits+overflow < floor(log2(fr modulus))
	overflow uint

	// internal indicates if the element is returned from [Field] methods. If
	// so, then we can assume that the limbs are already constrained to be
	// correct width. If the flag is not set, then the Element most probably
	// comes from the witness (or constructed by the user). Then we have to
	// ensure that the limbs are width-constrained. We do not store the
	// enforcement info in the Element to prevent modifying the witness.
	internal bool

	// modReduced indicates that the element has been reduced modulo the modulus
	// and we have asserted that the integer value of the element is strictly
	// less than the modulus. This is required for some operations which depend
	// on the bit-representation of the element (ToBits, exponentiation etc.).
	modReduced bool

	isEvaluated bool
	evaluation  frontend.Variable `gnark:"-"`
}

// bigIntPool is a pool of big.Int objects to avoid frequent allocations
var bigIntPool = sync.Pool{
	New: func() interface{} {
		return new(big.Int)
	},
}

// getBigInt returns a big.Int from the pool
func getBigInt() *big.Int {
	return bigIntPool.Get().(*big.Int).SetInt64(0)
}

// putBigInt returns a big.Int to the pool
func putBigInt(b *big.Int) {
	bigIntPool.Put(b)
}

// ValueOf returns an Element[T] from a constant value. This method is used for
// witness assignment. For in-circuit constant assignment use the
// [Field.NewElement] method.
//
// The input is converted into limbs according to the parameters of the field
// and returned as a new [Element[T]]. Note that it returns the value, not a
// reference, which is more convenient for witness assignment.
func ValueOf[T FieldParams](constant interface{}) Element[T] {
	// in this method we set the isWitness flag to true, because we do not know
	// the width of the input value. Even though it is valid to call this method
	// in circuit without reference to `Field`, then the canonical way would be
	// to call [Field.NewElement] method (which would set isWitness to false).
	if constant == nil {
		r := newConstElement[T](0, true)
		return *r
	}
	r := newConstElement[T](constant, true)
	return *r
}

// newConstElement is shorthand for initialising new element using NewElement and
// taking pointer to it. We only want to have a public method for initialising
// an element which return a value because the user uses this only for witness
// creation and it mess up schema parsing.
func newConstElement[T FieldParams](v interface{}, isWitness bool) *Element[T] {
	var fp T
	// convert to big.Int
	bValue := utils.FromInterface(v)

	// mod reduce
	if fp.Modulus().Cmp(&bValue) != 0 {
		bValue.Mod(&bValue, fp.Modulus())
	}

	// decompose into limbs. When set with isWitness, then we do not know at
	// compile time the width of the input, so we allocate the maximum number of
	// limbs. However, in-circuit we already do (we set it from actual
	// constant), thus we can allocate the exact number of limbs.
	var nbLimbs int
	if isWitness {
		nbLimbs = int(fp.NbLimbs())
	} else {
		nbLimbs = (bValue.BitLen() + int(fp.BitsPerLimb()) - 1) / int(fp.BitsPerLimb())
	}

	// Use big.Int pool instead of creating new objects
	blimbs := make([]*big.Int, nbLimbs)
	for i := range blimbs {
		blimbs[i] = getBigInt()
	}

	if err := limbs.Decompose(&bValue, fp.BitsPerLimb(), blimbs); err != nil {
		// Return big.Int objects to the pool before panicking
		for _, b := range blimbs {
			putBigInt(b)
		}
		panic(fmt.Errorf("decompose value: %w", err))
	}

	// assign limb values
	limbs := make([]frontend.Variable, len(blimbs))
	for i := range limbs {
		limbs[i] = frontend.Variable(blimbs[i])
		// Return big.Int to the pool after use
		putBigInt(blimbs[i])
	}
	return &Element[T]{
		Limbs:    limbs,
		overflow: 0,
		internal: true,
	}
}

// newInternalElement sets the limbs and overflow. Given as a function for later
// possible refactor.
func (f *Field[T]) newInternalElement(limbs []frontend.Variable, overflow uint) *Element[T] {
	return &Element[T]{Limbs: limbs, overflow: overflow, internal: true}
}

// GnarkInitHook describes how to initialise the element.
func (e *Element[T]) GnarkInitHook() {
	if e.Limbs == nil {
		*e = ValueOf[T](0)
		e.internal = false // we need to constrain in later.
	}
	// set modReduced to false - in case the circuit is compiled we may change
	// the value for an existing element. If we don't reset it here, then during
	// second compilation we may take a shortPath where we assume that modReduce
	// flag is set.
	e.modReduced = false
}

// copy makes a deep copy of the element.
func (e *Element[T]) copy() *Element[T] {
	r := Element[T]{}
	r.Limbs = make([]frontend.Variable, len(e.Limbs))
	copy(r.Limbs, e.Limbs)
	r.overflow = e.overflow
	r.internal = e.internal
	r.modReduced = e.modReduced
	return &r
}
