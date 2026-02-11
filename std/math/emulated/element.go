package emulated

import (
	"fmt"
	"math/big"

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

	// bitsDecomposition caches the bit decomposition of the element to avoid
	// redundant ToBits calls. Once computed, the bits are stored here and
	// reused on subsequent ToBits calls on the same element.
	// bitsOverflow stores the overflow value when bits were computed, to ensure
	// cached bits are only used when overflow hasn't changed.
	bitsDecomposition []frontend.Variable `gnark:"-"`
	bitsOverflow      uint                `gnark:"-"`

	isEvaluated bool
	evaluation  frontend.Variable `gnark:"-"`

	// witnessValue stores the value of the witness. We set Limbs from it when
	// calling the [Element.Initialize] method.
	//
	// NB! Even though we have documented not to use [ValueOf] method inside
	// a circuit to define constants, then many users still do it. In that case,
	// the [Element.Initialize] method is not called during witness parsing time and
	// we need to do it before using the limbs. This is automatically done
	// in [Field.enforceWidthConditional] method.
	witnessValue *big.Int
}

// ValueOf returns an Element[T] from a constant value. This method is used for
// witness assignment. For in-circuit constant assignment use the
// [Field.NewElement] method.
//
// The input is converted into limbs according to the parameters of the field
// and returned as a new [Element]. Note that it returns the value, not a
// reference, which is more convenient for witness assignment.
//
// The method is asynchronous and the limb decomposition is done during witness
// parsing.
func ValueOf[T FieldParams](constant interface{}) Element[T] {
	bValue := utils.FromInterface(constant)
	return Element[T]{
		witnessValue: &bValue,
	}
}

// newConstElement is shorthand for initialising new element using NewElement and
// taking pointer to it. We only want to have a public method for initialising
// an element which return a value because the user uses this only for witness
// creation and it mess up schema parsing.
func newConstElement[T FieldParams](field *big.Int, v interface{}, isWitness bool) *Element[T] {
	var fp T
	effNbLimbs, effNbBits := GetEffectiveFieldParams[T](field)
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
		nbLimbs = int(effNbLimbs)
	} else {
		nbLimbs = (bValue.BitLen() + int(effNbBits) - 1) / int(effNbBits)
	}
	// TODO @gbotrel use big.Int pool here
	blimbs := make([]*big.Int, nbLimbs)
	for i := range blimbs {
		blimbs[i] = new(big.Int)
	}
	if err := limbs.Decompose(&bValue, effNbBits, blimbs); err != nil {
		panic(fmt.Errorf("decompose value: %w", err))
	}

	// assign limb values
	limbs := make([]frontend.Variable, len(blimbs))
	for i := range limbs {
		limbs[i] = frontend.Variable(blimbs[i])
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

// Initialize automatically initializes non-native element during circuit parsing and compilation.
// It allocates the limbs and sets the element to be automatically range-checked on first use.
//
// The method has a side effect that when a circuit is parsed multiple times, then the subsequent
// calls to this method will not re-initialize the element. Thus any changes to the non-native element
// persist.
func (e *Element[T]) Initialize(field *big.Int) {
	if e == nil {
		return // we cannot initialize nil element
	}
	if e.Limbs == nil && field == nil {
		panic("field is nil")
	}
	if e.Limbs == nil {
		if e.witnessValue == nil {
			*e = *newConstElement[T](field, 0, true)
		} else {
			*e = *newConstElement[T](field, e.witnessValue, true)
		}
		e.internal = false // we need to constrain in later.
	}
	// set modReduced to false - in case the circuit is compiled we may change
	// the value for an existing element. If we don't reset it here, then during
	// second compilation we may take a shortPath where we assume that modReduce
	// flag is set.
	e.modReduced = false
	// reset bitsDecomposition to avoid stale cached bits from previous compilation
	e.bitsDecomposition = nil
	e.bitsOverflow = 0
}

// copy makes a deep copy of the element.
func (e *Element[T]) copy() *Element[T] {
	r := Element[T]{}
	r.Limbs = make([]frontend.Variable, len(e.Limbs))
	copy(r.Limbs, e.Limbs)
	r.overflow = e.overflow
	r.internal = e.internal
	r.modReduced = e.modReduced
	if e.bitsDecomposition != nil {
		r.bitsDecomposition = make([]frontend.Variable, len(e.bitsDecomposition))
		copy(r.bitsDecomposition, e.bitsDecomposition)
		r.bitsOverflow = e.bitsOverflow
	}
	r.isEvaluated = e.isEvaluated
	r.evaluation = e.evaluation
	if e.witnessValue != nil {
		r.witnessValue = new(big.Int).Set(e.witnessValue)
	}
	return &r
}

// isStrictZero checks if the element is strictly zero by convention. Can be
// used for determining if to take fast paths.
func (e *Element[T]) isStrictZero() bool {
	if e == nil {
		// conventionally we could say it is zero, but this can lead to some strange
		// edge cases where use uninitialized elements. So we just panic.
		panic("nil element. Uninitialized element?")
	}
	switch {
	case e.Limbs == nil && e.witnessValue == nil:
		// here also we could conventionally say it is zero, but this case usually
		// means we use uninitialized element.
		panic("nil limbs and witness value. Uninitialized element?")
	case e.Limbs == nil && e.witnessValue != nil:
		return e.witnessValue.Sign() == 0
	case e.Limbs != nil && len(e.Limbs) == 0:
		// by convention we say that empty limbs are zero
		return true
	default:
		// we could potentially check that the limbs are all zero (or multiple of the modulus),
		// but for consistency we just return false and take potential performance hit.
		return false
	}
}
