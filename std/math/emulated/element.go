package emulated

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/utils"
)

// Element defines an element in the ring of integers modulo n. The integer
// value of the element is split into limbs of nbBits lengths and represented as
// a slice of limbs. The type parameter defines the field this element belongs
// to.
type Element[T FieldParams] struct {
	Limbs []frontend.Variable `gnark:"limbs,inherit"` // in little-endian (least significant limb first) encoding

	// overflow indicates the number of additions on top of the normal form. To
	// ensure that none of the limbs overflow the scalar field of the snark
	// curve, we must check that nbBits+overflow < floor(log2(fr modulus))
	overflow uint `gnark:"-"`
}

// NewElement builds a new emulated element from input. The inputs can be:
//   - of type Element[T] (or a pointer to it). Then, the limbs are cloned and packed into new Element[T],
//   - integer-like. Then it is cast to [*big.Int], decomposed into limbs and packed into new Element[T],
//   - a variable in circuit. Then, it is packed into new Element[T]
func NewElement[T FieldParams](v interface{}) Element[T] {
	r := Element[T]{}
	var fp T

	if v == nil {
		r.Limbs = make([]frontend.Variable, fp.NbLimbs())
		for i := 0; i < len(r.Limbs); i++ {
			r.Limbs[i] = 0
		}

		return r
	}
	switch tv := v.(type) {
	case Element[T]:
		r.Limbs = make([]frontend.Variable, len(tv.Limbs))
		copy(r.Limbs, tv.Limbs)
		r.overflow = tv.overflow
		return r
	case *Element[T]:
		r.Limbs = make([]frontend.Variable, len(tv.Limbs))
		copy(r.Limbs, tv.Limbs)
		r.overflow = tv.overflow
		return r
	}
	if frontend.IsCanonical(v) {
		// TODO @gbotrel @ivokub check this -- seems oddd.
		r.Limbs = []frontend.Variable{v}
		return r
	}

	// convert to big.Int
	bValue := utils.FromInterface(v)

	// mod reduce
	if fp.Modulus().Cmp(&bValue) != 0 {
		bValue.Mod(&bValue, fp.Modulus())
	}

	// decompose into limbs
	// TODO @gbotrel use big.Int pool here
	limbs := make([]*big.Int, fp.NbLimbs())
	for i := range limbs {
		limbs[i] = new(big.Int)
	}
	if err := decompose(&bValue, fp.BitsPerLimb(), limbs); err != nil {
		panic(fmt.Errorf("decompose value: %w", err))
	}

	// assign limb values
	r.Limbs = make([]frontend.Variable, fp.NbLimbs())
	for i := range limbs {
		r.Limbs[i] = frontend.Variable(limbs[i])
	}

	return r
}

// newElementPtr is shorthand for initialising new element using NewElement and
// taking pointer to it. We only want to have a public method for initialising
// an element which return a value because the user uses this only for witness
// creation and it mess up schema parsing.
func newElementPtr[T FieldParams](v interface{}) *Element[T] {
	el := NewElement[T](v)
	return &el
}

// newElementLimbs sets the limbs and overflow. Given as a function for later
// possible refactor.
func newElementLimbs[T FieldParams](limbs []frontend.Variable, overflow uint) *Element[T] {
	return &Element[T]{Limbs: limbs, overflow: overflow}
}

// GnarkInitHook describes how to initialise the element.
func (e *Element[T]) GnarkInitHook() {
	if e.Limbs == nil {
		*e = NewElement[T](nil)
	}
}
