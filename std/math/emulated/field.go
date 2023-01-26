package emulated

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/logger"
	"github.com/rs/zerolog"
	"golang.org/x/exp/constraints"
)

// Field holds the configuration for non-native field operations. The field
// parameters (modulus, number of limbs) is given by [FieldParams] type
// parameter. If [FieldParams.IsPrime] is true, then allows inverse and division
// operations.
type Field[T FieldParams] struct {
	// api is the native API
	api frontend.API

	// f carries the ring parameters
	fParams T

	// maxOf is the maximum overflow before the element must be reduced.
	maxOf     uint
	maxOfOnce sync.Once

	// constants for often used elements n, 0 and 1. Allocated only once
	nConstOnce    sync.Once
	nConst        *Element[T]
	zeroConstOnce sync.Once
	zeroConst     *Element[T]
	oneConstOnce  sync.Once
	oneConst      *Element[T]

	log zerolog.Logger

	constrainedLimbs map[uint64]struct{}
}

// NewField returns an object to be used in-circuit to perform emulated
// arithmetic over the field defined by type parameter [FieldParams]. The
// operations on this type are defined on [Element]. There is also another type
// [FieldAPI] implementing [frontend.API] which can be used in place of native
// API for existing circuits.
//
// This is an experimental feature and performing emulated arithmetic in-circuit
// is extremly costly. See package doc for more info.
func NewField[T FieldParams](native frontend.API) (*Field[T], error) {
	f := &Field[T]{
		api:              native,
		log:              logger.Logger(),
		constrainedLimbs: make(map[uint64]struct{}),
	}

	// ensure prime is correctly set
	if f.fParams.IsPrime() {
		if !f.fParams.Modulus().ProbablyPrime(20) {
			return nil, fmt.Errorf("invalid parametrization: modulus is not prime")
		}
	}

	if f.fParams.BitsPerLimb() < 3 {
		// even three is way too small, but it should probably work.
		return nil, fmt.Errorf("nbBits must be at least 3")
	}

	if f.fParams.Modulus().Cmp(big.NewInt(1)) < 1 {
		return nil, fmt.Errorf("n must be at least 2")
	}

	nbLimbs := (uint(f.fParams.Modulus().BitLen()) + f.fParams.BitsPerLimb() - 1) / f.fParams.BitsPerLimb()
	if nbLimbs != f.fParams.NbLimbs() {
		return nil, fmt.Errorf("nbLimbs mismatch got %d expected %d", f.fParams.NbLimbs(), nbLimbs)
	}

	if f.api == nil {
		return f, fmt.Errorf("missing api")
	}

	if uint(f.api.Compiler().FieldBitLen()) < 2*f.fParams.BitsPerLimb()+1 {
		return nil, fmt.Errorf("elements with limb length %d does not fit into scalar field", f.fParams.BitsPerLimb())
	}

	return f, nil
}

// NewElement builds a new Element[T] from input v.
//   - if v is a Element[T] or *Element[T] it clones it
//   - if v is a constant this is equivalent to calling emulated.NewConstant[T]
//   - if this methods interpret v  (frontend.Variable or []frontend.Variable) as being the limbs; and constrain the limbs following the parameters of the Field.
func (f *Field[T]) NewElement(v interface{}) *Element[T] {
	if e, ok := v.(Element[T]); ok {
		return e.copy()
	}
	if e, ok := v.(*Element[T]); ok {
		return e.copy()
	}
	if frontend.IsCanonical(v) {
		return f.packLimbs([]frontend.Variable{v}, true)
	}
	if e, ok := v.([]frontend.Variable); ok {
		for _, sv := range e {
			if !frontend.IsCanonical(sv) {
				panic("[]frontend.Variable that are not canonical (known to the compiler) is not a valid input")
			}
		}
		return f.packLimbs(e, true)
	}
	c := NewConstant[T](v)
	return &c
}

// Zero returns zero as a constant.
func (f *Field[T]) Zero() *Element[T] {
	f.zeroConstOnce.Do(func() {
		f.zeroConst = newConstElement[T](0)
	})
	return f.zeroConst
}

// One returns one as a constant.
func (f *Field[T]) One() *Element[T] {
	f.oneConstOnce.Do(func() {
		f.oneConst = newConstElement[T](1)
	})
	return f.oneConst
}

// Modulus returns the modulus of the emulated ring as a constant.
func (f *Field[T]) Modulus() *Element[T] {
	f.nConstOnce.Do(func() {
		f.nConst = newConstElement[T](f.fParams.Modulus())
	})
	return f.nConst
}

// packLimbs returns an element from the given limbs.
// If strict is true, the most significant limb will be constrained to have width of the most
// significant limb of the modulus, which may have less bits than the other limbs. In which case,
// less constraints will be generated.
// If strict is false, each limbs is constrained to have width as defined by field parameter.
func (f *Field[T]) packLimbs(limbs []frontend.Variable, strict bool) *Element[T] {
	e := f.newInternalElement(limbs, 0)
	f.enforceWidth(e, strict)
	return e
}

func (f *Field[T]) enforceWidthConditional(a *Element[T]) (didConstrain bool) {
	if a == nil {
		// for some reason called on nil
		return false
	}
	if a.internal {
		// internal elements are already constrained in the method which returned it
		return false
	}
	if _, isConst := f.constantValue(a); isConst {
		// constant values are constant
		return false
	}
	for i := range a.Limbs {
		if !frontend.IsCanonical(a.Limbs[i]) {
			// this is not a variable. This may happen when some limbs are
			// constant and some variables. A strange case but lets try to cover
			// it anyway.
			continue
		}
		if vv, ok := a.Limbs[i].(interface{ HashCode() uint64 }); ok {
			// okay, this is a canonical variable and it has a hashcode. We use
			// it to see if the limb is already constrained.
			h := vv.HashCode()
			if _, ok := f.constrainedLimbs[h]; !ok {
				// we found a limb which hasn't yet been constrained. This means
				// that we should enforce width for the whole element. But we
				// still iterate over all limbs just to mark them in the table.
				didConstrain = true
				f.constrainedLimbs[h] = struct{}{}
			}
		} else {
			// we have no way of knowing if the limb has been constrained. To be
			// on the safe side constrain the whole element again.
			didConstrain = true
		}
	}
	if didConstrain {
		f.enforceWidth(a, false)
	}
	return
}

func (f *Field[T]) constantValue(v *Element[T]) (*big.Int, bool) {
	var ok bool

	constLimbs := make([]*big.Int, len(v.Limbs))
	for i, l := range v.Limbs {
		// for each limb we get it's constant value if we can, or fail.
		if constLimbs[i], ok = f.api.ConstantValue(l); !ok {
			return nil, false
		}
	}

	res := new(big.Int)
	if err := recompose(constLimbs, f.fParams.BitsPerLimb(), res); err != nil {
		f.log.Error().Err(err).Msg("recomposing constant")
		return nil, false
	}
	return res, true
}

// compact returns parameters which allow for most optimal regrouping of
// limbs. In regrouping the limbs, we encode multiple existing limbs as a linear
// combination in a single new limb.
// compact returns a and b minimal (in number of limbs) representation that fits in the snark field
func (f *Field[T]) compact(a, b *Element[T]) (ac, bc []frontend.Variable, bitsPerLimb uint) {
	// omit width reduction as is done in the calling method already
	maxOverflow := max(a.overflow, b.overflow)
	// subtract one bit as can not potentially use all bits of Fr and one bit as
	// grouping may overflow
	maxNbBits := uint(f.api.Compiler().FieldBitLen()) - 2 - maxOverflow
	groupSize := maxNbBits / f.fParams.BitsPerLimb()
	if groupSize == 0 {
		// no space for compact
		return a.Limbs, b.Limbs, f.fParams.BitsPerLimb()
	}

	bitsPerLimb = f.fParams.BitsPerLimb() * groupSize

	ac = f.compactLimbs(a, groupSize, bitsPerLimb)
	bc = f.compactLimbs(b, groupSize, bitsPerLimb)
	return
}

// compactLimbs perform the regrouping of limbs between old and new parameters.
func (f *Field[T]) compactLimbs(e *Element[T], groupSize, bitsPerLimb uint) []frontend.Variable {
	if f.fParams.BitsPerLimb() == bitsPerLimb {
		return e.Limbs
	}
	nbLimbs := (uint(len(e.Limbs)) + groupSize - 1) / groupSize
	r := make([]frontend.Variable, nbLimbs)
	coeffs := make([]*big.Int, groupSize)
	one := big.NewInt(1)
	for i := range coeffs {
		coeffs[i] = new(big.Int)
		coeffs[i].Lsh(one, f.fParams.BitsPerLimb()*uint(i))
	}
	for i := uint(0); i < nbLimbs; i++ {
		r[i] = uint(0)
		for j := uint(0); j < groupSize && i*groupSize+j < uint(len(e.Limbs)); j++ {
			r[i] = f.api.Add(r[i], f.api.Mul(coeffs[j], e.Limbs[i*groupSize+j]))
		}
	}
	return r
}

// maxOverflow returns the maximal possible overflow for the element. If the
// overflow of the next operation exceeds the value returned by this method,
// then the limbs may overflow the native field.
func (f *Field[T]) maxOverflow() uint {
	f.maxOfOnce.Do(func() {
		f.maxOf = uint(f.api.Compiler().FieldBitLen()-1) - f.fParams.BitsPerLimb()
	})
	return f.maxOf
}

func max[T constraints.Ordered](a ...T) T {
	if len(a) == 0 {
		var f T
		return f
	}
	m := a[0]
	for _, v := range a {
		if v > m {
			m = v
		}
	}
	return m
}
