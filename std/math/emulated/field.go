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
	nConst        Element[T]
	zeroConstOnce sync.Once
	zeroConst     Element[T]
	oneConstOnce  sync.Once
	oneConst      Element[T]

	log zerolog.Logger
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
		api: native,
		log: logger.Logger(),
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

// Zero returns zero as a constant.
func (f *Field[T]) Zero() *Element[T] {
	f.zeroConstOnce.Do(func() {
		f.zeroConst = NewElement[T](nil)
	})
	return &f.zeroConst
}

// One returns one as a constant.
func (f *Field[T]) One() *Element[T] {
	f.oneConstOnce.Do(func() {
		f.oneConst = NewElement[T](1)
	})
	return &f.oneConst
}

// Modulus returns the modulus of the emulated ring as a constant.
func (f *Field[T]) Modulus() *Element[T] {
	f.nConstOnce.Do(func() {
		f.nConst = NewElement[T](f.fParams.Modulus())
	})
	return &f.nConst
}

// PackElementLimbs returns an element from the given limbs. The method
// constrains the limbs to have same width as the modulus of the field.
func (f *Field[T]) PackElementLimbs(limbs []frontend.Variable) *Element[T] {
	e := newElementLimbs[T](limbs, 0)
	f.enforceWidth(e, true)
	return e
}

// PackFullLimbs creates an element from the given limbs and enforces every limb
// to have NbBits bits.
func (f *Field[T]) PackFullLimbs(limbs []frontend.Variable) *Element[T] {
	e := newElementLimbs[T](limbs, 0)
	f.enforceWidth(e, false)
	return e
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
