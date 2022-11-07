package emulated

import (
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"sync"

	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/rs/zerolog"
)

// Field defines the parameters of the emulated ring of integers modulo n. If
// n is prime, then the ring is also a finite Field where inverse and division
// are allowed.
type Field[T FieldParams] struct {
	// api is the native API
	api     frontend.API
	builder frontend.Builder

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

// NewField returns an object to be used in-circuit to perform emulated arithmetic.
//
// The returned object implements frontend.API and as such, is used transparently in a circuit.
//
// This is an experimental feature and performing emulated arithmetic in-circuit is extremly costly.
// See package doc for more info.
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

func NewBuilder[T FieldParams](b frontend.Builder) (frontend.Builder, error) {
	a, err := NewField[T](b)
	if err != nil {
		return nil, fmt.Errorf("init field: %w", err)
	}
	a.builder = b
	return a, nil
}

func (f *Field[T]) varToElement(in frontend.Variable) Element[T] {
	switch vv := in.(type) {
	case Element[T]:
		return vv
	case *Element[T]:
		return *vv
	default:
		return NewElement[T](in)
	}
}

func (f *Field[T]) varsToElements(in ...frontend.Variable) []Element[T] {
	var els []Element[T]
	for i := range in {
		switch v := in[i].(type) {
		case []frontend.Variable:
			subels := f.varsToElements(v...)
			els = append(els, subels...)
		case frontend.Variable:
			els = append(els, f.varToElement(v))
		default:
			// handle nil value
			panic("can't convert <nil> to Element[T]")
		}
	}
	return els
}

func (f *Field[T]) Add(i1 frontend.Variable, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	els := f.varsToElements(i1, i2, in)
	res := f.reduceAndOp(f.add, f.addPreCond, els[0], els[1])
	for i := 2; i < len(els); i++ {
		res = f.reduceAndOp(f.add, f.addPreCond, res, els[i]) // TODO @gbotrel re-use res memory, don't reallocate limbs !
	}
	return res
}

// Negate sets e to -a and returns e. The returned element may be larger than
// the modulus.
func (f *Field[T]) Neg(i1 frontend.Variable) frontend.Variable {
	el := f.varToElement(i1)

	return f.Sub(f.Zero(), el)
}

func (f *Field[T]) Sub(i1 frontend.Variable, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	els := f.varsToElements(i1, i2, in)
	sub := NewElement[T](nil)
	sub.Set(els[1])
	for i := 2; i < len(els); i++ {
		sub = f.reduceAndOp(f.add, f.addPreCond, sub, els[i])
	}
	res := f.reduceAndOp(f.sub, f.subPreCond, els[0], sub)
	return res
}

func (f *Field[T]) Mul(i1 frontend.Variable, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	els := f.varsToElements(i1, i2, in)
	res := f.reduceAndOp(f.mul, f.mulPreCond, els[0], els[1])
	for i := 2; i < len(els); i++ {
		res = f.reduceAndOp(f.mul, f.mulPreCond, res, els[i])
	}
	res = f.reduce(res)
	return res
}

func (f *Field[T]) DivUnchecked(i1 frontend.Variable, i2 frontend.Variable) frontend.Variable {
	return f.Div(i1, i2)
}

// Div sets e to a/b and returns e. If modulus is not a prime, it panics. The
// result is less than the modulus. This method is more efficient than inverting
// b and multiplying it by a.
func (f *Field[T]) Div(i1 frontend.Variable, i2 frontend.Variable) frontend.Variable {
	if !f.fParams.IsPrime() {
		// TODO shouldn't we still try to do a classic int div in a hint, constraint the result, and let it fail?
		// that would enable things like uint32 div ?
		panic("modulus not a prime")
	}

	els := f.varsToElements(i1, i2)
	a := els[0]
	b := els[1]
	div, err := f.computeDivisionHint(a.Limbs, b.Limbs)
	if err != nil {
		panic(fmt.Sprintf("compute division: %v", err))
	}
	e := NewElement[T](nil)
	e.Limbs = div
	e.overflow = 0
	f.EnforceWidth(e)
	res := (f.Mul(e, b)).(Element[T])
	f.assertIsEqual(res, a)
	return e
}

// Inverse sets e to 1/a and returns e. If modulus is not a prime, it panics.
// The result is less than the modulus.
func (f *Field[T]) Inverse(i1 frontend.Variable) frontend.Variable {
	a := f.varToElement(i1)
	if !f.fParams.IsPrime() {
		panic("modulus not a prime")
	}
	k, err := f.computeInverseHint(a.Limbs)
	if err != nil {
		panic(fmt.Sprintf("compute inverse: %v", err))
	}
	e := NewElement[T](nil)
	e.Limbs = k
	e.overflow = 0
	f.EnforceWidth(e)
	res := (f.Mul(e, a)).(Element[T])
	one := f.One()
	f.assertIsEqual(res, one)
	return e
}

func (f *Field[T]) ToBinary(i1 frontend.Variable, n ...int) []frontend.Variable {
	el := f.varToElement(i1)
	res := f.reduce(el)
	out := f.toBits(res)
	switch len(n) {
	case 0:
	case 1:
		// TODO @gbotrel this can unecessarly constraint some bits
		// and falsify test results where we only want to "mask" a part of the element
		out = out[:n[0]]
	default:
		panic("only single vararg permitted to ToBinary")
	}
	return out
}

func (f *Field[T]) FromBinary(b ...frontend.Variable) frontend.Variable {
	els := f.varsToElements(b)
	in := make([]frontend.Variable, len(els))
	for i := range els {
		f.AssertIsBoolean(els[i])
		in[i] = els[i].Limbs[0]
	}
	e := NewElement[T](nil)
	nbLimbs := (uint(len(in)) + e.fParams.BitsPerLimb() - 1) / e.fParams.BitsPerLimb()
	limbs := make([]frontend.Variable, nbLimbs)
	for i := uint(0); i < nbLimbs-1; i++ {
		limbs[i] = bits.FromBinary(f.api, in[i*e.fParams.BitsPerLimb():(i+1)*e.fParams.BitsPerLimb()])
	}
	limbs[nbLimbs-1] = bits.FromBinary(f.api, in[(nbLimbs-1)*e.fParams.BitsPerLimb():])
	e.overflow = 0
	e.Limbs = limbs
	return e
}

func (f *Field[T]) Xor(a frontend.Variable, b frontend.Variable) frontend.Variable {
	els := f.varsToElements(a, b)
	f.AssertIsBoolean(els[0])
	f.AssertIsBoolean(els[1])
	rv := f.api.Xor(els[0].Limbs[0], els[1].Limbs[0])
	r := f.PackLimbs([]frontend.Variable{rv})
	return r
}

func (f *Field[T]) Or(a frontend.Variable, b frontend.Variable) frontend.Variable {
	els := f.varsToElements(a, b)
	f.AssertIsBoolean(els[0])
	f.AssertIsBoolean(els[1])
	rv := f.api.Or(els[0].Limbs[0], els[1].Limbs[0])
	r := f.PackLimbs([]frontend.Variable{rv})
	return r
}

func (f *Field[T]) And(a frontend.Variable, b frontend.Variable) frontend.Variable {
	els := f.varsToElements(a, b)
	f.AssertIsBoolean(els[0])
	f.AssertIsBoolean(els[1])
	rv := f.api.And(els[0].Limbs[0], els[1].Limbs[0])
	r := f.PackLimbs([]frontend.Variable{rv})
	return r
}

func (f *Field[T]) Select(b frontend.Variable, i1 frontend.Variable, i2 frontend.Variable) frontend.Variable {
	els := f.varsToElements(i1, i2)
	switch vv := b.(type) {
	case Element[T]:
		f.AssertIsBoolean(vv)
		b = vv.Limbs[0]
	case *Element[T]:
		f.AssertIsBoolean(vv)
		b = vv.Limbs[0]
	}
	return f._select(b, els[0], els[1])
}

func (f *Field[T]) Lookup2(b0 frontend.Variable, b1 frontend.Variable, i0 frontend.Variable, i1 frontend.Variable, i2 frontend.Variable, i3 frontend.Variable) frontend.Variable {
	els := f.varsToElements(i0, i1, i2, i3)
	switch vv := b0.(type) {
	case Element[T]:
		f.AssertIsBoolean(vv)
		b0 = vv.Limbs[0]
	case *Element[T]:
		f.AssertIsBoolean(vv)
		b0 = vv.Limbs[0]
	}
	switch vv := b1.(type) {
	case Element[T]:
		f.AssertIsBoolean(vv)
		b1 = vv.Limbs[0]
	case *Element[T]:
		f.AssertIsBoolean(vv)
		b1 = vv.Limbs[0]
	}
	return f.lookup2(b0, b1, els[0], els[1], els[2], els[3])
}

func (f *Field[T]) IsZero(i1 frontend.Variable) frontend.Variable {
	el := f.varToElement(i1)
	reduced := f.reduce(el)
	res := f.api.IsZero(reduced.Limbs[0])
	for i := 1; i < len(reduced.Limbs); i++ {
		f.api.Mul(res, f.api.IsZero(reduced.Limbs[i]))
	}
	r := f.PackLimbs([]frontend.Variable{res})
	return r
}

func (f *Field[T]) Cmp(i1 frontend.Variable, i2 frontend.Variable) frontend.Variable {
	els := f.varsToElements(i1, i2)
	rls := make([]Element[T], 2)
	rls[0] = f.reduce(els[0])
	rls[1] = f.reduce(els[1])
	var res frontend.Variable = 0
	for i := int(f.fParams.NbLimbs() - 1); i >= 0; i-- {
		lmbCmp := f.api.Cmp(rls[0].Limbs[i], rls[1].Limbs[i])
		res = f.api.Select(f.api.IsZero(res), lmbCmp, res)
	}
	return res
}

func (f *Field[T]) AssertIsEqual(i1 frontend.Variable, i2 frontend.Variable) {
	els := f.varsToElements(i1, i2)
	tmp := NewElement[T](els[0])
	f.reduceAndOp(func(a, b Element[T], nextOverflow uint) Element[T] {
		f.assertIsEqual(a, b)
		return NewElement[T](nil)
	},
		func(e1, e2 Element[T]) (uint, error) {
			nextOverflow, err := f.subPreCond(e2, e1)
			var target errOverflow
			if err != nil && errors.As(err, &target) {
				target.reduceRight = !target.reduceRight
				return nextOverflow, target
			}
			return nextOverflow, err
		}, tmp, els[1])
}

func (f *Field[T]) AssertIsDifferent(i1 frontend.Variable, i2 frontend.Variable) {
	els := f.varsToElements(i1, i2)
	rls := []Element[T]{NewElement[T](nil), NewElement[T](nil)}
	rls[0] = f.reduce(els[0])
	rls[1] = f.reduce(els[1])
	var res frontend.Variable = 0
	for i := 0; i < int(f.fParams.NbLimbs()); i++ {
		cmp := f.api.Cmp(rls[0].Limbs[i], rls[1].Limbs[i])
		cmpsq := f.api.Mul(cmp, cmp)
		res = f.api.Add(res, cmpsq)
	}
	f.api.AssertIsDifferent(res, 0)
}

func (f *Field[T]) AssertIsBoolean(i1 frontend.Variable) {
	switch vv := i1.(type) {
	case Element[T]:
		v := f.reduce(vv)
		f.api.AssertIsBoolean(v.Limbs[0])
		for i := 1; i < len(v.Limbs); i++ {
			f.api.AssertIsEqual(v.Limbs[i], 0)
		}
	case *Element[T]:
		v := f.reduce(*vv)
		f.api.AssertIsBoolean(v.Limbs[0])
		for i := 1; i < len(v.Limbs); i++ {
			f.api.AssertIsEqual(v.Limbs[i], 0)
		}
	default:
		f.api.AssertIsBoolean(vv)
	}
}

func (f *Field[T]) AssertIsLessOrEqual(v frontend.Variable, bound frontend.Variable) {
	els := f.varsToElements(v, bound)
	l := f.reduce(els[0])
	r := f.reduce(els[1])
	f.AssertIsLessEqualThan(l, r)
}

func (f *Field[T]) Println(a ...frontend.Variable) {
	els := f.varsToElements(a)
	for i := range els {
		f.api.Println(els[i].Limbs...)
	}
}

func (f *Field[T]) Compiler() frontend.Compiler {
	return f
}

type typedInput struct {
	pos       int
	nbLimbs   int
	isElement bool
}

func (f *Field[T]) NewHint(hf hint.Function, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {
	// this is a trick to allow calling hint functions using non-native
	// elements. We use the fact that the hints take as inputs *big.Int values.
	// Instead of supplying hf to the solver for calling, we wrap it with
	// another function (implementing hint.Function), which takes as inputs the
	// "expanded" version of inputs (where instead of Element[T] values we provide
	// as inputs the limbs of every Element[T]) and returns nbLimbs*nbOutputs
	// number of outputs (i.e. the limbs of non-native Element[T] values). The
	// wrapper then recomposes and decomposes the *big.Int values at runtime and
	// provides them as input to the initially provided hint function.
	var expandedInputs []frontend.Variable
	typedInputs := make([]typedInput, len(inputs))
	for i := range inputs {
		switch vv := inputs[i].(type) {
		case Element[T]:
			expandedInputs = append(expandedInputs, vv.Limbs...)
			typedInputs[i] = typedInput{
				pos:       len(expandedInputs) - len(vv.Limbs),
				nbLimbs:   len(vv.Limbs),
				isElement: true,
			}
		case *Element[T]:
			expandedInputs = append(expandedInputs, vv.Limbs...)
			typedInputs[i] = typedInput{
				pos:       len(expandedInputs) - len(vv.Limbs),
				nbLimbs:   len(vv.Limbs),
				isElement: true,
			}
		default:
			expandedInputs = append(expandedInputs, inputs[i])
			typedInputs[i] = typedInput{
				pos:       len(expandedInputs) - 1,
				nbLimbs:   1,
				isElement: false,
			}
		}
	}
	nbNativeOutputs := nbOutputs * int(f.fParams.NbLimbs())
	wrappedHint := func(_ *big.Int, expandedHintInputs []*big.Int, expandedHintOutputs []*big.Int) error {
		hintInputs := make([]*big.Int, len(inputs))
		hintOutputs := make([]*big.Int, nbOutputs)
		for i, ti := range typedInputs {
			hintInputs[i] = new(big.Int)
			if ti.isElement {
				if err := recompose(expandedHintInputs[ti.pos:ti.pos+ti.nbLimbs], f.fParams.BitsPerLimb(), hintInputs[i]); err != nil {
					return fmt.Errorf("recompose: %w", err)
				}
			} else {
				hintInputs[i].Set(expandedHintInputs[ti.pos])
			}
		}
		for i := range hintOutputs {
			hintOutputs[i] = new(big.Int)
		}
		if err := hf(f.fParams.Modulus(), hintInputs, hintOutputs); err != nil {
			return fmt.Errorf("call hint: %w", err)
		}
		for i := range hintOutputs {
			if err := decompose(hintOutputs[i], f.fParams.BitsPerLimb(), expandedHintOutputs[i*int(f.fParams.NbLimbs()):(i+1)*int(f.fParams.NbLimbs())]); err != nil {
				return fmt.Errorf("decompose: %w", err)
			}
		}
		return nil
	}
	hintRet, err := f.api.Compiler().NewHint(wrappedHint, nbNativeOutputs, expandedInputs...)
	if err != nil {
		return nil, fmt.Errorf("NewHint: %w", err)
	}
	ret := make([]frontend.Variable, nbOutputs)
	for i := 0; i < nbOutputs; i++ {
		el := NewElement[T](nil)
		el.Limbs = hintRet[i*int(f.fParams.NbLimbs()) : (i+1)*int(f.fParams.NbLimbs())]
		ret[i] = el
	}
	return ret, nil
}

func (f *Field[T]) ConstantValue(v frontend.Variable) (*big.Int, bool) {
	var limbs []frontend.Variable // emulated limbs
	switch vv := v.(type) {
	case Element[T]:
		limbs = vv.Limbs
	case *Element[T]:
		limbs = vv.Limbs
	case []frontend.Variable:
		limbs = vv
	default:
		return f.api.Compiler().ConstantValue(vv)
	}
	var ok bool

	constLimbs := make([]*big.Int, len(limbs))
	for i, l := range limbs {
		// for each limb we get it's constant value if we can, or fail.
		if constLimbs[i], ok = f.ConstantValue(l); !ok {
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

func (f *Field[T]) Field() *big.Int {
	return f.fParams.Modulus()
}

func (f *Field[T]) FieldBitLen() int {
	return f.fParams.Modulus().BitLen()
}

func (f *Field[T]) IsBoolean(v frontend.Variable) bool {
	switch vv := v.(type) {
	case Element[T]:
		return f.api.Compiler().IsBoolean(vv.Limbs[0])
	case *Element[T]:
		return f.api.Compiler().IsBoolean(vv.Limbs[0])
	default:
		return f.api.Compiler().IsBoolean(vv)
	}
}

func (f *Field[T]) MarkBoolean(v frontend.Variable) {
	switch vv := v.(type) {
	case Element[T]:
		f.api.Compiler().MarkBoolean(vv.Limbs[0])
	case *Element[T]:
		f.api.Compiler().MarkBoolean(vv.Limbs[0])
	default:
		f.api.Compiler().MarkBoolean(vv)
	}
}

// Modulus returns the modulus of the emulated ring as a constant. The returned
// element is not safe to use as an operation receiver.
func (f *Field[T]) Modulus() Element[T] {
	f.nConstOnce.Do(func() {
		f.nConst = NewElement[T](f.fParams.Modulus())
	})
	return f.nConst
}

// Zero returns zero as a constant. The returned element is not safe to use as
// an operation receiver.
func (f *Field[T]) Zero() Element[T] {
	f.zeroConstOnce.Do(func() {
		f.zeroConst = NewElement[T](nil)
	})
	return f.zeroConst
}

// One returns one as a constant. The returned element is not safe to use as an
// operation receiver.
func (f *Field[T]) One() Element[T] {
	f.oneConstOnce.Do(func() {
		f.oneConst = NewElement[T](1)
	})
	return f.oneConst
}

// PackLimbs returns a constant element from the given limbs. The returned
// element is not safe to use as an operation receiver. The method constrains
// the limb widths.
func (f *Field[T]) PackLimbs(limbs []frontend.Variable) Element[T] {
	limbNbBits := int(f.fParams.BitsPerLimb())
	for i := range limbs {
		// bits.ToBinary restricts the least significant NbDigits to be equal to
		// the limb value. This is sufficient to restrict for the bitlength and
		// we can discard the bits themselves.
		bits.ToBinary(f.api, limbs[i], bits.WithNbDigits(limbNbBits))
	}

	return Element[T]{
		Limbs:    limbs,
		overflow: 0,
	}
}

// builderWrapper returns a wrapper for the builder which is compatible to use
// as a frontend compile option. When using this wrapper, it is possible to
// extend existing circuits into any emulated field defined by
func builderWrapper[T FieldParams]() frontend.BuilderWrapper {
	return func(b frontend.Builder) frontend.Builder {
		b, err := NewBuilder[T](b)
		if err != nil {
			panic(err)
		}
		return b
	}
}

func (f *Field[T]) Compile() (constraint.ConstraintSystem, error) {
	return f.builder.Compile()
}

func (f *Field[T]) VariableCount(t reflect.Type) int {
	return int(f.fParams.NbLimbs())
}

func (f *Field[T]) addVariable(sf *schema.Field, recurseFn func(*schema.Field) frontend.Variable) frontend.Variable {
	limbs := make([]frontend.Variable, f.fParams.NbLimbs())
	var subfs []schema.Field
	for i := range limbs {
		subf := schema.Field{
			Name:       strconv.Itoa(i),
			Visibility: sf.Visibility,
			FullName:   fmt.Sprintf("%s_%d", sf.FullName, i),
			Type:       schema.Leaf,
			ArraySize:  1,
		}
		subfs = append(subfs, subf)
		limbs[i] = recurseFn(&subf)
	}
	sf.ArraySize = len(subfs)
	sf.Type = schema.Array
	sf.SubFields = subfs
	el := f.PackLimbs(limbs)
	return el
}

func (f *Field[T]) PublicVariable(sf *schema.Field) frontend.Variable {
	return f.addVariable(sf, f.builder.PublicVariable)
}

func (f *Field[T]) SecretVariable(sf *schema.Field) frontend.Variable {
	return f.addVariable(sf, f.builder.SecretVariable)

}

func (f *Field[T]) Reduce(i frontend.Variable) frontend.Variable {
	el := f.varToElement(i)
	res := f.reduce(el)
	return res
}

func (f *Field[T]) Commit(v ...frontend.Variable) (frontend.Variable, error) {
	//TODO implement me
	panic("not implemented")
}
