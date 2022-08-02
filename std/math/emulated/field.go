package emulated

import (
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"sync"

	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/rs/zerolog"
)

// field defines the parameters of the emulated ring of integers modulo n. If
// n is prime, then the ring is also a finite field where inverse and division
// are allowed.
type field[T FieldParams] struct {
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
func NewField[T FieldParams](native frontend.API) (frontend.API, error) {
	f := &field[T]{
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

func (f *field[T]) varToElement(in frontend.Variable) Element[T] {
	switch vv := in.(type) {
	case Element[T]:
		return vv
	case *Element[T]:
		return *vv
	default:
		return NewElement[T](in)
	}
}

func (f *field[T]) varsToElements(in ...frontend.Variable) []Element[T] {
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

func (f *field[T]) Add(i1 frontend.Variable, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	els := f.varsToElements(i1, i2, in)
	res := f.reduceAndOp(f.add, f.addPreCond, els[0], els[1])
	for i := 2; i < len(els); i++ {
		res = f.reduceAndOp(f.add, f.addPreCond, res, els[i]) // TODO @gbotrel re-use res memory, don't reallocate limbs !
	}
	return res
}

// Negate sets e to -a and returns e. The returned element may be larger than
// the modulus.
func (f *field[T]) Neg(i1 frontend.Variable) frontend.Variable {
	el := f.varToElement(i1)

	return f.Sub(f.Zero(), el)
}

func (f *field[T]) Sub(i1 frontend.Variable, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	els := f.varsToElements(i1, i2, in)
	sub := NewElement[T](nil)
	sub.Set(els[1])
	for i := 2; i < len(els); i++ {
		sub = f.reduceAndOp(f.add, f.addPreCond, sub, els[i])
	}
	res := f.reduceAndOp(f.sub, f.subPreCond, els[0], sub)
	return res
}

func (f *field[T]) Mul(i1 frontend.Variable, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	els := f.varsToElements(i1, i2, in)
	res := f.reduceAndOp(f.mul, f.mulPreCond, els[0], els[1])
	for i := 2; i < len(els); i++ {
		res = f.reduceAndOp(f.mul, f.mulPreCond, res, els[i])
	}
	return res
}

func (f *field[T]) DivUnchecked(i1 frontend.Variable, i2 frontend.Variable) frontend.Variable {
	return f.Div(i1, i2)
}

// Div sets e to a/b and returns e. If modulus is not a prime, it panics. The
// result is less than the modulus. This method is more efficient than inverting
// b and multiplying it by a.
func (f *field[T]) Div(i1 frontend.Variable, i2 frontend.Variable) frontend.Variable {
	if !f.fParams.IsPrime() {
		// TODO shouldn't we still try to do a classic int div in a hint, constraint the result, and let it fail?
		// that would enable things like uint32 div ?
		panic("modulus not a prime")
	}

	els := f.varsToElements(i1, i2)
	a := els[0]
	b := els[1]
	div, err := computeDivisionHint(f.api, f, a.Limbs, b.Limbs)
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
func (f *field[T]) Inverse(i1 frontend.Variable) frontend.Variable {
	a := f.varToElement(i1)
	if !f.fParams.IsPrime() {
		panic("modulus not a prime")
	}
	k, err := computeInverseHint(f.api, f, a.Limbs)
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

func (f *field[T]) ToBinary(i1 frontend.Variable, n ...int) []frontend.Variable {
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

func (f *field[T]) FromBinary(b ...frontend.Variable) frontend.Variable {
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

func (f *field[T]) Xor(a frontend.Variable, b frontend.Variable) frontend.Variable {
	els := f.varsToElements(a, b)
	f.AssertIsBoolean(els[0])
	f.AssertIsBoolean(els[1])
	rv := f.api.Xor(els[0].Limbs[0], els[1].Limbs[0])
	r := f.PackLimbs([]frontend.Variable{rv})

	f.EnforceWidth(r)
	return r
}

func (f *field[T]) Or(a frontend.Variable, b frontend.Variable) frontend.Variable {
	els := f.varsToElements(a, b)
	f.AssertIsBoolean(els[0])
	f.AssertIsBoolean(els[1])
	rv := f.api.Or(els[0].Limbs[0], els[1].Limbs[0])
	r := f.PackLimbs([]frontend.Variable{rv})

	f.EnforceWidth(r)
	return r
}

func (f *field[T]) And(a frontend.Variable, b frontend.Variable) frontend.Variable {
	els := f.varsToElements(a, b)
	f.AssertIsBoolean(els[0])
	f.AssertIsBoolean(els[1])
	rv := f.api.And(els[0].Limbs[0], els[1].Limbs[0])
	r := f.PackLimbs([]frontend.Variable{rv})

	f.EnforceWidth(r)
	return r
}

func (f *field[T]) Select(b frontend.Variable, i1 frontend.Variable, i2 frontend.Variable) frontend.Variable {
	els := f.varsToElements(i1, i2)
	switch vv := b.(type) {
	case Element[T]:
		f.AssertIsBoolean(vv)
		b = vv.Limbs[0]
	case *Element[T]:
		f.AssertIsBoolean(vv)
		b = vv.Limbs[0]
	}
	if els[0].overflow == els[1].overflow && len(els[0].Limbs) == len(els[1].Limbs) {
		return f._select(b, els[0], els[1])
	}
	s0 := els[0]
	s1 := els[1]
	if s0.overflow != 0 || len(s0.Limbs) != int(f.fParams.NbLimbs()) {
		s0 = f.reduce(s0)
	}
	if s1.overflow != 0 || len(s1.Limbs) != int(f.fParams.NbLimbs()) {
		s1 = f.reduce(s1)
	}
	return f._select(b, s0, s1)
}

func (f *field[T]) Lookup2(b0 frontend.Variable, b1 frontend.Variable, i0 frontend.Variable, i1 frontend.Variable, i2 frontend.Variable, i3 frontend.Variable) frontend.Variable {
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
	if els[0].overflow == els[1].overflow && els[0].overflow == els[2].overflow && els[0].overflow == els[3].overflow && len(els[0].Limbs) == len(els[1].Limbs) && len(els[0].Limbs) == len(els[2].Limbs) && len(els[0].Limbs) == len(els[3].Limbs) {
		return f.lookup2(b0, b1, els[0], els[1], els[2], els[3])
	}
	s0 := els[0]
	s1 := els[1]
	s2 := els[2]
	s3 := els[3]
	if s0.overflow != 0 || len(s0.Limbs) != int(f.fParams.NbLimbs()) {
		s0 = f.reduce(s0)
	}
	if s1.overflow != 0 || len(s1.Limbs) != int(f.fParams.NbLimbs()) {
		s1 = f.reduce(s1)
	}
	if s2.overflow != 0 || len(s2.Limbs) != int(f.fParams.NbLimbs()) {
		s2 = f.reduce(s2)
	}
	if s3.overflow != 0 || len(s3.Limbs) != int(f.fParams.NbLimbs()) {
		s3 = f.reduce(s3)
	}
	return f.lookup2(b0, b1, s0, s1, s2, s3)
}

func (f *field[T]) IsZero(i1 frontend.Variable) frontend.Variable {
	el := f.varToElement(i1)
	reduced := f.reduce(el)
	res := f.api.IsZero(reduced.Limbs[0])
	for i := 1; i < len(reduced.Limbs); i++ {
		f.api.Mul(res, f.api.IsZero(reduced.Limbs[i]))
	}
	r := f.PackLimbs([]frontend.Variable{res})

	f.EnforceWidth(r)
	return r
}

func (f *field[T]) Cmp(i1 frontend.Variable, i2 frontend.Variable) frontend.Variable {
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

func (f *field[T]) AssertIsEqual(i1 frontend.Variable, i2 frontend.Variable) {
	els := f.varsToElements(i1, i2)
	tmp := NewElement[T](els[0])
	// tmp.Set(els[0]) // TODO @gbotrel do we need to duplicate here?
	f.reduceAndOp(func(a, b Element[T], nextOverflow uint) Element[T] {
		f.assertIsEqual(a, b)
		return NewElement[T](nil)
	},
		func(e1, e2 Element[T]) (uint, error) {
			nextOverflow, err := f.subPreCond(e2, e1) // TODO @gbotrel previously "tmp.sub..."
			var target errOverflow
			if err != nil && errors.As(err, &target) {
				target.reduceRight = !target.reduceRight
				return nextOverflow, target
			}
			return nextOverflow, err
		}, tmp, els[1])
}

func (f *field[T]) AssertIsDifferent(i1 frontend.Variable, i2 frontend.Variable) {
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

func (f *field[T]) AssertIsBoolean(i1 frontend.Variable) {
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

func (f *field[T]) AssertIsLessOrEqual(v frontend.Variable, bound frontend.Variable) {
	els := f.varsToElements(v, bound)
	l := f.reduce(els[0])
	r := f.reduce(els[1])
	f.AssertIsLessEqualThan(l, r)
}

func (f *field[T]) Println(a ...frontend.Variable) {
	els := f.varsToElements(a)
	for i := range els {
		f.api.Println(els[i].Limbs...)
	}
}

func (f *field[T]) Compiler() frontend.Compiler {
	return f
}

type typedInput struct {
	pos       int
	nbLimbs   int
	isElement bool
}

func (f *field[T]) NewHint(hf hint.Function, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {
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

func (f *field[T]) ConstantValue(v frontend.Variable) (*big.Int, bool) {
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

func (f *field[T]) Field() *big.Int {
	return f.fParams.Modulus()
}

func (f *field[T]) FieldBitLen() int {
	return f.fParams.Modulus().BitLen()
}

func (f *field[T]) IsBoolean(v frontend.Variable) bool {
	switch vv := v.(type) {
	case Element[T]:
		return f.api.Compiler().IsBoolean(vv.Limbs[0])
	case *Element[T]:
		return f.api.Compiler().IsBoolean(vv.Limbs[0])
	default:
		return f.api.Compiler().IsBoolean(vv)
	}
}

func (f *field[T]) MarkBoolean(v frontend.Variable) {
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
func (f *field[T]) Modulus() Element[T] {
	f.nConstOnce.Do(func() {
		f.nConst = NewElement[T](f.fParams.Modulus())
	})
	return f.nConst
}

// Zero returns zero as a constant. The returned element is not safe to use as
// an operation receiver.
func (f *field[T]) Zero() Element[T] {
	f.zeroConstOnce.Do(func() {
		f.zeroConst = NewElement[T](nil)
	})
	return f.zeroConst
}

// One returns one as a constant. The returned element is not safe to use as an
// operation receiver.
func (f *field[T]) One() Element[T] {
	f.oneConstOnce.Do(func() {
		f.oneConst = NewElement[T](1)
	})
	return f.oneConst
}

// PackLimbs returns a constant element from the given limbs. The
// returned element is not safe to use as an operation receiver.
func (f *field[T]) PackLimbs(limbs []frontend.Variable) Element[T] {
	// TODO: check that every limb does not overflow the expected width

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
		fw, err := NewField[T](b)
		if err != nil {
			panic(err)
		}
		fw.(*field[T]).builder = b
		return fw.(*field[T])
	}
}

func (f *field[T]) Compile() (frontend.CompiledConstraintSystem, error) {
	return f.builder.Compile()
}

func (f *field[T]) SetSchema(s *schema.Schema) {
	f.builder.SetSchema(s)
}

func (f *field[T]) VariableCount(t reflect.Type) int {
	return int(f.fParams.NbLimbs())
}

func (f *field[T]) addVariable(sf *schema.Field, recurseFn func(*schema.Field) frontend.Variable) frontend.Variable {
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

func (f *field[T]) AddPublicVariable(sf *schema.Field) frontend.Variable {
	return f.addVariable(sf, f.builder.AddPublicVariable)
}

func (f *field[T]) AddSecretVariable(sf *schema.Field) frontend.Variable {
	return f.addVariable(sf, f.builder.AddSecretVariable)

}
