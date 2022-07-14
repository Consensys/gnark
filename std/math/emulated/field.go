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
	"github.com/consensys/gnark/frontend/compiled"
	"github.com/consensys/gnark/frontend/schema"
)

// field defines the parameters of the emulated ring of integers modulo n. If
// n is prime, then the ring is also a finite field where inverse and division
// are allowed.
type field struct {
	// api is the native API
	api     frontend.API
	builder frontend.Builder

	// r is the modulus
	r *big.Int
	// hasInverses indicates if order is prime
	hasInverses bool
	// nbLimbs is the number of limbs which fit reduced element
	nbLimbs uint
	// limbSize is number of bits per limb. Top limb may contain less than
	// limbSize bits.
	limbSize uint
	// maxOf is the maximum overflow before the element must be reduced.
	maxOf     uint
	maxOfOnce sync.Once

	// constants for often used elements n, 0 and 1. Allocated only once
	nConstOnce    sync.Once
	nConst        *Element `gnark:"-"`
	zeroConstOnce sync.Once
	zeroConst     *Element `gnark:"-"`
	oneConstOnce  sync.Once
	oneConst      *Element `gnark:"-"`
}

// NewField wraps the existing native API such that all methods are performed
// using field emulation.
//
// It initializes the parameters for emulating operations modulo n where
// every limb of the element contains up to nbBits bits. Returns error if sanity
// checks fail.
//
// This method checks the primality of n to detect if parameters define a finite
// field. As such, invocation of this method is expensive and should be done
// once.
func NewField(native frontend.API, r *big.Int, nbBits int) (frontend.API, error) {

	if r.Cmp(big.NewInt(1)) < 1 {
		return nil, fmt.Errorf("n must be at least 2")
	}
	if nbBits < 3 {
		// even three is way too small, but it should probably work.
		return nil, fmt.Errorf("nbBits must be at least 3")
	}
	nbLimbs := (r.BitLen() + nbBits - 1) / nbBits
	fp := &field{
		r:           new(big.Int).Set(r),
		nbLimbs:     uint(nbLimbs),
		limbSize:    uint(nbBits),
		hasInverses: r.ProbablyPrime(20),
		api:         native,
	}
	return fp, nil
}

func (f *field) SetNativeAPI(api frontend.API) {
	f.api = api
}

func (f *field) varToElement(in frontend.Variable) *Element {
	var e *Element
	switch vv := in.(type) {
	case Element:
		e = &vv
	case *Element:
		e = vv
	case *big.Int:
		el := f.ConstantFromBigOrPanic(vv)
		e = &el
	case big.Int:
		el := f.ConstantFromBigOrPanic(&vv)
		e = &el
	case int:
		el := f.ConstantFromBigOrPanic(big.NewInt(int64(vv)))
		e = &el
	case string:
		elb := new(big.Int)
		elb.SetString(vv, 10)
		el := f.ConstantFromBigOrPanic(elb)
		e = &el
	case interface{ ToBigIntRegular(*big.Int) *big.Int }:
		b := new(big.Int)
		vv.ToBigIntRegular(b)
		el := f.ConstantFromBigOrPanic(b)
		e = &el
	case compiled.LinearExpression:
		el := f.PackLimbs([]frontend.Variable{in})
		e = &el
	case compiled.Term:
		el := f.PackLimbs([]frontend.Variable{in})
		e = &el
	default:
		panic(fmt.Sprintf("can not cast %T to *Element", in))
	}
	if !f.isEqual(e.params) {
		panic("incompatible Element parameters")
	}
	return e
}

func (f *field) varsToElements(in ...frontend.Variable) []*Element {
	var els []*Element
	for i := range in {
		switch v := in[i].(type) {
		case []frontend.Variable:
			subels := f.varsToElements(v...)
			els = append(els, subels...)
		case frontend.Variable:
			els = append(els, f.varToElement(v))
		}
	}
	return els
}

func (f *field) Add(i1 frontend.Variable, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	els := f.varsToElements(i1, i2, in)
	res := f.Element(f.api)
	res.reduceAndOp(res.add, res.addPreCond, els[0], els[1])
	for i := 2; i < len(els); i++ {
		res.reduceAndOp(res.add, res.addPreCond, &res, els[i])
	}
	return &res
}

func (f *field) Neg(i1 frontend.Variable) frontend.Variable {
	el := f.varToElement(i1)
	res := f.Element(f.api)
	res.Negate(*el)
	return &res
}

func (f *field) Sub(i1 frontend.Variable, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	els := f.varsToElements(i1, i2, in)
	sub := f.Element(f.api)
	sub.Set(*els[1])
	for i := 2; i < len(els); i++ {
		sub.reduceAndOp(sub.add, sub.addPreCond, &sub, els[i])
	}
	res := f.Element(f.api)
	res.reduceAndOp(res.sub, res.subPreCond, els[0], &sub)
	return &res
}

func (f *field) Mul(i1 frontend.Variable, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	els := f.varsToElements(i1, i2, in)
	res := f.Element(f.api)
	res.reduceAndOp(res.mul, res.mulPreCond, els[0], els[1])
	for i := 2; i < len(els); i++ {
		res.reduceAndOp(res.mul, res.mulPreCond, &res, els[i])
	}
	return &res
}

func (f *field) DivUnchecked(i1 frontend.Variable, i2 frontend.Variable) frontend.Variable {
	return f.Div(i1, i2)
}

func (f *field) Div(i1 frontend.Variable, i2 frontend.Variable) frontend.Variable {
	els := f.varsToElements(i1, i2)
	res := f.Element(f.api)
	res.Div(*els[0], *els[1])
	return &res
}

func (f *field) Inverse(i1 frontend.Variable) frontend.Variable {
	el := f.varToElement(i1)
	res := f.Element(f.api)
	res.Inverse(*el)
	return &res
}

func (f *field) ToBinary(i1 frontend.Variable, n ...int) []frontend.Variable {
	el := f.varToElement(i1)
	res := f.Element(f.api)
	res.Reduce(*el)
	out := res.ToBits()
	switch len(n) {
	case 0:
	case 1:
		out = out[:n[0]]
	default:
		panic("only single vararg permitted to ToBinary")
	}
	return out
}

func (f *field) FromBinary(b ...frontend.Variable) frontend.Variable {
	els := f.varsToElements(b)
	bits := make([]frontend.Variable, len(els))
	for i := range els {
		f.AssertIsBoolean(els[i])
		bits[i] = els[i].Limbs[0]
	}
	res := f.Element(f.api)
	res.FromBits(bits)
	return &res
}

func (f *field) Xor(a frontend.Variable, b frontend.Variable) frontend.Variable {
	els := f.varsToElements(a, b)
	f.AssertIsBoolean(els[0])
	f.AssertIsBoolean(els[1])
	rv := f.api.Xor(els[0].Limbs[0], els[1].Limbs[0])
	r := f.PackLimbs([]frontend.Variable{rv})
	r.api = f.api
	r.EnforceWidth()
	return r
}

func (f *field) Or(a frontend.Variable, b frontend.Variable) frontend.Variable {
	els := f.varsToElements(a, b)
	f.AssertIsBoolean(els[0])
	f.AssertIsBoolean(els[1])
	rv := f.api.Or(els[0].Limbs[0], els[1].Limbs[0])
	r := f.PackLimbs([]frontend.Variable{rv})
	r.api = f.api
	r.EnforceWidth()
	return r
}

func (f *field) And(a frontend.Variable, b frontend.Variable) frontend.Variable {
	els := f.varsToElements(a, b)
	f.AssertIsBoolean(els[0])
	f.AssertIsBoolean(els[1])
	rv := f.api.And(els[0].Limbs[0], els[1].Limbs[0])
	r := f.PackLimbs([]frontend.Variable{rv})
	r.api = f.api
	r.EnforceWidth()
	return r
}

func (f *field) Select(b frontend.Variable, i1 frontend.Variable, i2 frontend.Variable) frontend.Variable {
	els := f.varsToElements(i1, i2)
	res := f.Element(f.api)
	switch vv := b.(type) {
	case Element:
		f.AssertIsBoolean(vv)
		b = vv.Limbs[0]
	case *Element:
		f.AssertIsBoolean(vv)
		b = vv.Limbs[0]
	}
	if els[0].overflow == els[1].overflow && len(els[0].Limbs) == len(els[1].Limbs) {
		res.Select(b, *els[0], *els[1])
		return &res
	}
	s0 := els[0]
	s1 := els[1]
	if s0.overflow != 0 || len(s0.Limbs) != int(f.nbLimbs) {
		v := f.Element(f.api)
		v.Reduce(*s0)
		s0 = &v
	}
	if s1.overflow != 0 || len(s1.Limbs) != int(f.nbLimbs) {
		v := f.Element(f.api)
		v.Reduce(*s1)
		s1 = &v
	}
	res.Select(b, *s0, *s1)
	return &res
}

func (f *field) Lookup2(b0 frontend.Variable, b1 frontend.Variable, i0 frontend.Variable, i1 frontend.Variable, i2 frontend.Variable, i3 frontend.Variable) frontend.Variable {
	els := f.varsToElements(i0, i1, i2, i3)
	res := f.Element(f.api)
	switch vv := b0.(type) {
	case Element:
		f.AssertIsBoolean(vv)
		b0 = vv.Limbs[0]
	case *Element:
		f.AssertIsBoolean(vv)
		b0 = vv.Limbs[0]
	}
	switch vv := b1.(type) {
	case Element:
		f.AssertIsBoolean(vv)
		b1 = vv.Limbs[0]
	case *Element:
		f.AssertIsBoolean(vv)
		b1 = vv.Limbs[0]
	}
	if els[0].overflow == els[1].overflow && els[0].overflow == els[2].overflow && els[0].overflow == els[3].overflow && len(els[0].Limbs) == len(els[1].Limbs) && len(els[0].Limbs) == len(els[2].Limbs) && len(els[0].Limbs) == len(els[3].Limbs) {
		res.Lookup2(b0, b1, *els[0], *els[1], *els[2], *els[3])
		return &res
	}
	s0 := els[0]
	s1 := els[1]
	s2 := els[2]
	s3 := els[3]
	if s0.overflow != 0 || len(s0.Limbs) != int(f.nbLimbs) {
		v := f.Element(f.api)
		v.Reduce(*s0)
		s0 = &v
	}
	if s1.overflow != 0 || len(s1.Limbs) != int(f.nbLimbs) {
		v := f.Element(f.api)
		v.Reduce(*s1)
		s1 = &v
	}
	if s2.overflow != 0 || len(s2.Limbs) != int(f.nbLimbs) {
		v := f.Element(f.api)
		v.Reduce(*s2)
		s2 = &v
	}
	if s3.overflow != 0 || len(s3.Limbs) != int(f.nbLimbs) {
		v := f.Element(f.api)
		v.Reduce(*s3)
		s3 = &v
	}
	res.Lookup2(b0, b1, *s0, *s1, *s2, *s3)
	return &res
}

func (f *field) IsZero(i1 frontend.Variable) frontend.Variable {
	el := f.varToElement(i1)
	reduced := f.Element(f.api)
	reduced.Reduce(*el)
	res := f.api.IsZero(reduced.Limbs[0])
	for i := 1; i < len(reduced.Limbs); i++ {
		f.api.Mul(res, f.api.IsZero(reduced.Limbs[i]))
	}
	r := f.PackLimbs([]frontend.Variable{res})
	r.api = f.api
	r.EnforceWidth()
	return r
}

func (f *field) Cmp(i1 frontend.Variable, i2 frontend.Variable) frontend.Variable {
	els := f.varsToElements(i1, i2)
	rls := []Element{f.Element(f.api), f.Element(f.api)}
	rls[0].Reduce(*els[0])
	rls[1].Reduce(*els[1])
	var res frontend.Variable = 0
	for i := int(f.nbLimbs - 1); i >= 0; i-- {
		lmbCmp := f.api.Cmp(rls[0].Limbs[i], rls[1].Limbs[i])
		res = f.api.Select(f.api.IsZero(res), lmbCmp, res)
	}
	return res
}

func (f *field) AssertIsEqual(i1 frontend.Variable, i2 frontend.Variable) {
	els := f.varsToElements(i1, i2)
	tmp := f.Element(f.api)
	tmp.Set(*els[0])
	tmp.reduceAndOp(func(a, b Element, nextOverflow uint) { a.AssertIsEqual(b) }, func(e1, e2 Element) (uint, error) {
		nextOverflow, err := tmp.subPreCond(e2, e1)
		var target errOverflow
		if err != nil && errors.As(err, &target) {
			target.reduceRight = !target.reduceRight
			return nextOverflow, target
		}
		return nextOverflow, err
	}, &tmp, els[1])
}

func (f *field) AssertIsDifferent(i1 frontend.Variable, i2 frontend.Variable) {
	els := f.varsToElements(i1, i2)
	rls := []Element{f.Element(f.api), f.Element(f.api)}
	rls[0].Reduce(*els[0])
	rls[1].Reduce(*els[1])
	var res frontend.Variable = 0
	for i := 0; i < int(f.nbLimbs); i++ {
		cmp := f.api.Cmp(rls[0].Limbs[i], rls[1].Limbs[i])
		cmpsq := f.api.Mul(cmp, cmp)
		res = f.api.Add(res, cmpsq)
	}
	f.api.AssertIsDifferent(res, 0)
}

func (f *field) AssertIsBoolean(i1 frontend.Variable) {
	switch vv := i1.(type) {
	case Element:
		v := f.Element(f.api)
		v.Reduce(vv)
		f.api.AssertIsBoolean(v.Limbs[0])
		for i := 1; i < len(v.Limbs); i++ {
			f.api.AssertIsEqual(v.Limbs[i], 0)
		}
	case *Element:
		v := f.Element(f.api)
		v.Reduce(*vv)
		f.api.AssertIsBoolean(v.Limbs[0])
		for i := 1; i < len(v.Limbs); i++ {
			f.api.AssertIsEqual(v.Limbs[i], 0)
		}
	default:
		f.api.AssertIsBoolean(vv)
	}
}

func (f *field) AssertIsLessOrEqual(v frontend.Variable, bound frontend.Variable) {
	els := f.varsToElements(v, bound)
	l := f.Element(f.api)
	l.Reduce(*els[0])
	r := f.Element(f.api)
	r.Reduce(*els[1])
	l.AssertIsLessEqualThan(r)
}

func (f *field) Println(a ...frontend.Variable) {
	els := f.varsToElements(a)
	for i := range els {
		f.api.Println(els[i].Limbs...)
	}
}

func (f *field) Compiler() frontend.Compiler {
	return f
}

func (f *field) NewHint(hf hint.Function, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {
	// this is a trick to allow calling hint functions using non-native
	// elements. We use the fact that the hints take as inputs *big.Int values.
	// Instead of supplying hf to the solver for calling, we wrap it with
	// another function (implementing hint.Function), which takes as inputs the
	// "expanded" version of inputs (where instead of Element values we provide
	// as inputs the limbs of every Element) and returns nbLimbs*nbOutputs
	// number of outputs (i.e. the limbs of non-native Element values). The
	// wrapper then recomposes and decomposes the *big.Int values at runtime and
	// provides them as input to the initially provided hint function.
	var expandedInputs []frontend.Variable
	type typedInput struct {
		pos       int
		nbLimbs   int
		isElement bool
	}
	typedInputs := make([]typedInput, len(inputs))
	for i := range inputs {
		switch vv := inputs[i].(type) {
		case Element:
			expandedInputs = append(expandedInputs, vv.Limbs...)
			typedInputs[i] = typedInput{
				pos:       len(expandedInputs) - len(vv.Limbs),
				nbLimbs:   len(vv.Limbs),
				isElement: true,
			}
		case *Element:
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
	nbNativeOutputs := nbOutputs * int(f.nbLimbs)
	wrappedHint := func(_ *big.Int, expandedHintInputs []*big.Int, expandedHintOutputs []*big.Int) error {
		hintInputs := make([]*big.Int, len(inputs))
		hintOutputs := make([]*big.Int, nbOutputs)
		for i, ti := range typedInputs {
			hintInputs[i] = new(big.Int)
			if ti.isElement {
				if err := recompose(expandedHintInputs[ti.pos:ti.pos+ti.nbLimbs], f.limbSize, hintInputs[i]); err != nil {
					return fmt.Errorf("recompose: %w", err)
				}
			} else {
				hintInputs[i].Set(expandedHintInputs[ti.pos])
			}
		}
		for i := range hintOutputs {
			hintOutputs[i] = new(big.Int)
		}
		if err := hf(f.r, hintInputs, hintOutputs); err != nil {
			return fmt.Errorf("call hint: %w", err)
		}
		for i := range hintOutputs {
			if err := decompose(hintOutputs[i], f.limbSize, expandedHintOutputs[i*int(f.nbLimbs):(i+1)*int(f.nbLimbs)]); err != nil {
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
		el := f.Element(f.api)
		el.Limbs = hintRet[i*int(f.nbLimbs) : (i+1)*int(f.nbLimbs)]
		ret[i] = &el
	}
	return ret, nil
}

func (f *field) Tag(name string) frontend.Tag {
	return f.api.Compiler().Tag(name)
}

func (f *field) AddCounter(from frontend.Tag, to frontend.Tag) {
	f.api.Compiler().AddCounter(from, to)
}

func (f *field) ConstantValue(v frontend.Variable) (*big.Int, bool) {
	var constLimbs []*big.Int
	var nbBits uint
	var ok bool
	switch vv := v.(type) {
	// TODO @gbotrel since Element doesn't kow which fields it belongs to, this is a bit broken.
	// replaced nbBits = vv.nbBits by nbBits = f.nbBits
	case Element:
		nbBits = f.limbSize
		constLimbs = make([]*big.Int, len(vv.Limbs))
		for i := range vv.Limbs {
			if constLimbs[i], ok = f.api.Compiler().ConstantValue(vv.Limbs[i]); !ok {
				return nil, false
			}
		}
	case *Element:
		nbBits = f.limbSize
		constLimbs = make([]*big.Int, len(vv.Limbs))
		for i := range vv.Limbs {
			if constLimbs[i], ok = f.api.Compiler().ConstantValue(vv.Limbs[i]); !ok {
				return nil, false
			}
		}
	default:
		return f.api.Compiler().ConstantValue(vv)
	}
	res := new(big.Int)
	if err := recompose(constLimbs, nbBits, res); err != nil {
		return nil, false
	}
	return res, true
}

func (f *field) Field() *big.Int {
	return f.r
}

func (f *field) FieldBitLen() int {
	return f.r.BitLen()
}

func (f *field) IsBoolean(v frontend.Variable) bool {
	switch vv := v.(type) {
	case Element:
		return f.api.Compiler().IsBoolean(vv.Limbs[0])
	case *Element:
		return f.api.Compiler().IsBoolean(vv.Limbs[0])
	default:
		return f.api.Compiler().IsBoolean(vv)
	}
}

func (f *field) MarkBoolean(v frontend.Variable) {
	switch vv := v.(type) {
	case Element:
		f.api.Compiler().MarkBoolean(vv.Limbs[0])
	case *Element:
		f.api.Compiler().MarkBoolean(vv.Limbs[0])
	default:
		f.api.Compiler().MarkBoolean(vv)
	}
}

// builderWrapper returns a wrapper for the builder which is compatible to use
// as a frontend compile option. When using this wrapper, it is possible to
// extend existing circuits into any emulated field defined by
func builderWrapper(f *field) frontend.BuilderWrapper {
	return func(b frontend.Builder) frontend.Builder {
		fw, err := NewField(b, f.r, int(f.limbSize))
		if err != nil {
			panic(err)
		}
		fw.(*field).builder = b
		return fw.(*field)
	}
}

func (f *field) Compile() (frontend.CompiledConstraintSystem, error) {
	return f.builder.Compile()
}

func (f *field) SetSchema(s *schema.Schema) {
	f.builder.SetSchema(s)
}

func (f *field) VariableCount(t reflect.Type) int {
	return int(f.nbLimbs)
}

func (f *field) addVariable(sf *schema.Field, recurseFn func(*schema.Field) frontend.Variable) frontend.Variable {
	limbs := make([]frontend.Variable, f.nbLimbs)
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

func (f *field) AddPublicVariable(sf *schema.Field) frontend.Variable {
	return f.addVariable(sf, f.builder.AddPublicVariable)
}

func (f *field) AddSecretVariable(sf *schema.Field) frontend.Variable {
	return f.addVariable(sf, f.builder.AddSecretVariable)

}
