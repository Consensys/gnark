package emulated

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
)

type FieldAPI[T FieldParams] struct {
	f *Field[T]
	b frontend.Builder
}

func NewAPI[T FieldParams](native frontend.API) (*FieldAPI[T], error) {
	f, err := NewField[T](native)
	if err != nil {
		return nil, fmt.Errorf("new field: %w", err)
	}
	return &FieldAPI[T]{f: f}, nil
}

func (w *FieldAPI[T]) varToElement(in frontend.Variable) *Element[T] {
	switch vv := in.(type) {
	case Element[T]:
		return &vv
	case *Element[T]:
		return vv
	default:
		return newElementPtr[T](in)
	}
}

func (w *FieldAPI[T]) varsToElements(in ...frontend.Variable) []*Element[T] {
	var els []*Element[T]
	for i := range in {
		switch v := in[i].(type) {
		case []frontend.Variable:
			subels := w.varsToElements(v...)
			els = append(els, subels...)
		case frontend.Variable:
			els = append(els, w.varToElement(v))
		default:
			// handle nil value
			panic("can't convert <nil> to Element[T]")
		}
	}
	return els
}

func (w *FieldAPI[T]) Add(i1 frontend.Variable, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	els := w.varsToElements(i1, i2, in)
	res := w.f.reduceAndOp(w.f.add, w.f.addPreCond, els[0], els[1])
	for i := 2; i < len(els); i++ {
		res = w.f.reduceAndOp(w.f.add, w.f.addPreCond, res, els[i]) // TODO @gbotrel re-use res memory, don't reallocate limbs !
	}
	return res
}

func (w *FieldAPI[T]) Neg(i1 frontend.Variable) frontend.Variable {
	el := w.varToElement(i1)
	return w.f.Neg(el)
}

func (w *FieldAPI[T]) Sub(i1 frontend.Variable, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	els := w.varsToElements(i1, i2, in)
	sub := newElementPtr[T](els[1])
	for i := 2; i < len(els); i++ {
		sub = w.f.reduceAndOp(w.f.add, w.f.addPreCond, sub, els[i])
	}
	res := w.f.Sub(els[0], sub)
	return res
}

func (w *FieldAPI[T]) Mul(i1 frontend.Variable, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	els := w.varsToElements(i1, i2, in)
	res := w.f.reduceAndOp(w.f.mul, w.f.mulPreCond, els[0], els[1])
	for i := 2; i < len(els); i++ {
		res = w.f.reduceAndOp(w.f.mul, w.f.mulPreCond, res, els[i])
	}
	res = w.f.Reduce(res)
	return res
}

func (w *FieldAPI[T]) DivUnchecked(i1 frontend.Variable, i2 frontend.Variable) frontend.Variable {
	return w.Div(i1, i2)
}

func (w *FieldAPI[T]) Div(i1 frontend.Variable, i2 frontend.Variable) frontend.Variable {
	els := w.varsToElements(i1, i2)
	return w.f.Div(els[0], els[1])
}

func (w *FieldAPI[T]) Inverse(i1 frontend.Variable) frontend.Variable {
	a := w.varToElement(i1)
	return w.f.Inverse(a)
}

func (w *FieldAPI[T]) ToBinary(i1 frontend.Variable, n ...int) []frontend.Variable {
	el := w.varToElement(i1)
	res := w.f.Reduce(el)
	out := w.f.ToBits(res)
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

func (w *FieldAPI[T]) FromBinary(b ...frontend.Variable) frontend.Variable {
	els := w.varsToElements(b)
	in := make([]frontend.Variable, len(els))
	for i := range els {
		w.AssertIsBoolean(els[i])
		in[i] = els[i].Limbs[0]
	}
	return w.f.FromBits(in...)
}

func (w *FieldAPI[T]) Xor(a frontend.Variable, b frontend.Variable) frontend.Variable {
	els := w.varsToElements(a, b)
	w.AssertIsBoolean(els[0])
	w.AssertIsBoolean(els[1])
	rv := w.f.api.Xor(els[0].Limbs[0], els[1].Limbs[0])
	return newElementLimbs[T]([]frontend.Variable{rv}, 0)
}

func (w *FieldAPI[T]) Or(a frontend.Variable, b frontend.Variable) frontend.Variable {
	els := w.varsToElements(a, b)
	w.AssertIsBoolean(els[0])
	w.AssertIsBoolean(els[1])
	rv := w.f.api.Or(els[0].Limbs[0], els[1].Limbs[0])
	return newElementLimbs[T]([]frontend.Variable{rv}, 0)
}

func (w *FieldAPI[T]) And(a frontend.Variable, b frontend.Variable) frontend.Variable {
	els := w.varsToElements(a, b)
	w.AssertIsBoolean(els[0])
	w.AssertIsBoolean(els[1])
	rv := w.f.api.And(els[0].Limbs[0], els[1].Limbs[0])
	return newElementLimbs[T]([]frontend.Variable{rv}, 0)
}

func (w *FieldAPI[T]) Select(b frontend.Variable, i1 frontend.Variable, i2 frontend.Variable) frontend.Variable {
	els := w.varsToElements(i1, i2)
	switch vv := b.(type) {
	case Element[T]:
		w.AssertIsBoolean(vv)
		b = vv.Limbs[0]
	case *Element[T]:
		w.AssertIsBoolean(vv)
		b = vv.Limbs[0]
	}
	return w.f.Select(b, els[0], els[1])
}

func (w *FieldAPI[T]) Lookup2(b0 frontend.Variable, b1 frontend.Variable, i0 frontend.Variable, i1 frontend.Variable, i2 frontend.Variable, i3 frontend.Variable) frontend.Variable {
	els := w.varsToElements(i0, i1, i2, i3)
	switch vv := b0.(type) {
	case Element[T]:
		w.AssertIsBoolean(vv)
		b0 = vv.Limbs[0]
	case *Element[T]:
		w.AssertIsBoolean(vv)
		b0 = vv.Limbs[0]
	}
	switch vv := b1.(type) {
	case Element[T]:
		w.AssertIsBoolean(vv)
		b1 = vv.Limbs[0]
	case *Element[T]:
		w.AssertIsBoolean(vv)
		b1 = vv.Limbs[0]
	}
	return w.f.Lookup2(b0, b1, els[0], els[1], els[2], els[3])
}

func (w *FieldAPI[T]) IsZero(i1 frontend.Variable) frontend.Variable {
	el := w.varToElement(i1)
	reduced := w.f.Reduce(el)
	res := w.f.api.IsZero(reduced.Limbs[0])
	for i := 1; i < len(reduced.Limbs); i++ {
		w.f.api.Mul(res, w.f.api.IsZero(reduced.Limbs[i]))
	}
	r := w.f.PackLimbs([]frontend.Variable{res})
	return r
}

func (w *FieldAPI[T]) Cmp(i1 frontend.Variable, i2 frontend.Variable) frontend.Variable {
	els := w.varsToElements(i1, i2)
	rls := make([]*Element[T], 2)
	rls[0] = w.f.Reduce(els[0])
	rls[1] = w.f.Reduce(els[1])
	var res frontend.Variable = 0
	for i := int(w.f.fParams.NbLimbs() - 1); i >= 0; i-- {
		lmbCmp := w.f.api.Cmp(rls[0].Limbs[i], rls[1].Limbs[i])
		res = w.f.api.Select(w.f.api.IsZero(res), lmbCmp, res)
	}
	return res
}

func (w *FieldAPI[T]) AssertIsEqual(i1 frontend.Variable, i2 frontend.Variable) {
	els := w.varsToElements(i1, i2)
	tmp := newElementPtr[T](els[0])
	w.f.reduceAndOp(func(a, b *Element[T], nextOverflow uint) *Element[T] {
		w.f.AssertIsEqual(a, b)
		return nil
	},
		func(e1, e2 *Element[T]) (uint, error) {
			nextOverflow, err := w.f.subPreCond(e2, e1)
			var target errOverflow
			if err != nil && errors.As(err, &target) {
				target.reduceRight = !target.reduceRight
				return nextOverflow, target
			}
			return nextOverflow, err
		}, tmp, els[1])
}

func (w *FieldAPI[T]) AssertIsDifferent(i1 frontend.Variable, i2 frontend.Variable) {
	els := w.varsToElements(i1, i2)
	rls := [2]*Element[T]{}
	rls[0] = w.f.Reduce(els[0])
	rls[1] = w.f.Reduce(els[1])
	var res frontend.Variable = 0
	for i := 0; i < int(w.f.fParams.NbLimbs()); i++ {
		cmp := w.f.api.Cmp(rls[0].Limbs[i], rls[1].Limbs[i])
		cmpsq := w.f.api.Mul(cmp, cmp)
		res = w.f.api.Add(res, cmpsq)
	}
	w.f.api.AssertIsDifferent(res, 0)
}

func (w *FieldAPI[T]) AssertIsBoolean(i1 frontend.Variable) {
	switch vv := i1.(type) {
	case Element[T]:
		v := w.f.Reduce(&vv)
		w.f.api.AssertIsBoolean(v.Limbs[0])
		for i := 1; i < len(v.Limbs); i++ {
			w.f.api.AssertIsEqual(v.Limbs[i], 0)
		}
	case *Element[T]:
		v := w.f.Reduce(vv)
		w.f.api.AssertIsBoolean(v.Limbs[0])
		for i := 1; i < len(v.Limbs); i++ {
			w.f.api.AssertIsEqual(v.Limbs[i], 0)
		}
	default:
		w.f.api.AssertIsBoolean(vv)
	}
}

func (w *FieldAPI[T]) AssertIsLessOrEqual(v frontend.Variable, bound frontend.Variable) {
	els := w.varsToElements(v, bound)
	l := w.f.Reduce(els[0])
	r := w.f.Reduce(els[1])
	w.f.AssertIsLessEqualThan(l, r)
}

func (w *FieldAPI[T]) Println(a ...frontend.Variable) {
	els := w.varsToElements(a)
	for i := range els {
		w.f.api.Println(els[i].Limbs...)
	}
}

func (w *FieldAPI[T]) Compiler() frontend.Compiler {
	return w
}

type typedInput struct {
	pos       int
	nbLimbs   int
	isElement bool
}

func (w *FieldAPI[T]) NewHint(hf hint.Function, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {
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
	nbNativeOutputs := nbOutputs * int(w.f.fParams.NbLimbs())
	wrappedHint := func(_ *big.Int, expandedHintInputs []*big.Int, expandedHintOutputs []*big.Int) error {
		hintInputs := make([]*big.Int, len(inputs))
		hintOutputs := make([]*big.Int, nbOutputs)
		for i, ti := range typedInputs {
			hintInputs[i] = new(big.Int)
			if ti.isElement {
				if err := recompose(expandedHintInputs[ti.pos:ti.pos+ti.nbLimbs], w.f.fParams.BitsPerLimb(), hintInputs[i]); err != nil {
					return fmt.Errorf("recompose: %w", err)
				}
			} else {
				hintInputs[i].Set(expandedHintInputs[ti.pos])
			}
		}
		for i := range hintOutputs {
			hintOutputs[i] = new(big.Int)
		}
		if err := hf(w.f.fParams.Modulus(), hintInputs, hintOutputs); err != nil {
			return fmt.Errorf("call hint: %w", err)
		}
		for i := range hintOutputs {
			if err := decompose(hintOutputs[i], w.f.fParams.BitsPerLimb(), expandedHintOutputs[i*int(w.f.fParams.NbLimbs()):(i+1)*int(w.f.fParams.NbLimbs())]); err != nil {
				return fmt.Errorf("decompose: %w", err)
			}
		}
		return nil
	}
	hintRet, err := w.f.api.Compiler().NewHint(wrappedHint, nbNativeOutputs, expandedInputs...)
	if err != nil {
		return nil, fmt.Errorf("NewHint: %w", err)
	}
	ret := make([]frontend.Variable, nbOutputs)
	for i := 0; i < nbOutputs; i++ {
		limbs := hintRet[i*int(w.f.fParams.NbLimbs()) : (i+1)*int(w.f.fParams.NbLimbs())]
		ret[i] = newElementLimbs[T](limbs, 0)
	}
	return ret, nil
}

func (w *FieldAPI[T]) ConstantValue(v frontend.Variable) (*big.Int, bool) {
	el := w.varToElement(v)
	return w.f.constantValue(el)
}

func (w *FieldAPI[T]) Field() *big.Int {
	return w.f.fParams.Modulus()
}

func (w *FieldAPI[T]) FieldBitLen() int {
	return w.f.fParams.Modulus().BitLen()
}

func (w *FieldAPI[T]) IsBoolean(v frontend.Variable) bool {
	switch vv := v.(type) {
	case Element[T]:
		return w.f.api.Compiler().IsBoolean(vv.Limbs[0])
	case *Element[T]:
		return w.f.api.Compiler().IsBoolean(vv.Limbs[0])
	default:
		return w.f.api.Compiler().IsBoolean(vv)
	}
}

func (w *FieldAPI[T]) MarkBoolean(v frontend.Variable) {
	switch vv := v.(type) {
	case Element[T]:
		w.f.api.Compiler().MarkBoolean(vv.Limbs[0])
	case *Element[T]:
		w.f.api.Compiler().MarkBoolean(vv.Limbs[0])
	default:
		w.f.api.Compiler().MarkBoolean(vv)
	}
}

// --- non-API methods

func (w *FieldAPI[T]) Reduce(i1 frontend.Variable) frontend.Variable {
	el := w.varToElement(i1)
	return w.f.Reduce(el)
}
