package emulated

import (
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

func (f *Field[T]) Div(a, b *Element[T]) *Element[T] {
	if !f.fParams.IsPrime() {
		// TODO shouldn't we still try to do a classic int div in a hint, constraint the result, and let it fail?
		// that would enable things like uint32 div ?
		panic("modulus not a prime")
	}
	div, err := f.computeDivisionHint(a.Limbs, b.Limbs)
	if err != nil {
		panic(fmt.Sprintf("compute division: %v", err))
	}
	e := f.PackLimbs(div)
	res := f.Mul(e, b)
	f.AssertIsEqual(res, a)
	return e
}

func (f *Field[T]) Inverse(a *Element[T]) *Element[T] {
	if !f.fParams.IsPrime() {
		panic("modulus not a prime")
	}
	k, err := f.computeInverseHint(a.Limbs)
	if err != nil {
		panic(fmt.Sprintf("compute inverse: %v", err))
	}
	e := f.PackLimbs(k)
	res := f.Mul(e, a)
	one := f.One()
	f.AssertIsEqual(res, one)
	return e
}

func (f *Field[T]) Add(a, b *Element[T]) *Element[T] {
	return f.reduceAndOp(f.add, f.addPreCond, a, b)
}

func (f *Field[T]) AddMutable(a, b *Element[T]) *Element[T] {
	r := f.reduceAndOpMutable(f.add, f.addPreCond, a, b)
	return r
}

func (f *Field[T]) addPreCond(a, b *Element[T]) (nextOverflow uint, err error) {
	reduceRight := a.overflow < b.overflow
	nextOverflow = max(a.overflow, b.overflow) + 1
	if nextOverflow > f.maxOverflow() {
		err = errOverflow{op: "add", nextOverflow: nextOverflow, maxOverflow: f.maxOverflow(), reduceRight: reduceRight}
	}
	return
}

func (f *Field[T]) add(a, b *Element[T], nextOverflow uint) *Element[T] {
	ba, aConst := f.constantValue(a)
	bb, bConst := f.constantValue(b)
	if aConst && bConst {
		ba.Add(ba, bb).Mod(ba, f.fParams.Modulus())
		return newElementPtr[T](ba)
	}

	nbLimbs := max(len(a.Limbs), len(b.Limbs))
	limbs := make([]frontend.Variable, nbLimbs)
	for i := range limbs {
		limbs[i] = 0
		if i < len(a.Limbs) {
			limbs[i] = f.api.Add(limbs[i], a.Limbs[i])
		}
		if i < len(b.Limbs) {
			limbs[i] = f.api.Add(limbs[i], b.Limbs[i])
		}
	}
	return newElementLimbs[T](limbs, nextOverflow)
}

func (f *Field[T]) Mul(a, b *Element[T]) *Element[T] {
	return f.reduceAndOp(f.mul, f.mulPreCond, a, b)
}

func (f *Field[T]) MulMod(a, b *Element[T]) *Element[T] {
	r := f.Mul(a, b)
	return f.Reduce(r)
}

func (f *Field[T]) MulModMutable(a, b *Element[T]) *Element[T] {
	r := f.reduceAndOpMutable(f.mul, f.mulPreCond, a, b)
	return f.Reduce(r)
}

func (f *Field[T]) mulPreCond(a, b *Element[T]) (nextOverflow uint, err error) {
	reduceRight := a.overflow < b.overflow
	nbResLimbs := nbMultiplicationResLimbs(len(a.Limbs), len(b.Limbs))
	nextOverflow = f.fParams.BitsPerLimb() + uint(math.Log2(float64(2*nbResLimbs-1))) + 1 + a.overflow + b.overflow
	if nextOverflow > f.maxOverflow() {
		err = errOverflow{op: "mul", nextOverflow: nextOverflow, maxOverflow: f.maxOverflow(), reduceRight: reduceRight}
	}
	return
}

func (f *Field[T]) mul(a, b *Element[T], nextOverflow uint) *Element[T] {
	ba, aConst := f.constantValue(a)
	bb, bConst := f.constantValue(b)
	if aConst && bConst {
		ba.Mul(ba, bb).Mod(ba, f.fParams.Modulus())
		return newElementPtr[T](ba)
	}

	// mulResult contains the result (out of circuit) of a * b school book multiplication
	// len(mulResult) == len(a) + len(b) - 1
	mulResult, err := f.computeMultiplicationHint(a.Limbs, b.Limbs)
	if err != nil {
		panic(fmt.Sprintf("multiplication hint: %s", err))
	}

	// we computed the result of the mul outside the circuit (mulResult)
	// and we want to constrain inside the circuit that this injected value
	// actually matches the in-circuit a * b values
	// create constraints (\sum_{i=0}^{m-1} a_i c^i) * (\sum_{i=0}^{m-1} b_i
	// c^i) = (\sum_{i=0}^{2m-2} z_i c^i) for c \in {1, 2m-1}
	w := new(big.Int)
	for c := 1; c <= len(mulResult); c++ {
		w.SetInt64(1) // c^i
		l := a.Limbs[0]
		r := b.Limbs[0]
		o := mulResult[0]

		for i := 1; i < len(mulResult); i++ {
			w.Lsh(w, uint(c))
			if i < len(a.Limbs) {
				l = f.api.Add(l, f.api.Mul(a.Limbs[i], w))
			}
			if i < len(b.Limbs) {
				r = f.api.Add(r, f.api.Mul(b.Limbs[i], w))
			}
			o = f.api.Add(o, f.api.Mul(mulResult[i], w))
		}
		f.api.AssertIsEqual(f.api.Mul(l, r), o)
	}
	return newElementLimbs[T](mulResult, nextOverflow)
}

// Reduce reduces a modulo modulus and assigns e to the reduced value.
func (f *Field[T]) Reduce(a *Element[T]) *Element[T] {
	if a.overflow == 0 {
		// fast path - already reduced, omit reduction.
		return a
	}
	// sanity check
	_, aConst := f.constantValue(a)
	if aConst {
		panic("trying to reduce a constant, which happen to have an overflow flag set")
	}

	// slow path - use hint to reduce value
	e, err := f.computeRemHint(a, f.Modulus())
	if err != nil {
		panic(fmt.Sprintf("reduction hint: %v", err))
	}
	// TODO @gbotrel fixme: AssertIsEqual(a, e) crashes Pairing test
	f.AssertIsEqual(e, a)
	return e
}

func (f *Field[T]) Sub(a, b *Element[T]) *Element[T] {
	return f.reduceAndOp(f.sub, f.subPreCond, a, b)
}

func (f *Field[T]) SubMutable(a, b *Element[T]) *Element[T] {
	r := f.reduceAndOpMutable(f.sub, f.subPreCond, a, b)
	return r
}

func (f *Field[T]) subPreCond(a, b *Element[T]) (nextOverflow uint, err error) {
	reduceRight := a.overflow < b.overflow+2
	nextOverflow = max(b.overflow+2, a.overflow)
	if nextOverflow > f.maxOverflow() {
		err = errOverflow{op: "sub", nextOverflow: nextOverflow, maxOverflow: f.maxOverflow(), reduceRight: reduceRight}
	}
	return
}

func (f *Field[T]) sub(a, b *Element[T], nextOverflow uint) *Element[T] {
	ba, aConst := f.constantValue(a)
	bb, bConst := f.constantValue(b)
	if aConst && bConst {
		ba.Sub(ba, bb).Mod(ba, f.fParams.Modulus())
		return newElementPtr[T](ba)
	}

	// first we have to compute padding to ensure that the subtraction does not
	// underflow.
	nbLimbs := max(len(a.Limbs), len(b.Limbs))
	limbs := make([]frontend.Variable, nbLimbs)
	padLimbs := subPadding[T](b.overflow, uint(nbLimbs))
	for i := range limbs {
		limbs[i] = padLimbs[i]
		if i < len(a.Limbs) {
			limbs[i] = f.api.Add(limbs[i], a.Limbs[i])
		}
		if i < len(b.Limbs) {
			limbs[i] = f.api.Sub(limbs[i], b.Limbs[i])
		}
	}
	return newElementLimbs[T](limbs, nextOverflow)
}

func (f *Field[T]) Neg(a *Element[T]) *Element[T] {
	return f.Sub(f.Zero(), a)
}

// Select sets e to a if selector == 0 and to b otherwise.
// assumes a overflow == b overflow
func (f *Field[T]) Select(selector frontend.Variable, a, b *Element[T]) *Element[T] {
	overflow := max(a.overflow, b.overflow)
	nbLimbs := max(len(a.Limbs), len(b.Limbs))
	e := newElementLimbs[T](make([]frontend.Variable, nbLimbs), overflow)
	normalize := func(limbs []frontend.Variable) []frontend.Variable {
		if len(limbs) < nbLimbs {
			tail := make([]frontend.Variable, nbLimbs-len(limbs))
			for i := range tail {
				tail[i] = 0
			}
			return append(limbs, tail...)
		}
		return limbs
	}
	aNormLimbs := normalize(a.Limbs)
	bNormLimbs := normalize(b.Limbs)
	for i := range e.Limbs {
		e.Limbs[i] = f.api.Select(selector, aNormLimbs[i], bNormLimbs[i])
	}
	return e
}

// Lookup2 performs two-bit lookup between a, b, c, d based on lookup bits b1
// and b2. Sets e to a if b0=b1=0, b if b0=1 and b1=0, c if b0=0 and b1=1, d if b0=b1=1.
func (f *Field[T]) Lookup2(b0, b1 frontend.Variable, a, b, c, d *Element[T]) *Element[T] {
	overflow := max(a.overflow, b.overflow, c.overflow, d.overflow)
	nbLimbs := max(len(a.Limbs), len(b.Limbs), len(c.Limbs), len(d.Limbs))
	e := newElementLimbs[T](make([]frontend.Variable, nbLimbs), overflow)
	normalize := func(limbs []frontend.Variable) []frontend.Variable {
		if len(limbs) < nbLimbs {
			tail := make([]frontend.Variable, nbLimbs-len(limbs))
			for i := range tail {
				tail[i] = 0
			}
			return append(limbs, tail...)
		}
		return limbs
	}
	aNormLimbs := normalize(a.Limbs)
	bNormLimbs := normalize(b.Limbs)
	cNormLimbs := normalize(c.Limbs)
	dNormLimbs := normalize(d.Limbs)
	for i := range a.Limbs {
		e.Limbs[i] = f.api.Lookup2(b0, b1, aNormLimbs[i], bNormLimbs[i], cNormLimbs[i], dNormLimbs[i])
	}
	return e
}

// reduceAndOp applies op on the inputs. If the pre-condition check preCond
// errs, then first reduces the input arguments. The reduction is done
// one-by-one with the element with highest overflow reduced first.
func (f *Field[T]) reduceAndOp(op func(*Element[T], *Element[T], uint) *Element[T], preCond func(*Element[T], *Element[T]) (uint, error), a, b *Element[T]) *Element[T] {
	var nextOverflow uint
	var err error
	var target errOverflow

	for nextOverflow, err = preCond(a, b); errors.As(err, &target); nextOverflow, err = preCond(a, b) {
		if !target.reduceRight {
			a = f.Reduce(a)
		} else {
			b = f.Reduce(b)
		}
	}
	return op(a, b, nextOverflow)
}

func (f *Field[T]) reduceAndOpMutable(op func(*Element[T], *Element[T], uint) *Element[T], preCond func(*Element[T], *Element[T]) (uint, error), a, b *Element[T]) *Element[T] {
	var nextOverflow uint
	var err error
	var target errOverflow

	for nextOverflow, err = preCond(a, b); errors.As(err, &target); nextOverflow, err = preCond(a, b) {
		if !target.reduceRight {
			*a = *f.Reduce(a)
		} else {
			*b = *f.Reduce(b)
		}
	}
	return op(a, b, nextOverflow)
}

type errOverflow struct {
	op           string
	nextOverflow uint
	maxOverflow  uint
	reduceRight  bool
}

func (e errOverflow) Error() string {
	return fmt.Sprintf("op %s overflow %d exceeds max %d", e.op, e.nextOverflow, e.maxOverflow)
}
