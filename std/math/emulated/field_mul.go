package emulated

import (
	"fmt"
	"math"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/internal/multicommit"
)

type mulCheck[T FieldParams] struct {
	f *Field[T]
	// a * b = r + k*p + c
	a, b *Element[T] // inputs
	r    *Element[T] // reduced value
	k    *Element[T] // coefficient
	c    *Element[T] // carry
}

func (mc *mulCheck[T]) evalRound1(api frontend.API, at []frontend.Variable) {
	mc.c = mc.f.evalWithChallenge(mc.c, at)
	mc.r = mc.f.evalWithChallenge(mc.r, at)
	mc.k = mc.f.evalWithChallenge(mc.k, at)
}

func (mc *mulCheck[T]) evalRound2(api frontend.API, at []frontend.Variable) {
	mc.a = mc.f.evalWithChallenge(mc.a, at)
	mc.b = mc.f.evalWithChallenge(mc.b, at)
}

func (mc *mulCheck[T]) check(api frontend.API, peval, coef frontend.Variable) {
	ls := api.Mul(mc.a.evaluation, mc.b.evaluation)
	rs := api.Add(mc.r.evaluation, api.Mul(peval, mc.k.evaluation), api.Mul(mc.c.evaluation, coef))
	api.AssertIsEqual(ls, rs)
}

func (f *Field[T]) mulMod(a, b *Element[T], nextOverflow uint) *Element[T] {
	f.enforceWidthConditional(a)
	f.enforceWidthConditional(b)
	k, r, c, err := f.callMulHint(a, b)
	if err != nil {
		panic(err)
	}
	mc := mulCheck[T]{
		f: f,
		a: a,
		b: b,
		c: c,
		k: k,
		r: r,
	}
	f.mulChecks = append(f.mulChecks, mc)
	return r
}

func (f *Field[T]) evalWithChallenge(a *Element[T], at []frontend.Variable) *Element[T] {
	if a.isEvaluated {
		return a
	}
	if len(at) < len(a.Limbs)-1 {
		panic("evaluation powers less than limbs")
	}
	sum := f.api.Mul(a.Limbs[0], 1) // copy because we use MulAcc
	for i := 1; i < len(a.Limbs); i++ {
		sum = f.api.MulAcc(sum, a.Limbs[i], at[i-1])
	}
	a.isEvaluated = true
	a.evaluation = sum
	return a
}

func (f *Field[T]) performMulChecks(api frontend.API) error {
	// use given api. We are in defer and API may be different to what we have
	// stored.

	// there are no multiplication checks, nothing to do
	if len(f.mulChecks) == 0 {
		return nil
	}

	// we construct a list of elements we want to commit to. Even though we have
	// commited when doing range checks, do it again here explicitly for safety.
	// TODO: committing is actually expensive in PLONK. We create a constraint
	// for every variable we commit to (to set the selector polynomial). So, it
	// is actually better not to commit again. However, if we would be to use
	// multi-commit and range checks are in different commitment, then we have
	// problem.
	var toCommit []frontend.Variable
	for i := range f.mulChecks {
		toCommit = append(toCommit, f.mulChecks[i].a.Limbs...)
		toCommit = append(toCommit, f.mulChecks[i].b.Limbs...)
		toCommit = append(toCommit, f.mulChecks[i].r.Limbs...)
		toCommit = append(toCommit, f.mulChecks[i].k.Limbs...)
		toCommit = append(toCommit, f.mulChecks[i].c.Limbs...)
	}
	multicommit.WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
		coefsLen := 0
		for i := range f.mulChecks {
			coefsLen = max(coefsLen, len(f.mulChecks[i].c.Limbs))
		}
		at := make([]frontend.Variable, coefsLen)
		var prev frontend.Variable = 1
		for i := range at {
			at[i] = api.Mul(prev, commitment)
			prev = at[i]
		}
		for i := range f.mulChecks {
			f.mulChecks[i].evalRound1(api, at)
		}
		// assuming r is input to some other multiplication, then is already evaluated
		for i := range f.mulChecks {
			f.mulChecks[i].evalRound2(api, at)
		}
		pval := f.evalWithChallenge(f.Modulus(), at)
		coef := big.NewInt(1)
		coef.Lsh(coef, f.fParams.BitsPerLimb())
		ccoef := api.Sub(coef, commitment)
		for i := range f.mulChecks {
			f.mulChecks[i].check(api, pval.evaluation, ccoef)
		}
		return nil
	}, toCommit...)
	return nil
}

func (f *Field[T]) callMulHint(a, b *Element[T]) (quo, rem, carries *Element[T], err error) {
	// inputs is always nblimbs
	// quotient may be larger if inputs have overflow
	// remainder is always nblimbs
	// carries is 2 * nblimbs - 2 (do not consider first limb)
	nextOverflow, _ := f.mulPreCond(a, b)
	// skip error handle - it happens when we are supposed to reduce. But we
	// already check it as a precondition. We only need the overflow here.
	nbLimbs, nbBits := f.fParams.NbLimbs(), f.fParams.BitsPerLimb()
	nbQuoLimbs := ((2*nbLimbs-1)*nbBits + nextOverflow + 1 - //
		uint(f.fParams.Modulus().BitLen()) + //
		nbBits - 1) /
		nbBits
	nbRemLimbs := nbLimbs
	nbCarryLimbs := (nbQuoLimbs + nbLimbs) - 2
	hintInputs := []frontend.Variable{
		nbBits,
		nbLimbs,
	}
	hintInputs = append(hintInputs, f.Modulus().Limbs...)
	hintInputs = append(hintInputs, a.Limbs...)
	hintInputs = append(hintInputs, b.Limbs...)
	ret, err := f.api.NewHint(mulHint, int(nbQuoLimbs)+int(nbRemLimbs)+int(nbCarryLimbs), hintInputs...)
	if err != nil {
		err = fmt.Errorf("call hint: %w", err)
		return
	}
	quo = f.packLimbs(ret[:nbQuoLimbs], false)
	rem = f.packLimbs(ret[nbQuoLimbs:nbQuoLimbs+nbRemLimbs], true)
	carries = f.newInternalElement(ret[nbQuoLimbs+nbRemLimbs:], 0)
	return
}

func mulHint(field *big.Int, inputs, outputs []*big.Int) error {
	nbBits := int(inputs[0].Int64())
	nbLimbs := int(inputs[1].Int64())
	ptr := 2
	plimbs := inputs[ptr : ptr+nbLimbs]
	ptr += nbLimbs
	alimbs := inputs[ptr : ptr+nbLimbs]
	ptr += nbLimbs
	blimbs := inputs[ptr : ptr+nbLimbs]

	nbQuoLen := (len(outputs) - 2*nbLimbs + 2) / 2
	nbCarryLen := nbLimbs + nbQuoLen - 2
	outptr := 0
	quoLimbs := outputs[outptr : outptr+nbQuoLen]
	outptr += nbQuoLen
	remLimbs := outputs[outptr : outptr+nbLimbs]
	outptr += nbLimbs
	carryLimbs := outputs[outptr : outptr+nbCarryLen]

	p := new(big.Int)
	a := new(big.Int)
	b := new(big.Int)
	if err := recompose(plimbs, uint(nbBits), p); err != nil {
		return fmt.Errorf("recompose p: %w", err)
	}
	if err := recompose(alimbs, uint(nbBits), a); err != nil {
		return fmt.Errorf("recompose a: %w", err)
	}
	if err := recompose(blimbs, uint(nbBits), b); err != nil {
		return fmt.Errorf("recompose b: %w", err)
	}
	quo := new(big.Int)
	rem := new(big.Int)
	ab := new(big.Int).Mul(a, b)
	quo.QuoRem(ab, p, rem)
	if err := decompose(quo, uint(nbBits), quoLimbs); err != nil {
		return fmt.Errorf("decompose quo: %w", err)
	}
	if err := decompose(rem, uint(nbBits), remLimbs); err != nil {
		return fmt.Errorf("decompose rem: %w", err)
	}
	xp := make([]*big.Int, nbLimbs+nbQuoLen-1)
	yp := make([]*big.Int, nbLimbs+nbQuoLen-1)
	for i := range xp {
		xp[i] = new(big.Int)
	}
	for i := range yp {
		yp[i] = new(big.Int)
	}
	tmp := new(big.Int)
	for i := 0; i < nbLimbs; i++ {
		for j := 0; j < nbLimbs; j++ {
			tmp.Mul(alimbs[i], blimbs[j])
			xp[i+j].Add(xp[i+j], tmp)
		}
		yp[i].Add(yp[i], remLimbs[i])
		for j := 0; j < nbQuoLen; j++ {
			tmp.Mul(quoLimbs[j], plimbs[i])
			yp[i+j].Add(yp[i+j], tmp)
		}
	}
	carry := new(big.Int)
	for i := range carryLimbs {
		carry.Add(carry, xp[i])
		carry.Sub(carry, yp[i])
		carry.Rsh(carry, uint(nbBits))
		carryLimbs[i] = new(big.Int).Set(carry)
	}
	return nil
}
