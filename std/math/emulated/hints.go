package emulated

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
)

func init() {
	hints := GetHints()
	for _, h := range hints {
		hint.Register(h)
	}
}

// GetHints returns all hint functions used in the package.
func GetHints() []hint.Function {
	return []hint.Function{
		DivHint,
		EqualityHint,
		InverseHint,
		MultiplicationHint,
		ReductionHint,
	}
}

// computeMultiplicationHint packs the inputs for the MultiplicationHint hint function.
func computeMultiplicationHint[T FieldParams](api frontend.API, params *field[T], leftLimbs, rightLimbs []frontend.Variable) (mulLimbs []frontend.Variable, err error) {
	hintInputs := []frontend.Variable{
		params.fParams.BitsPerLimb(),
		len(leftLimbs),
		len(rightLimbs),
	}
	hintInputs = append(hintInputs, leftLimbs...)
	hintInputs = append(hintInputs, rightLimbs...)
	return api.NewHint(MultiplicationHint, nbMultiplicationResLimbs(len(leftLimbs), len(rightLimbs)), hintInputs...)
}

// nbMultiplicationResLimbs returns the number of limbs which fit the
// multiplication result.
func nbMultiplicationResLimbs(lenLeft, lenRight int) int {
	return lenLeft + lenRight - 1
}

// MultiplicationHint unpacks the factors and parameters from inputs, computes
// the product and stores it in output. See internal method
// computeMultiplicationHint for the input packing.
func MultiplicationHint(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) < 3 {
		return fmt.Errorf("input must be at least three elements")
	}
	nbBits := int(inputs[0].Int64())
	if 2*nbBits+1 >= mod.BitLen() {
		return fmt.Errorf("can not fit multiplication result into limb of length %d", nbBits)
	}
	// TODO: check that the scalar field fits 2*nbBits + nbLimbs. 2*nbBits comes
	// from multiplication and nbLimbs comes from additions.
	// TODO: check that all limbs all fully reduced
	nbLimbsLeft := int(inputs[1].Int64())
	// TODO: get the limb length from the input instead of packing into input
	nbLimbsRight := int(inputs[2].Int64())
	if len(inputs) != 3+nbLimbsLeft+nbLimbsRight {
		return fmt.Errorf("input invalid")
	}
	if len(outputs) < nbLimbsLeft+nbLimbsRight-1 {
		return fmt.Errorf("can not fit multiplication result into %d limbs", len(outputs))
	}
	for _, oi := range outputs {
		if oi == nil {
			return fmt.Errorf("output not initialized")
		}
		oi.SetUint64(0)
	}
	tmp := new(big.Int)
	for i, li := range inputs[3 : 3+nbLimbsLeft] {
		for j, rj := range inputs[3+nbLimbsLeft:] {
			outputs[i+j].Add(outputs[i+j], tmp.Mul(li, rj))
		}
	}
	return nil
}

// computeReductionHint packs inputs for the ReductionHint hint function.
func (f *field[T]) computeReductionHint(inLimbs []frontend.Variable) (reducedLimbs []frontend.Variable, err error) {
	var fp T
	hintInputs := []frontend.Variable{
		fp.BitsPerLimb(),
		fp.NbLimbs(),
	}
	p := f.Modulus()
	for i := range p.Limbs {
		hintInputs = append(hintInputs, frontend.Variable(p.Limbs[i]))
	}
	hintInputs = append(hintInputs, inLimbs...)
	return f.api.NewHint(ReductionHint, int(fp.NbLimbs()), hintInputs...)
}

// ReductionHint computes the remainder r for input x = k*p + r and stores it
// in outputs.
func ReductionHint(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) < 2 {
		return fmt.Errorf("input must be at least two elements")
	}
	nbBits := uint(inputs[0].Uint64())
	nbLimbs := int(inputs[1].Int64())
	if len(inputs[2:]) < 2*nbLimbs {
		return fmt.Errorf("reducible value missing")
	}
	if len(outputs) != nbLimbs {
		return fmt.Errorf("result does not fit into output")
	}
	p := new(big.Int)
	if err := recompose(inputs[2:2+nbLimbs], nbBits, p); err != nil {
		return fmt.Errorf("recompose emulated order: %w", err)
	}
	x := new(big.Int)
	if err := recompose(inputs[2+nbLimbs:], nbBits, x); err != nil {
		return fmt.Errorf("recompose value: %w", err)
	}
	q := new(big.Int)
	r := new(big.Int)
	q.QuoRem(x, p, r)
	if err := decompose(r, nbBits, outputs); err != nil {
		return fmt.Errorf("decompose remainder: %w", err)
	}
	return nil
}

// computeEqualityHint packs the inputs for EqualityHint function.
func computeEqualityHint[T FieldParams](api frontend.API, params *field[T], diff Element[T]) (kpLimbs []frontend.Variable, err error) {
	var fp T
	p := params.Modulus()
	resLen := (uint(len(diff.Limbs))*fp.BitsPerLimb() + diff.overflow + 1 - // diff total bitlength
		uint(fp.Modulus().BitLen()) + // subtract modulus bitlength
		fp.BitsPerLimb() - 1) / // to round up
		fp.BitsPerLimb()
	hintInputs := []frontend.Variable{
		fp.BitsPerLimb(),
		fp.NbLimbs(),
	}
	hintInputs = append(hintInputs, p.Limbs...)
	hintInputs = append(hintInputs, diff.Limbs...)
	return api.NewHint(EqualityHint, int(resLen), hintInputs...)
}

// EqualityHint computes k for input x = k*p and stores it in outputs.
func EqualityHint(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	// first value is the number of bits per limb (nbBits)
	// second value is the number of limbs for modulus
	// then comes emulated modulus (p)
	// and the rest is for the difference (diff)
	//
	// if the quotient z = diff / p is larger than the scalar modulus, then err.
	// Otherwise we store the quotient in the output element (a single element).
	//
	// errors when does not divide evenly (we do not allow to generate invalid
	// proofs)
	if len(inputs) < 2 {
		return fmt.Errorf("at least 2 inputs required")
	}
	nbBits := uint(inputs[0].Uint64())
	nbLimbs := int(inputs[1].Int64())
	if len(inputs[2:]) < nbLimbs {
		return fmt.Errorf("modulus limbs missing")
	}
	p := new(big.Int)
	diff := new(big.Int)
	if err := recompose(inputs[2:2+nbLimbs], nbBits, p); err != nil {
		return fmt.Errorf("recompose emulated order: %w", err)
	}
	if err := recompose(inputs[2+nbLimbs:], nbBits, diff); err != nil {
		return fmt.Errorf("recompose diff")
	}
	r := new(big.Int)
	z := new(big.Int)
	z.QuoRem(diff, p, r)
	if r.Cmp(big.NewInt(0)) != 0 {
		return fmt.Errorf("modulus does not divide diff evenly")
	}
	if err := decompose(z, nbBits, outputs); err != nil {
		return fmt.Errorf("decompose: %w", err)
	}
	return nil
}

// computeInverseHint packs the inputs for the InverseHint hint function.
func computeInverseHint[T FieldParams](api frontend.API, params *field[T], inLimbs []frontend.Variable) (inverseLimbs []frontend.Variable, err error) {
	var fp T
	hintInputs := []frontend.Variable{
		fp.BitsPerLimb(),
		fp.NbLimbs(),
	}
	p := params.Modulus()
	hintInputs = append(hintInputs, p.Limbs...)
	hintInputs = append(hintInputs, inLimbs...)
	return api.NewHint(InverseHint, int(fp.NbLimbs()), hintInputs...)
}

// InverseHint computes the inverse x^-1 for the input x and stores it in outputs.
func InverseHint(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) < 2 {
		return fmt.Errorf("input must be at least two elements")
	}
	nbBits := uint(inputs[0].Uint64())
	nbLimbs := int(inputs[1].Int64())
	if len(inputs[2:]) < 2*nbLimbs {
		return fmt.Errorf("inputs missing")
	}
	if len(outputs) != nbLimbs {
		return fmt.Errorf("result does not fit into output")
	}
	p := new(big.Int)
	if err := recompose(inputs[2:2+nbLimbs], nbBits, p); err != nil {
		return fmt.Errorf("recompose emulated order: %w", err)
	}
	x := new(big.Int)
	if err := recompose(inputs[2+nbLimbs:], nbBits, x); err != nil {
		return fmt.Errorf("recompose value: %w", err)
	}
	if x.ModInverse(x, p) == nil {
		return fmt.Errorf("input and modulus not relatively primes")
	}
	if err := decompose(x, nbBits, outputs); err != nil {
		return fmt.Errorf("decompose: %w", err)
	}
	return nil
}

// computeDivisionHint packs the inputs for DivisionHint hint function.
func computeDivisionHint[T FieldParams](api frontend.API, params *field[T], nomLimbs, denomLimbs []frontend.Variable) (divLimbs []frontend.Variable, err error) {
	var fp T
	hintInputs := []frontend.Variable{
		fp.BitsPerLimb(),
		fp.NbLimbs(),
		len(nomLimbs),
	}
	p := params.Modulus()
	hintInputs = append(hintInputs, p.Limbs...)
	hintInputs = append(hintInputs, nomLimbs...)
	hintInputs = append(hintInputs, denomLimbs...)
	return api.NewHint(DivHint, int(fp.NbLimbs()), hintInputs...)
}

// DivHint computes the value z = x/y for inputs x and y and stores z in
// outputs.
func DivHint(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) < 3 {
		return fmt.Errorf("input must be at least three elements")
	}
	nbBits := uint(inputs[0].Uint64())
	nbLimbs := int(inputs[1].Int64())
	// nominator does not have to be reduced and can be more than nbLimbs.
	// Denominator and order have to be nbLimbs long.
	nbNomLimbs := int(inputs[2].Int64())
	if len(inputs[3:]) != nbNomLimbs+2*nbLimbs {
		return fmt.Errorf("input length mismatch")
	}
	if len(outputs) != nbLimbs {
		return fmt.Errorf("result does not fit into output")
	}
	p := new(big.Int)
	if err := recompose(inputs[3:3+nbLimbs], nbBits, p); err != nil {
		return fmt.Errorf("recompose emulated order: %w", err)
	}
	nominator := new(big.Int)
	if err := recompose(inputs[3+nbLimbs:3+nbLimbs+nbNomLimbs], nbBits, nominator); err != nil {
		return fmt.Errorf("recompose nominator: %w", err)
	}
	denominator := new(big.Int)
	if err := recompose(inputs[3+nbLimbs+nbNomLimbs:], nbBits, denominator); err != nil {
		return fmt.Errorf("recompose denominator: %w", err)
	}
	res := new(big.Int).ModInverse(denominator, p)
	if res == nil {
		return fmt.Errorf("no modular inverse")
	}
	res.Mul(res, nominator)
	res.Mod(res, p)
	if err := decompose(res, nbBits, outputs); err != nil {
		return fmt.Errorf("decompose division: %w", err)
	}
	return nil
}
