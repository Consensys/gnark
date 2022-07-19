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
		QuoHint,
		InverseHint,
		MultiplicationHint,
		RemHint,
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

// computeRemHint packs inputs for the RemHint hint function.
// sets z to the remainder x%y for y != 0 and returns z.
func (f *field[T]) computeRemHint(x, y Element[T]) (z Element[T], err error) {
	var fp T
	hintInputs := []frontend.Variable{
		fp.BitsPerLimb(),
		len(x.Limbs),
	}
	hintInputs = append(hintInputs, x.Limbs...)
	hintInputs = append(hintInputs, y.Limbs...)
	limbs, err := f.api.NewHint(RemHint, int(len(y.Limbs)), hintInputs...)
	if err != nil {
		return Element[T]{}, err
	}
	return f.PackLimbs(limbs), nil
}

// RemHint sets z to the remainder x%y for y != 0 and returns z.
// If y == 0, returns an error.
// Rem implements truncated modulus (like Go); see QuoRem for more details.
func RemHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	nbBits, x, y, err := parseHintDivInputs(inputs)
	if err != nil {
		return err
	}
	r := new(big.Int)
	r.Rem(x, y)
	if err := decompose(r, nbBits, outputs); err != nil {
		return fmt.Errorf("decompose remainder: %w", err)
	}
	return nil
}

// computeQuoHint packs the inputs for QuoHint function and returns z = x / y
// (discards remainder)
func (f *field[T]) computeQuoHint(x, y Element[T]) (z Element[T], err error) {
	var fp T
	xBitLen := uint(len(x.Limbs))*(fp.BitsPerLimb()) + x.overflow
	yBitLen := uint(len(y.Limbs))*(fp.BitsPerLimb()) + y.overflow
	diff := max(xBitLen, yBitLen) - min(xBitLen, yBitLen)
	resLen := (diff + fp.BitsPerLimb() - 1) / fp.BitsPerLimb()

	hintInputs := []frontend.Variable{
		fp.BitsPerLimb(),
		len(x.Limbs),
	}
	hintInputs = append(hintInputs, x.Limbs...)
	hintInputs = append(hintInputs, y.Limbs...)

	limbs, err := f.api.NewHint(QuoHint, int(resLen), hintInputs...)
	if err != nil {
		return Element[T]{}, err
	}

	return f.PackLimbs(limbs), nil
}

// QuoHint sets z to the quotient x/y for y != 0 and returns z.
// If y == 0, returns an error.
// Quo implements truncated division (like Go); see QuoRem for more details.
func QuoHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	nbBits, x, y, err := parseHintDivInputs(inputs)
	if err != nil {
		return err
	}
	z := new(big.Int)
	z.Quo(x, y)
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

// input[0] = nbBits per limb
// input[1] = nbLimbs(x)
// input[2:2+nbLimbs(x)] = limbs(x)
// input[2+nbLimbs(x):] = limbs(y)
// errors if y == 0
func parseHintDivInputs(inputs []*big.Int) (uint, *big.Int, *big.Int, error) {
	if len(inputs) < 2 {
		return 0, nil, nil, fmt.Errorf("at least 2 inputs required")
	}
	nbBits := uint(inputs[0].Uint64())
	nbLimbs := int(inputs[1].Int64())
	if len(inputs[2:]) < nbLimbs {
		return 0, nil, nil, fmt.Errorf("x limbs missing")
	}
	x, y := new(big.Int), new(big.Int)
	if err := recompose(inputs[2:2+nbLimbs], nbBits, x); err != nil {
		return 0, nil, nil, fmt.Errorf("recompose x: %w", err)
	}
	if err := recompose(inputs[2+nbLimbs:], nbBits, y); err != nil {
		return 0, nil, nil, fmt.Errorf("recompose y: %w", err)
	}
	if y.IsUint64() && y.Uint64() == 0 {
		return 0, nil, nil, fmt.Errorf("y == 0")
	}
	return nbBits, x, y, nil
}
