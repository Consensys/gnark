package emulated

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
)

func (f *Field[T]) wrapHint(nonnativeInputs ...*Element[T]) []frontend.Variable {
	res := []frontend.Variable{f.fParams.BitsPerLimb(), f.fParams.NbLimbs()}
	res = append(res, f.Modulus().Limbs...)
	res = append(res, len(nonnativeInputs))
	for i := range nonnativeInputs {
		res = append(res, len(nonnativeInputs[i].Limbs))
		res = append(res, nonnativeInputs[i].Limbs...)
	}
	return res
}

func (f *Field[T]) wrapHintNatives(nativeInputs ...frontend.Variable) []frontend.Variable {
	res := []frontend.Variable{f.fParams.BitsPerLimb(), f.fParams.NbLimbs()}
	res = append(res, f.Modulus().Limbs...)
	res = append(res, nativeInputs...)
	return res
}

// UnwrapHint unwraps the native inputs into nonnative inputs. Then it calls
// nonnativeHint function with nonnative inputs. After nonnativeHint returns, it
// decomposes the outputs into limbs.
func UnwrapHint(nativeInputs, nativeOutputs []*big.Int, nonnativeHint solver.Hint) error {
	return unwrapHint(true, true, nativeInputs, nativeOutputs, nonnativeHint)
}

// UnwrapHintWithNativeOutput unwraps the native inputs into nonnative inputs. Then
// it calls nonnativeHint function with nonnative inputs. After nonnativeHint
// returns, it returns native outputs as-is.
func UnwrapHintWithNativeOutput(nativeInputs, nativeOutputs []*big.Int, nonnativeHint solver.Hint) error {
	return unwrapHint(true, false, nativeInputs, nativeOutputs, nonnativeHint)
}

// UnwrapHintWithNativeInput unwraps the native inputs into native inputs. Then
// it calls nonnativeHint function with native inputs. After nonnativeHint
// returns, it decomposes the outputs into limbs.
func UnwrapHintWithNativeInput(nativeInputs, nativeOutputs []*big.Int, nonnativeHint solver.Hint) error {
	return unwrapHint(false, true, nativeInputs, nativeOutputs, nonnativeHint)
}

func unwrapHint(isEmulatedInput, isEmulatedOutput bool, nativeInputs, nativeOutputs []*big.Int, nonnativeHint solver.Hint) error {
	if len(nativeInputs) < 2 {
		return errors.New("hint wrapper header is 2 elements")
	}
	if !nativeInputs[0].IsInt64() || !nativeInputs[1].IsInt64() {
		return errors.New("header must be castable to int64")
	}
	nbBits := int(nativeInputs[0].Int64())
	nbLimbs := int(nativeInputs[1].Int64())
	if len(nativeInputs) < 2+nbLimbs {
		return errors.New("hint wrapper header is 2+nbLimbs elements")
	}
	nonnativeMod := new(big.Int)
	if err := limbs.Recompose(nativeInputs[2:2+nbLimbs], uint(nbBits), nonnativeMod); err != nil {
		return fmt.Errorf("cannot recover nonnative mod: %w", err)
	}
	var nonnativeInputs []*big.Int
	if isEmulatedInput {
		if !nativeInputs[2+nbLimbs].IsInt64() {
			return errors.New("number of nonnative elements must be castable to int64")
		}
		nbInputs := int(nativeInputs[2+nbLimbs].Int64())
		readPtr := 3 + nbLimbs
		nonnativeInputs = make([]*big.Int, nbInputs)
		for i := 0; i < nbInputs; i++ {
			if len(nativeInputs) < readPtr+1 {
				return fmt.Errorf("can not read %d-th native input", i)
			}
			if !nativeInputs[readPtr].IsInt64() {
				return fmt.Errorf("corrupted %d-th native input", i)
			}
			currentInputLen := int(nativeInputs[readPtr].Int64())
			if len(nativeInputs) < (readPtr + 1 + currentInputLen) {
				return fmt.Errorf("cannot read %d-th nonnative element", i)
			}
			nonnativeInputs[i] = new(big.Int)
			if err := limbs.Recompose(nativeInputs[readPtr+1:readPtr+1+currentInputLen], uint(nbBits), nonnativeInputs[i]); err != nil {
				return fmt.Errorf("recompose %d-th element: %w", i, err)
			}
			readPtr += 1 + currentInputLen
		}
	} else {
		nbInputs := len(nativeInputs[2+nbLimbs:])
		readPtr := 2 + nbLimbs
		nonnativeInputs = make([]*big.Int, nbInputs)
		for i := 0; i < nbInputs; i++ {
			nonnativeInputs[i] = new(big.Int).Set(nativeInputs[readPtr+i])
		}
	}

	var nonnativeOutputs []*big.Int
	if isEmulatedOutput {
		if len(nativeOutputs)%nbLimbs != 0 {
			return errors.New("output count doesn't divide limb count")
		}
		nonnativeOutputs = make([]*big.Int, len(nativeOutputs)/nbLimbs)
	} else {
		nonnativeOutputs = make([]*big.Int, len(nativeOutputs))
	}
	for i := range nonnativeOutputs {
		nonnativeOutputs[i] = new(big.Int)
	}
	if err := nonnativeHint(nonnativeMod, nonnativeInputs, nonnativeOutputs); err != nil {
		return fmt.Errorf("nonnative hint: %w", err)
	}
	if isEmulatedOutput {
		for i := range nonnativeOutputs {
			nonnativeOutputs[i].Mod(nonnativeOutputs[i], nonnativeMod)
			if err := limbs.Decompose(nonnativeOutputs[i], uint(nbBits), nativeOutputs[i*nbLimbs:(i+1)*nbLimbs]); err != nil {
				return fmt.Errorf("decompose %d-th element: %w", i, err)
			}
		}
	} else {
		for i := range nonnativeOutputs {
			nativeOutputs[i].Set(nonnativeOutputs[i])
		}
	}
	return nil
}

// NewHint allows to call the emulation hint function hf on inputs, expecting
// nbOutputs results. This function splits internally the emulated element into
// limbs and passes these to the hint function. There is [UnwrapHint] function
// which performs corresponding recomposition of limbs into integer values (and
// vice verse for output).
//
// The hint function for this method is defined as:
//
//	func HintFn(mod *big.Int, inputs, outputs []*big.Int) error {
//	    return emulated.UnwrapHint(inputs, outputs, func(mod *big.Int, inputs, outputs []*big.Int) error { // NB we shadow initial input, output, mod to avoid accidental overwrite!
//		    // here all inputs and outputs are modulo nonnative mod. we decompose them automatically
//	    })}
//
// See the example for full written example.
func (f *Field[T]) NewHint(hf solver.Hint, nbOutputs int, inputs ...*Element[T]) ([]*Element[T], error) {
	// we need to initialize the inputs before to ensure the constant values are decomposed
	// into limbs. If inputs are already initialize, then it is no-op.
	for i := range inputs {
		inputs[i].Initialize(f.api.Compiler().Field())
	}
	nativeInputs := f.wrapHint(inputs...)
	nbNativeOutputs := int(f.fParams.NbLimbs()) * nbOutputs
	nativeOutputs, err := f.api.Compiler().NewHint(hf, nbNativeOutputs, nativeInputs...)
	if err != nil {
		return nil, fmt.Errorf("call hint: %w", err)
	}
	outputs := make([]*Element[T], nbOutputs)
	for i := 0; i < nbOutputs; i++ {
		outputs[i] = f.packLimbs(nativeOutputs[i*int(f.fParams.NbLimbs()):(i+1)*int(f.fParams.NbLimbs())], true)
	}
	return outputs, nil
}

// NewHintWithNativeOutput allows to call the emulation hint function hf on
// nonnative inputs, expecting nbOutputs results. This function splits
// internally the emulated element into limbs and passes these to the hint
// function. There is [UnwrapHintWithNativeOutput] function which performs
// corresponding recomposition of limbs into integer values (and vice verse for
// output).
//
// This method is an alternation of [NewHint] method, which allows to pass
// nonnative inputs to the hint function and returns native outputs. This is
// useful when the outputs do not necessarily have to be emulated elements (e.g.
// bits) as it skips enforcing range checks on the outputs.
//
// The hint function for this method is defined as:
//
//	func HintFn(nativeMod *big.Int, inputs, outputs []*big.Int) error {
//	    return emulated.UnwrapHintWithNativeOutput(inputs, outputs, func(emulatedMod *big.Int, inputs, outputs []*big.Int) error {
//	        // in the function we have access to both native and nonantive modulus
//	    })}
func (f *Field[T]) NewHintWithNativeOutput(hf solver.Hint, nbOutputs int, inputs ...*Element[T]) ([]frontend.Variable, error) {
	// we need to initialize the inputs before to ensure the constant values are decomposed
	// into limbs. If inputs are already initialize, then it is no-op.
	for i := range inputs {
		inputs[i].Initialize(f.api.Compiler().Field())
	}
	nativeInputs := f.wrapHint(inputs...)
	nbNativeOutputs := nbOutputs
	nativeOutputs, err := f.api.Compiler().NewHint(hf, nbNativeOutputs, nativeInputs...)
	if err != nil {
		return nil, fmt.Errorf("call hint: %w", err)
	}
	return nativeOutputs, nil
}

// NewHintWithNativeInput allows to call the emulation hint function hf on
// native inputs, expecting nbOutputs results. This function passes the native
// inputs to the hint function directly and reconstructs the outputs into
// non-native elements. There is [UnwrapHintWithNativeInput] function which
// performs corresponding recomposition of limbs into integer values (and vice
// verse for output).
//
// This method is an alternation of [NewHint] method, which allows to pass
// native inputs to the hint function and returns nonnative outputs. This is
// useful when the inputs do not necessarily have to be emulated elements (e.g.
// indices) and allows to work between different fields.
//
// The hint function for this method is defined as:
//
//	func HintFn(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
//	    return emulated.UnwrapHintWithNativeInput(nativeInputs, nativeOutputs, func(emulatedMod *big.Int, inputs, outputs []*big.Int) error {
//	        // in the function we have access to both native and nonantive modulus
//	    })}
func (f *Field[T]) NewHintWithNativeInput(hf solver.Hint, nbOutputs int, inputs ...frontend.Variable) ([]*Element[T], error) {
	nativeInputs := f.wrapHintNatives(inputs...)
	nbNativeOutputs := int(f.fParams.NbLimbs()) * nbOutputs
	nativeOutputs, err := f.api.Compiler().NewHint(hf, nbNativeOutputs, nativeInputs...)
	if err != nil {
		return nil, fmt.Errorf("call hint: %w", err)
	}
	outputs := make([]*Element[T], nbOutputs)
	for i := 0; i < nbOutputs; i++ {
		outputs[i] = f.packLimbs(nativeOutputs[i*int(f.fParams.NbLimbs()):(i+1)*int(f.fParams.NbLimbs())], true)
	}
	return outputs, nil
}

type hintContextField struct {
	Modulus *big.Int
	Inputs  []*big.Int
	Outputs []*big.Int

	// nbLimbs and nbBits are used to store the default number of limbs and bits
	// for non-native context.
	nbLimbs, nbBits int
	// native indicates if this is a context for native field
	native bool
}

// HintContext contains context for the emulated hint. It allows to access the
// inputs and outputs for the given field modulus (native and emulated).
type HintContext []hintContextField

// InputsOutputs returns the inputs and outputs for the given field. If there
// are no inputs for given field, then returns nil.
//
// As we return reference to the inputs and outputs, it is expected that the
// hint does not modify the inputs and assigns values to the outputs using
// [big.Int.Set] method.
//
// To access the native field inputs and outputs, pass nil as the field
// argument.
func (hi HintContext) InputsOutputs(field *big.Int) (inputs []*big.Int, outputs []*big.Int) {
	if len(hi) == 0 {
		return nil, nil
	}
	for _, input := range hi {
		if field == nil && input.native {
			// if the given field is nil and it is the native context, then we return it.
			// This is due to the backwards compatibility promise where we don't have
			// access to the native field modulus and assume it being nil.
			return input.Inputs, input.Outputs
		}
		if input.Modulus == nil {
			// if the context modulus is nil, then it is from the backwards
			// compatibility promise. This shouldn't happen in new code. But for
			// now we cannot compare it against the search value.
			continue
		}
		if field != nil && input.Modulus.Cmp(field) == 0 {
			return input.Inputs, input.Outputs
		}
	}
	return nil, nil
}

// Moduli returns all moduli for which there are inputs or outputs in the
// context. If there are no inputs or outputs, then returns nil.
func (hi HintContext) Moduli() []*big.Int {
	if len(hi) == 0 {
		return nil
	}
	moduli := make([]*big.Int, len(hi))
	for i, input := range hi {
		moduli[i] = input.Modulus
	}
	return moduli
}

// wrapGenericHintInputs wraps the inputs for different fields into a slice
// which can be passed into the native hint calling mechanism. To unwrap, use
// the [unwrapGenericHintOutputs] function.
func wrapGenericHintInputs[T1, T2 FieldParams](nativeField *big.Int, nbNativeOutputs, nbEmulated1Outputs, nbEmulated2Outputs int,
	nativeInputs []frontend.Variable,
	emulated1Inputs []*Element[T1],
	emulated2Inputs []*Element[T2],
) (wrappedInputs []frontend.Variable, nbOutputs int, err error) {
	// packing:
	//  - nbNativeInputs
	//  - nbNativeOutputs
	//  - nbEmulated1Inputs
	//  - nbEmulated1Outputs
	//  - nbEmulated2Inputs
	//  - nbEmulated2Outputs
	//  - native inputs
	//  - nbLimbs for T1
	//  - nbBits for T1
	//  - modulus for T1 (limb decomposition)
	//  - emulated1 inputs (for every input: nbLimbs || limb decomposition)
	//  - nbLimbs for T2
	//  - nbBits for T2
	//  - modulus for T2
	//  - emulated2 inputs (for every input: nbLimbs || limb decomposition)
	effNbLimbs1, effNbBits1 := GetEffectiveFieldParams[T1](nativeField)
	effNbLimbs2, effNbBits2 := GetEffectiveFieldParams[T2](nativeField)
	var t1 T1
	var t2 T2
	mod1Limbs := make([]*big.Int, effNbLimbs1)
	for i := range mod1Limbs {
		mod1Limbs[i] = new(big.Int)
	}
	mod2Limbs := make([]*big.Int, effNbLimbs2)
	for i := range mod2Limbs {
		mod2Limbs[i] = new(big.Int)
	}
	if err := limbs.Decompose(t1.Modulus(), uint(effNbBits1), mod1Limbs); err != nil {
		return nil, 0, fmt.Errorf("decompose modulus for T1: %w", err)
	}
	if err := limbs.Decompose(t2.Modulus(), uint(effNbBits2), mod2Limbs); err != nil {
		return nil, 0, fmt.Errorf("decompose modulus for T2: %w", err)
	}
	wrappedInputs = []frontend.Variable{
		len(nativeInputs),
		nbNativeOutputs,
		len(emulated1Inputs),
		nbEmulated1Outputs,
		len(emulated2Inputs),
		nbEmulated2Outputs,
	}
	wrappedInputs = append(wrappedInputs, nativeInputs...)
	if len(emulated1Inputs) > 0 || nbEmulated1Outputs > 0 {
		wrappedInputs = append(wrappedInputs, effNbLimbs1, effNbBits1)
		for i := range mod1Limbs {
			wrappedInputs = append(wrappedInputs, mod1Limbs[i])
		}
	}
	for i := range emulated1Inputs {
		if emulated1Inputs[i] == nil {
			return nil, 0, fmt.Errorf("nil emulated1 input at index %d", i)
		}
		wrappedInputs = append(wrappedInputs, len(emulated1Inputs[i].Limbs))
		wrappedInputs = append(wrappedInputs, emulated1Inputs[i].Limbs...)
	}
	if len(emulated2Inputs) > 0 || nbEmulated2Outputs > 0 {
		wrappedInputs = append(wrappedInputs, effNbLimbs2, effNbBits2)
		for i := range mod2Limbs {
			wrappedInputs = append(wrappedInputs, mod2Limbs[i])
		}
	}
	for i := range emulated2Inputs {
		if emulated2Inputs[i] == nil {
			return nil, 0, fmt.Errorf("nil emulated2 input at index %d", i)
		}
		wrappedInputs = append(wrappedInputs, len(emulated2Inputs[i].Limbs))
		wrappedInputs = append(wrappedInputs, emulated2Inputs[i].Limbs...)
	}
	nbOutputs = nbNativeOutputs + nbEmulated1Outputs*int(effNbLimbs1) + nbEmulated2Outputs*int(effNbLimbs2)
	return wrappedInputs, nbOutputs, nil
}

// unwrapGenericHintOutputs unwraps the wrapped outputs from the hint function
// into elements of different fields.
func unwrapGenericHintOutputs[T1, T2 FieldParams](field *big.Int, fp1 *Field[T1], fp2 *Field[T2],
	nbNativeOutputs, nbEmulated1Outputs, nbEmulated2Outputs int,
	hintOutputs []frontend.Variable,
) (nativeOutputs []frontend.Variable, emulated1Outputs []*Element[T1], emulated2Outputs []*Element[T2], err error) {
	effNbLimbs1, _ := GetEffectiveFieldParams[T1](field)
	effNbLimbs2, _ := GetEffectiveFieldParams[T2](field)
	nbExpectedOutputs := nbNativeOutputs + nbEmulated1Outputs*int(effNbLimbs1) + nbEmulated2Outputs*int(effNbLimbs2)
	if len(hintOutputs) != nbExpectedOutputs {
		return nil, nil, nil, fmt.Errorf("hint outputs length mismatch: expected %d, got %d", nbExpectedOutputs, len(hintOutputs))
	}
	nativeOutputs = hintOutputs[:nbNativeOutputs]
	if nbEmulated1Outputs > 0 {
		if fp1 == nil {
			return nil, nil, nil, errors.New("nil emulated1 field")
		}
		emulated1Outputs = make([]*Element[T1], nbEmulated1Outputs)
		for i := range nbEmulated1Outputs {
			limbs := hintOutputs[nbNativeOutputs+i*int(effNbLimbs1) : nbNativeOutputs+(i+1)*int(effNbLimbs1)]
			emulated1Outputs[i] = fp1.packLimbs(limbs, true)
		}
	}
	if nbEmulated2Outputs > 0 {
		if fp2 == nil {
			return nil, nil, nil, errors.New("nil emulated2 field")
		}
		emulated2Outputs = make([]*Element[T2], nbEmulated2Outputs)
		for i := range nbEmulated2Outputs {
			limbs := hintOutputs[nbNativeOutputs+nbEmulated1Outputs*int(effNbLimbs1)+i*int(effNbLimbs2) : nbNativeOutputs+nbEmulated1Outputs*int(effNbLimbs1)+(i+1)*int(effNbLimbs2)]
			emulated2Outputs[i] = fp2.packLimbs(limbs, true)
		}
	}
	return nativeOutputs, emulated1Outputs, emulated2Outputs, nil
}

// Hint is a non-native hint function which takes a [HintContext] as an argument
// which allows to access inputs and outputs over different fields.
//
// It is not directly passed as an argument to the hint calling methods which
// expect [solver.Hint] type. So, the user would have to define the hint
// function as [solver.Hint] and then use [UnwrapHintContext] to obtain the
// [HintContext]. It is due to the fact that we use native API hint calling
// mechanism which expects [solver.Hint] type.
//
// For example, the user could define the hint function as follows:
//
//	func MyHintFn(mod *big.Int, inputs, outputs []*big.Int) error { // this is [solver.Hint] type
//	    return emulated.UnwrapHintContext(mod, inputs, outputs, func(hc emulated.HintContext) error { // this is [Hint] type
//	        // here we can access inputs and outputs for the given field modulus
//	        // and perform the hint logic.
//	        // For example, we can access the native inputs and outputs as follows:
//	        nativeInputs, nativeOutputs := hc.InputsOutputs(mod)
//	        // and emulated inputs and outputs as follows:
//	        moduli := hc.Moduli()
//	        emulatedInputs, emulatedOutputs := hc.InputsOutputs(moduli[1]) // moduli[0] is the native field modulus
//	        // then we can perform the hint logic using nativeInputs, nativeOutputs,
//	        // emulatedInputs and emulatedOutputs.
//	        // Finally, we can assign the outputs using big.Int.Set method:
//	        for i, output := range nativeOutputs {
//	            output.Set(someValue) // someValue is the value we want to assign to the output
//	        }
//	        for i, output := range emulatedOutputs {
//	            output.Set(someEmulatedValue) // someEmulatedValue is the value we want to assign to the output
//	        }
//	        return nil
//	    })
//	}
type Hint func(HintContext) error

// NewHintGeneric is a generic hint function which allows to call the hint
// function with mixed native and emulated inputs and outputs. It wraps
// everything so that it can be passed without overflowing the native field.
//
// In the hint function, the user should unwrap the inputs and outputs using
// [UnwrapHintContext] function.
//
// The hint function hf is expected to be of type [solver.Hint], but it should
// unwrap the inputs and outputs into [HintContext] type. As an example, the
// user could define the hint function as follows:
//
//	func MyHintFn(mod *big.Int, inputs, outputs []*big.Int) error {
//	    return emulated.UnwrapHintContext(mod, inputs, outputs, func(hc emulated.HintContext) error {
//	         // here we can use hc to access inputs and outputs for the given field modulus
//	    })
//	}
func (f *Field[T]) NewHintGeneric(hf solver.Hint, nbNativeOutputs, nbEmulatedOutputs int, nativeInputs []frontend.Variable, nonNativeInputs []*Element[T]) ([]frontend.Variable, []*Element[T], error) {
	for i := range nonNativeInputs {
		nonNativeInputs[i].Initialize(f.api.Compiler().Field())
	}
	wrappedInputs, nbOutputs, err := wrapGenericHintInputs[T, T](f.api.Compiler().Field(), nbNativeOutputs, nbEmulatedOutputs, 0, nativeInputs, nonNativeInputs, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("wrap generic hint context: %w", err)
	}
	outputs, err := f.api.Compiler().NewHint(hf, nbOutputs, wrappedInputs...)
	if err != nil {
		return nil, nil, fmt.Errorf("call hint: %w", err)
	}
	nres, em1res, em2res, err := unwrapGenericHintOutputs[T, T](f.api.Compiler().Field(), f, nil, nbNativeOutputs, nbEmulatedOutputs, 0, outputs)
	if err != nil {
		return nil, nil, fmt.Errorf("unwrap generic hint context: %w", err)
	}
	if len(em2res) != 0 {
		return nil, nil, errors.New("generic hint returned non-empty outputs for second emulated field")
	}
	return nres, em1res, nil
}

// UnwrapHintContext unwraps the nativeInputs and nativeOutputs into
// [HintContext] for field-specific inputs/outputs and passes it as an argument
// to the genericHint function. It is expected that the caller has called either
// [Field.NewHintGeneric] or [NewVarGenericHint] which performs standard wrapping.
//
// We also provide backwards compatibility with other hint calling and
// unwrapping functions. This means that when calling these functions, the
// native inputs can be unwrapped using this method. Otherwise, the caller can
// also call the backwards-compatible methods directly:
//   - [UnwrapHint] for [Field.NewHint]
//   - [UnwrapHintWithNativeOutput] for [Field.NewHintWithNativeOutput]
//   - [UnwrapHintWithNativeInput] for [Field.NewHintWithNativeInput]
func UnwrapHintContext(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int, genericHint Hint) error {
	// TODO: use pools for inputs and outputs to avoid allocations
	if len(nativeInputs) < 6 {
		return fmt.Errorf("hint wrapper header is 6 elements, got %d", len(nativeInputs))
	}
	for i := range 6 {
		if !nativeInputs[i].IsInt64() {
			return fmt.Errorf("header element %d must be castable to int64", i)
		}
	}
	nbNativeInputs := int(nativeInputs[0].Int64())
	nbNativeOutputs := int(nativeInputs[1].Int64())
	nbEmulated1Inputs := int(nativeInputs[2].Int64())
	nbEmulated1Outputs := int(nativeInputs[3].Int64())
	nbEmulated2Inputs := int(nativeInputs[4].Int64())
	nbEmulated2Outputs := int(nativeInputs[5].Int64())

	ptr := 6
	var hctx HintContext
	if nbNativeInputs > 0 || nbNativeOutputs > 0 {
		if len(nativeInputs) < ptr+nbNativeInputs {
			return fmt.Errorf("not enough native inputs, expected %d, got %d", ptr+nbNativeInputs, len(nativeInputs))
		}
		nhctx := hintContextField{
			Modulus: nativeMod,
			Inputs:  nativeInputs[ptr : ptr+nbNativeInputs],
			Outputs: make([]*big.Int, nbNativeOutputs),
			native:  true,
		}
		ptr += nbNativeInputs
		for i := range nhctx.Outputs {
			nhctx.Outputs[i] = new(big.Int)
		}
		hctx = append(hctx, nhctx)
	}
	decomposeEmulated := func(nbEmulatedInputs, nbEmulatedOutputs int) error {
		if nbEmulatedInputs > 0 || nbEmulatedOutputs > 0 {
			if len(nativeInputs) < ptr+nbEmulatedInputs+2 {
				return fmt.Errorf("not enough emulated inputs, expected %d, got %d", ptr+nbEmulatedInputs+2, len(nativeInputs))
			}
			if !nativeInputs[ptr].IsInt64() || !nativeInputs[ptr+1].IsInt64() {
				return fmt.Errorf("emulated header elements must be castable to int64, got %v and %v", nativeInputs[ptr], nativeInputs[ptr+1])
			}
			nbLimbs := int(nativeInputs[ptr].Int64())
			nbBits := int(nativeInputs[ptr+1].Int64())
			ptr += 2
			if len(nativeInputs) < ptr+nbLimbs {
				return fmt.Errorf("not enough emulated modulus limbs, expected %d, got %d", ptr+nbLimbs, len(nativeInputs))
			}
			modEm := new(big.Int)
			if err := limbs.Recompose(nativeInputs[ptr:ptr+nbLimbs], uint(nbBits), modEm); err != nil {
				return fmt.Errorf("recompose emulated modulus: %w", err)
			}
			ptr += nbLimbs
			nhctx := hintContextField{
				Modulus: modEm,
				Inputs:  make([]*big.Int, nbEmulatedInputs),
				Outputs: make([]*big.Int, nbEmulatedOutputs),
				nbLimbs: nbLimbs,
				nbBits:  nbBits,
			}
			for i := range nhctx.Inputs {
				if len(nativeInputs) < ptr+1 {
					return fmt.Errorf("not enough emulated inputs, expected %d, got %d", ptr+1, len(nativeInputs))
				}
				if !nativeInputs[ptr].IsInt64() {
					return fmt.Errorf("emulated input %d must be castable to int64, got %v", i, nativeInputs[ptr])
				}
				currentInputLen := int(nativeInputs[ptr].Int64())
				ptr++
				if len(nativeInputs) < ptr+currentInputLen {
					return fmt.Errorf("not enough emulated input limbs, expected %d, got %d", ptr+currentInputLen, len(nativeInputs))
				}
				nhctx.Inputs[i] = new(big.Int)
				if err := limbs.Recompose(nativeInputs[ptr:ptr+currentInputLen], uint(nbBits), nhctx.Inputs[i]); err != nil {
					return fmt.Errorf("recompose emulated input %d: %w", i, err)
				}
				ptr += currentInputLen
			}
			for i := range nhctx.Outputs {
				nhctx.Outputs[i] = new(big.Int)
			}
			hctx = append(hctx, nhctx)
		}
		return nil
	}
	if err := decomposeEmulated(nbEmulated1Inputs, nbEmulated1Outputs); err != nil {
		return fmt.Errorf("decompose emulated1 inputs/outputs: %w", err)
	}
	if err := decomposeEmulated(nbEmulated2Inputs, nbEmulated2Outputs); err != nil {
		return fmt.Errorf("decompose emulated2 inputs/outputs: %w", err)
	}
	if ptr != len(nativeInputs) {
		return fmt.Errorf("not all native inputs were consumed, expected %d, got %d", len(nativeInputs), ptr)
	}
	if err := genericHint(hctx); err != nil {
		return fmt.Errorf("call generic hint: %w", err)
	}
	if len(nativeOutputs) < nbNativeOutputs {
		return fmt.Errorf("not enough native outputs, expected %d, got %d", nbNativeOutputs, len(nativeOutputs))
	}
	_, hnout := hctx.InputsOutputs(nativeMod)
	if len(hnout) != nbNativeOutputs {
		return fmt.Errorf("hint outputs length mismatch: expected %d, got %d", nbNativeOutputs, len(hnout))
	}
	outPtr := 0
	for i := range hnout {
		nativeOutputs[i].Set(hnout[i])
	}
	outPtr += nbNativeOutputs
	for i := range hctx {
		if hctx[i].native {
			// skip native field, it is already processed
			continue
		}
		for j := range hctx[i].Outputs {
			if outPtr >= len(nativeOutputs) {
				return fmt.Errorf("not enough native outputs for emulated field %d, expected %d, got %d", i+1, len(hctx[i].Outputs), len(nativeOutputs))
			}
			if err := limbs.Decompose(hctx[i].Outputs[j], uint(hctx[i].nbBits), nativeOutputs[outPtr:outPtr+hctx[i].nbLimbs]); err != nil {
				return fmt.Errorf("decompose emulated output %d for field %d: %w", j, i+1, err)
			}
			outPtr += hctx[i].nbLimbs
		}
	}
	if outPtr != len(nativeOutputs) {
		return fmt.Errorf("not all native outputs were consumed, expected %d, got %d", len(nativeOutputs), outPtr)
	}
	return nil
}

// NewVarGenericHint allows to call a hint function operating over native and
// two emulated fields. It is useful in the context where the hint needs to get
// inputs from several different fields or return outputs in different fields.
//
// The hint function hf received as an input wrapped inputs and it should unwrap
// it using [UnwrapHintContext] function. For example:
//
//	func hint(mod *big.Int, inputs, outputs []*big.Int) error {
//	    return emulated.UnwrapHintContext(mod, inputs, outputs, func(hctx emulated.HintContext) error {
//	        // here we can access inputs and outputs for each field
//	        // and perform operations on them
//
//	        // to get the moduli for the fields we can do:
//	        moduli := hctx.Moduli()
//	        // now we can access inputs and outputs for each field
//	        nativeInputs, nativeOutputs := hctx.InputsOutputs(moduli[0])
//	        emulated1Inputs, emulated1Outputs := hctx.InputsOutputs(moduli[1])
//	        emulated2Inputs, emulated2Outputs := hctx.InputsOutputs(moduli[2])
//
//	        // now we perform operations on the inputs and outputs and then we set the outputs
//	        // using big.Int.Set method, e.g.:
//	        for i := range nativeOutputs {
//	            nativeOutputs[i].Set(nativeInputs[i].Mul(nativeInputs[i], big.NewInt(2)))
//	        }
//	        for i := range emulated1Outputs {
//	            emulated1Outputs[i].Set(emulated1Inputs[i].Mul(emulated1Inputs[i], big.NewInt(2)))
//	        }
//	        for i := range emulated2Outputs {
//	            emulated2Outputs[i].Set(emulated2Inputs[i].Mul(emulated2Inputs[i], big.NewInt(2)))
//	        }
//	        return nil
//	    })
//	}
func NewVarGenericHint[T1, T2 FieldParams](
	api frontend.API,
	nbNativeOutputs, nbEmulated1Outputs, nbEmulated2Outputs int,
	nativeInputs []frontend.Variable,
	emulated1Inputs []*Element[T1],
	emulated2Inputs []*Element[T2],
	hf solver.Hint,
) (nativeOutputs []frontend.Variable, emulated1Outputs []*Element[T1], emulated2Outputs []*Element[T2], err error) {
	fp1, err := NewField[T1](api)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create emulated1 field: %w", err)
	}
	fp2, err := NewField[T2](api)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create emulated2 field: %w", err)
	}
	nativeField := api.Compiler().Field()
	wrappedInputs, nbOutputs, err := wrapGenericHintInputs(nativeField, nbNativeOutputs, nbEmulated1Outputs, nbEmulated2Outputs, nativeInputs, emulated1Inputs, emulated2Inputs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("wrap generic hint inputs: %w", err)
	}
	outputs, err := api.Compiler().NewHint(hf, nbOutputs, wrappedInputs...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("call hint: %w", err)
	}
	return unwrapGenericHintOutputs(nativeField, fp1, fp2,
		nbNativeOutputs, nbEmulated1Outputs, nbEmulated2Outputs,
		outputs)
}
