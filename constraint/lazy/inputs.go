package lazy

import (
	"github.com/consensys/gnark/constraint"
)

type GeneralLazyInputs struct {
	// record the start location constraint
	Loc int

	// record the Shift from the static constraint
	Shift int

	// record the ParamsNum to differ
	ParamsNum int

	// reusing the constraints related to inputs
	InputConstraints []constraint.R1C

	// record the constraints num for every single lazy inputs
	ConstraintsNum int

	// the lazy inputs type, using to extract the static r1cs
	Key string
}

func (le *GeneralLazyInputs) GetConstraintsNum() int {
	return le.ConstraintsNum
}

func (le *GeneralLazyInputs) GetLoc() int {
	return le.Loc
}

func (le *GeneralLazyInputs) FetchLazy(r1cs constraint.R1CS, j int) constraint.R1C {
	staticR1cs := r1cs.GetStaticConstraints(le.Key).StaticR1CS

	if j < len(le.InputConstraints) {
		return le.InputConstraints[j]
	}

	resL := addShiftToTermsForExpression(staticR1cs[j].L, le.Shift)
	resR := addShiftToTermsForExpression(staticR1cs[j].R, le.Shift)
	resO := addShiftToTermsForExpression(staticR1cs[j].O, le.Shift)

	return constraint.R1C{
		L: resL,
		R: resR,
		O: resO,
	}
}

func addShiftToTermsForExpression(expression constraint.LinearExpression, shift int) constraint.LinearExpression {
	_expression := expression.Clone()
	for i := range _expression {
		if _expression[i].VID == 0 {
			continue
		}
		_expression[i].VID += uint32(shift)
	}
	return _expression
}

func createGeneralLazyInputsFunc(key string) func(inputs []constraint.R1C, loc int, constraintsNum int, paramsNum int, shift int) constraint.LazyInputs {
	return func(inputs []constraint.R1C, loc int, constraintsNum int, paramsNum int, shift int) constraint.LazyInputs {
		return &GeneralLazyInputs{
			InputConstraints: inputs,
			ParamsNum:        paramsNum,
			Loc:              loc,
			ConstraintsNum:   constraintsNum,
			Key:              key,
			Shift:            shift,
		}
	}
}
