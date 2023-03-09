package lazy

import (
	"github.com/consensys/gnark/constraint"
)

type GeneralLazyInputs struct {
	// record the start location constraint
	loc int

	// record the shift from the static constraint
	shift int

	// record the paramsNum to differ
	paramsNum int

	// reusing the constraints related to inputs
	inputConstraints []constraint.R1C

	// record the constraints num for every single lazy inputs
	constraintsNum int

	// the lazy inputs type, using to extract the static r1cs
	key string
}

func (le *GeneralLazyInputs) GetConstraintsNum() int {
	return le.constraintsNum
}

func (le *GeneralLazyInputs) GetLoc() int {
	return le.loc
}

func (le *GeneralLazyInputs) FetchLazy(r1cs constraint.R1CS, j int) constraint.R1C {
	staticR1cs := r1cs.GetStaticConstraints(le.key).StaticR1CS

	if j < len(le.inputConstraints) {
		return le.inputConstraints[j]
	}

	resL := addShiftToTermsForExpression(staticR1cs[j].L, le.shift)
	resR := addShiftToTermsForExpression(staticR1cs[j].R, le.shift)
	resO := addShiftToTermsForExpression(staticR1cs[j].O, le.shift)

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
			inputConstraints: inputs,
			paramsNum:        paramsNum,
			loc:              loc,
			constraintsNum:   constraintsNum,
			key:              key,
			shift:            shift,
		}
	}
}
