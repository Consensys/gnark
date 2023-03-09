package constraint

import (
	"fmt"
)

type LazyR1CS []LazyInputs

type LazyInputs interface {
	GetConstraintsNum() int
	GetLoc() int
	FetchLazy(r1cs R1CS, j int) R1C
}

type StaticConstraints struct {
	StaticR1CS                []R1C
	Begin                     int
	End                       int
	NbVariables               int
	InputConstraintsThreshold int
	InputLinearExpressions    *[]LinearExpression
}

type LazyIndexedInputs struct {
	Index     int
	LazyIndex int
}

func (l *LazyR1CS) GetConstraintsAll() int {
	sum := 0
	for _, v := range *l {
		sum += v.GetConstraintsNum()
	}
	return sum
}

type LazyInputsFactory func(constraints []R1C, loc int, constraintsNum int, paramsNum int, shift int) LazyInputs

var LazyInputsFactoryMap map[string]LazyInputsFactory

func init() {
	LazyInputsFactoryMap = make(map[string]LazyInputsFactory)
}

func Register(key string, factory LazyInputsFactory) {
	LazyInputsFactoryMap[key] = factory
}

func NewLazyInputs(key string, inputConstraints []R1C, loc int, constraintsNum int, paramsNum int, shift int) LazyInputs {
	if factory, exists := LazyInputsFactoryMap[key]; exists {
		return factory(inputConstraints, loc, constraintsNum, paramsNum, shift)
	} else {
		panic(fmt.Sprintf("can not read lazy inputs for %s, please Register first", key))
	}
}

func ComputeInputConstraintsThreshold(s []R1C, expressions *[]LinearExpression) int {
	threshold := 1
	tempMapInputs := make(map[uint32]bool)
	for _, expression := range *expressions {
		for _, eterm := range expression {
			tempMapInputs[eterm.VID] = true
		}
	}
	for i, expression := range s {
		var hasInput bool
		for _, term := range expression.L {
			hasInput = hasInput || tempMapInputs[term.VID]
		}
		for _, term := range expression.R {
			hasInput = hasInput || tempMapInputs[term.VID]
		}
		for _, term := range expression.O {
			hasInput = hasInput || tempMapInputs[term.VID]
		}
		if hasInput {
			threshold = i + 1
		}
	}
	return threshold
}
