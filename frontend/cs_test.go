package frontend

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/backend/r1cs/r1c"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/commands"
	"github.com/leanovate/gopter/gen"
)

var variableName big.Int

// csState holds information on the expected state of a cs (commands.State)
type csState struct {
	nbPublicVariables   int
	nbSecretVariables   int
	nbInternalVariables int
	nbConstraints       int
	nbAssertions        int
}

// deltaState holds the difference between the next state (after calling a function from the API) and the previous one
type deltaState = csState

// contains information about a constraint system after a gnark function has been called
type csResult struct {
	cs                *ConstraintSystem // constraint system after it has been modified using gnark API
	publicVariables   []Variable        // public variables created after calling a run function
	secretVariables   []Variable        // secret variables created aftrer calling a run funcion
	internalVariables []Variable        // variables resulting of the function call (from cs.Add, cs.Mul, etc)
	solver            r1c.SolvingMethod // according to the solving method, different features are checked
}

type runfunc func(systemUnderTest commands.SystemUnderTest) commands.Result
type nextstatefunc func(state commands.State) commands.State

// the names of the public/secret inputs are variableName.String()
func incVariableName() {
	variableName.Add(&variableName, bOne)
}

// ------------------------------------------------------------------------------
// util functions

func buildProtoCommands(name string, rf runfunc, ns nextstatefunc) *commands.ProtoCommand {
	return &commands.ProtoCommand{
		Name:              name,
		RunFunc:           rf,
		NextStateFunc:     ns,
		PostConditionFunc: postConditionAPI,
	}
}

func checkPublicVariables(csRes csResult) bool {
	for i, args := range csRes.publicVariables {
		expectedID := len(csRes.cs.publicVariables) - len(csRes.publicVariables) + i
		if args.val != nil || args.id != expectedID {
			return false
		}
	}
	return true
}

func checkSecretVariables(csRes csResult) bool {
	for i, args := range csRes.secretVariables {
		expectedID := len(csRes.cs.secretVariables) - len(csRes.secretVariables) + i
		if args.val != nil || args.id != expectedID {
			return false
		}
	}
	return true
}

func checkInternalVariables(csRes csResult) bool {
	for i, args := range csRes.internalVariables {
		expectedID := len(csRes.cs.internalVariables) - len(csRes.internalVariables) + i
		if args.val != nil || args.id != expectedID {
			return false
		}
	}
	return true
}

// ------------------------------------------------------------------------------
// post condition should hold when applying a function on the system

func postConditionAPI(state commands.State, result commands.Result) *gopter.PropResult {
	st := state.(*csState)
	csRes := result.(csResult)

	var witness bool

	// check IDs of the created variables
	witness = checkPublicVariables(csRes)
	if !witness {
		return &gopter.PropResult{Status: gopter.PropFalse}
	}

	witness = checkSecretVariables(csRes)
	if !witness {
		return &gopter.PropResult{Status: gopter.PropFalse}
	}

	witness = checkInternalVariables(csRes)
	if !witness {
		return &gopter.PropResult{Status: gopter.PropFalse}
	}

	// checks the state of the constraint system
	if len(csRes.cs.publicVariableNames) != st.nbPublicVariables ||
		len(csRes.cs.publicVariables) != st.nbPublicVariables ||
		len(csRes.cs.secretVariableNames) != st.nbSecretVariables ||
		len(csRes.cs.secretVariables) != st.nbSecretVariables ||
		len(csRes.cs.internalVariables) != st.nbInternalVariables ||
		len(csRes.cs.constraints) != st.nbConstraints ||
		len(csRes.cs.assertions) != st.nbAssertions {
		return &gopter.PropResult{Status: gopter.PropFalse}
	}
	return &gopter.PropResult{Status: gopter.PropTrue}
}

// ------------------------------------------------------------------------------
// list of run functions

// Add several variables
func rfAddVariablesOnly() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		pVariablesCreated = append(pVariablesCreated, a)
		incVariableName()

		b := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		sVariablesCreated = append(sVariablesCreated, b)
		incVariableName()

		c := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		sVariablesCreated = append(sVariablesCreated, c)
		incVariableName()

		d := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		sVariablesCreated = append(sVariablesCreated, d)
		incVariableName()

		v := systemUnderTest.(*ConstraintSystem).Add(a, b, c, d)
		iVariablesCreated = append(iVariablesCreated, v)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsAddVariablesOnly = deltaState{1, 3, 1, 1, 0} // ex: after calling add, we should have 1 public variable, 1 secret variable, 1 internal variable and 1 constraint more in the cs

// Add variables and constant
func rfAddVariablesConstants() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		pVariablesCreated = append(pVariablesCreated, a)
		incVariableName()

		b := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		sVariablesCreated = append(sVariablesCreated, b)
		incVariableName()

		v := systemUnderTest.(*ConstraintSystem).Add(a, b, 3, 4)
		iVariablesCreated = append(iVariablesCreated, v)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsAddVariablesConstants = csState{1, 1, 1, 1, 0}

// Add constants only
func rfAddConstantsOnly() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		v := systemUnderTest.(*ConstraintSystem).Add(4, 3, 2, 1)
		iVariablesCreated = append(iVariablesCreated, v)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsAddConstantsOnly = deltaState{0, 0, 1, 1, 0}

// sub 2 variables
func rfSubVariablesOnly() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		b := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		sVariablesCreated = append(sVariablesCreated, b)
		incVariableName()

		v := systemUnderTest.(*ConstraintSystem).Sub(a, b)
		iVariablesCreated = append(iVariablesCreated, v)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsSubVariablesOnly = deltaState{1, 1, 1, 1, 0}

// sub Variable and a constant
func rfSubVariableConstant() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		v := systemUnderTest.(*ConstraintSystem).Sub(a, 3)
		iVariablesCreated = append(iVariablesCreated, v)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsSubVariableConstant = deltaState{1, 0, 1, 1, 0}

// sub Constant and a variable
func rfSubConstantVariables() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		v := systemUnderTest.(*ConstraintSystem).Sub(3, a)
		iVariablesCreated = append(iVariablesCreated, v)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsSubConstantVariable = deltaState{1, 0, 1, 1, 0}

// sub Constants only
func rfSubConstantsOnly() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		v := systemUnderTest.(*ConstraintSystem).Sub(3, 4)
		iVariablesCreated = append(iVariablesCreated, v)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsSubConstantsOnly = deltaState{0, 0, 1, 1, 0}

// mul variables
func rfMulVariablesOnly() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		b := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		sVariablesCreated = append(sVariablesCreated, b)

		c := systemUnderTest.(*ConstraintSystem).Mul(a, a, a, b, b)

		iVariablesCreated = append(iVariablesCreated, c)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsMulVariablesOnly = csState{1, 1, 4, 4, 0}

// mul variables and constants
func rfMulVariablesConstants() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		b := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		sVariablesCreated = append(sVariablesCreated, b)

		c := systemUnderTest.(*ConstraintSystem).Mul(a, b)
		iVariablesCreated = append(iVariablesCreated, c)

		d := systemUnderTest.(*ConstraintSystem).Mul(a, 3)
		iVariablesCreated = append(iVariablesCreated, d)

		e := systemUnderTest.(*ConstraintSystem).Mul(d, 4)
		iVariablesCreated = append(iVariablesCreated, e)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsMulVariablesConstants = deltaState{1, 1, 3, 3, 0}

// mul constants only
func rfMulConstantsOnly() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).Mul(3, 3)
		iVariablesCreated = append(iVariablesCreated, a)

		b := systemUnderTest.(*ConstraintSystem).Mul(4, 6)
		iVariablesCreated = append(iVariablesCreated, b)

		c := systemUnderTest.(*ConstraintSystem).Mul(2, 4)
		iVariablesCreated = append(iVariablesCreated, c)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsMulConstantsOnly = deltaState{0, 0, 3, 3, 0}

// mul linear expressions
func rfMulLinearExpressions() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		b := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		sVariablesCreated = append(sVariablesCreated, b)

		c := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, c)

		d := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		sVariablesCreated = append(sVariablesCreated, d)

		l := systemUnderTest.(*ConstraintSystem).
			LinearExpression(
				systemUnderTest.(*ConstraintSystem).Term(a, big.NewInt(1)),
				systemUnderTest.(*ConstraintSystem).Term(b, big.NewInt(2)),
			)

		r := systemUnderTest.(*ConstraintSystem).
			LinearExpression(
				systemUnderTest.(*ConstraintSystem).Term(c, big.NewInt(3)),
				systemUnderTest.(*ConstraintSystem).Term(d, big.NewInt(4)),
			)

		e := systemUnderTest.(*ConstraintSystem).Mul(l, r)
		iVariablesCreated = append(iVariablesCreated, e)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsMulLinearExpressions = csState{2, 2, 1, 1, 0}

// inverse a variable
func rfInverseVariable() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		v := systemUnderTest.(*ConstraintSystem).Inverse(a)
		iVariablesCreated = append(iVariablesCreated, v)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsInverse = deltaState{1, 0, 1, 1, 0}

// div 2 variables
func rfDivVariablesOnly() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		b := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		sVariablesCreated = append(sVariablesCreated, b)

		v := systemUnderTest.(*ConstraintSystem).Div(a, b)
		iVariablesCreated = append(iVariablesCreated, v)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsDivVariablesOnly = deltaState{1, 1, 1, 1, 0}

// div a constant by a variable
func rfDivConstantVariable() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		v := systemUnderTest.(*ConstraintSystem).Div(3, a)
		iVariablesCreated = append(iVariablesCreated, v)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsDivConstantVariable = deltaState{1, 0, 1, 1, 0}

// div a varialbe by a constant
func rfDivVariableConstant() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		v := systemUnderTest.(*ConstraintSystem).Div(a, 3)
		iVariablesCreated = append(iVariablesCreated, v)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsDivVariableConstant = deltaState{1, 0, 1, 1, 0}

// div a constant by a constant
func rfDivConstantsOnly() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		v := systemUnderTest.(*ConstraintSystem).Div(6, 3)
		iVariablesCreated = append(iVariablesCreated, v)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsDivConstantsOnly = deltaState{0, 0, 1, 1, 0}

// div a 2 linear expressions
func rfDivLinearExpressions() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		b := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		sVariablesCreated = append(sVariablesCreated, b)

		c := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, c)

		d := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		sVariablesCreated = append(sVariablesCreated, d)

		l := systemUnderTest.(*ConstraintSystem).
			LinearExpression(
				systemUnderTest.(*ConstraintSystem).Term(a, big.NewInt(1)),
				systemUnderTest.(*ConstraintSystem).Term(b, big.NewInt(2)),
			)

		r := systemUnderTest.(*ConstraintSystem).
			LinearExpression(
				systemUnderTest.(*ConstraintSystem).Term(c, big.NewInt(3)),
				systemUnderTest.(*ConstraintSystem).Term(d, big.NewInt(4)),
			)

		v := systemUnderTest.(*ConstraintSystem).Div(l, r)
		iVariablesCreated = append(iVariablesCreated, v)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsDivLinearExpressions = deltaState{2, 2, 1, 1, 0}

// xor between two variables
func rfXor() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		b := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		sVariablesCreated = append(sVariablesCreated, b)

		v := systemUnderTest.(*ConstraintSystem).Xor(a, b)
		iVariablesCreated = append(iVariablesCreated, v)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsXor = deltaState{1, 1, 1, 1, 2}

// binary decomposition of a variable
func rfToBinary() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		iVariablesCreated := systemUnderTest.(*ConstraintSystem).ToBinary(a, 256)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.BinaryDec}

		return csRes
	}
	return res
}

var nsToBinary = deltaState{1, 0, 256, 1, 256}

// select constraint betwwen variableq
func rfSelectVariables() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		b := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		sVariablesCreated = append(sVariablesCreated, b)

		c := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		sVariablesCreated = append(sVariablesCreated, c)

		v := systemUnderTest.(*ConstraintSystem).Select(a, b, c)
		iVariablesCreated = append(iVariablesCreated, v)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsSelectVariables = deltaState{1, 2, 1, 1, 1}

// select constraint betwwen variable and constant
func rfSelectVariableConstant() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		b := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		sVariablesCreated = append(sVariablesCreated, b)

		v := systemUnderTest.(*ConstraintSystem).Select(a, b, 1)
		iVariablesCreated = append(iVariablesCreated, v)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsSelectVariableConstant = deltaState{1, 1, 1, 1, 1}

// select constraint betwwen variable and constant
func rfSelectConstantVariable() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		b := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		sVariablesCreated = append(sVariablesCreated, b)

		v := systemUnderTest.(*ConstraintSystem).Select(a, 1, b)
		iVariablesCreated = append(iVariablesCreated, v)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsSelectConstantVariable = deltaState{1, 1, 1, 1, 1}

// copy of variable
func rfConstant() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		systemUnderTest.(*ConstraintSystem).Constant(a)
		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsConstant = deltaState{1, 0, 0, 0, 0}

// equality between 2 variables
func rfIsEqualTwoVariables() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		b := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		sVariablesCreated = append(sVariablesCreated, b)

		systemUnderTest.(*ConstraintSystem).AssertIsEqual(a, b)
		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsIsEqualVariables = deltaState{1, 1, 0, 0, 1}

// equality between a variable and a constant
func rfIsEqualVariableConstant() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		systemUnderTest.(*ConstraintSystem).AssertIsEqual(a, 3)
		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsIsEqualVariableConstant = deltaState{1, 0, 0, 0, 1}

// equality between a variable and a constant
func rfIsEqualConstantVariable() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		systemUnderTest.(*ConstraintSystem).AssertIsEqual(3, a)
		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsIsEqualConstantVariable = deltaState{1, 0, 0, 0, 1}

// equality between 2 variables
func rfIsEqualTwoLinearExpression() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		b := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		sVariablesCreated = append(sVariablesCreated, b)

		c := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, c)

		d := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		sVariablesCreated = append(sVariablesCreated, d)

		l := systemUnderTest.(*ConstraintSystem).
			LinearExpression(
				systemUnderTest.(*ConstraintSystem).Term(a, big.NewInt(1)),
				systemUnderTest.(*ConstraintSystem).Term(b, big.NewInt(2)),
			)

		r := systemUnderTest.(*ConstraintSystem).
			LinearExpression(
				systemUnderTest.(*ConstraintSystem).Term(c, big.NewInt(3)),
				systemUnderTest.(*ConstraintSystem).Term(d, big.NewInt(4)),
			)

		systemUnderTest.(*ConstraintSystem).AssertIsEqual(l, r)
		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsIsEqualTwoLinearExpressions = deltaState{2, 2, 0, 0, 1}

// packing from binary variables
func rfFromBinary() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 256)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		for i := 0; i < 256; i++ {
			pVariablesCreated[i] = systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
			incVariableName()
		}

		v := systemUnderTest.(*ConstraintSystem).FromBinary(pVariablesCreated...)
		iVariablesCreated = append(iVariablesCreated, v)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsFromBinary = deltaState{256, 0, 1, 1, 256}

// boolean constrain a variable
func rfIsBoolean() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		systemUnderTest.(*ConstraintSystem).AssertIsBoolean(a)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsIsBoolean = deltaState{1, 0, 0, 0, 1}

// bound a variable by another variable
func rfMustBeLessOrEqVar() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		b := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		sVariablesCreated = append(sVariablesCreated, b)

		systemUnderTest.(*ConstraintSystem).AssertIsLessOrEqual(a, b)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsMustBeLessOrEqVar = deltaState{1, 1, 1281, 771, 768}

// bound a variable by a constant
func rfMustBeLessOrEqConst() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		systemUnderTest.(*ConstraintSystem).AssertIsLessOrEqual(a, 256)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			r1c.SingleOutput}

		return csRes
	}
	return res
}

var nsMustBeLessOrEqConst = csState{1, 0, 257, 2, 511} // nb internal variables: 256+HW(bound), nb constraints: 1+HW(bound), nb assertions: 256+HW(^bound)

// ------------------------------------------------------------------------------
// build the next state function using the delta state
func nextStateFunc(ds deltaState) nextstatefunc {

	res := func(state commands.State) commands.State {
		state.(*csState).nbPublicVariables += ds.nbPublicVariables
		state.(*csState).nbSecretVariables += ds.nbSecretVariables
		state.(*csState).nbInternalVariables += ds.nbInternalVariables
		state.(*csState).nbConstraints += ds.nbConstraints
		state.(*csState).nbAssertions += ds.nbAssertions
		return state
	}
	return res
}

// ------------------------------------------------------------------------------
// Test chaining the functions
func TestAPI(t *testing.T) {

	// buillding the list of functions from gnark api
	listFuncs := []interface{}{
		buildProtoCommands("Add variables only", rfAddVariablesOnly(), nextStateFunc(nsAddVariablesOnly)),
		buildProtoCommands("Add variables constants", rfAddVariablesConstants(), nextStateFunc(nsAddVariablesConstants)),
		buildProtoCommands("Add constants only", rfAddConstantsOnly(), nextStateFunc(nsAddConstantsOnly)),
		buildProtoCommands("Sub variables only", rfSubVariablesOnly(), nextStateFunc(nsSubVariablesOnly)),
		buildProtoCommands("Sub variable constant", rfSubVariableConstant(), nextStateFunc(nsSubVariableConstant)),
		buildProtoCommands("Sub constant variable", rfSubConstantVariables(), nextStateFunc(nsSubConstantVariable)),
		buildProtoCommands("Sub constants only", rfSubConstantsOnly(), nextStateFunc(nsSubConstantsOnly)),
		buildProtoCommands("Mul variables only", rfMulVariablesOnly(), nextStateFunc(nsMulVariablesOnly)),
		buildProtoCommands("Mul variables constants", rfMulVariablesConstants(), nextStateFunc(nsMulVariablesConstants)),
		buildProtoCommands("Mul constants only", rfMulConstantsOnly(), nextStateFunc(nsMulConstantsOnly)),
		buildProtoCommands("Mul linear expressions", rfMulLinearExpressions(), nextStateFunc(nsMulLinearExpressions)),
		buildProtoCommands("Inv a variable", rfInverseVariable(), nextStateFunc(nsInverse)),
		buildProtoCommands("Div variables only", rfDivVariablesOnly(), nextStateFunc(nsDivVariablesOnly)),
		buildProtoCommands("Div variable constant", rfDivVariableConstant(), nextStateFunc(nsDivVariableConstant)),
		buildProtoCommands("Div constant variable", rfDivConstantVariable(), nextStateFunc(nsDivConstantVariable)),
		buildProtoCommands("Div constants only", rfDivConstantsOnly(), nextStateFunc(nsDivConstantsOnly)),
		buildProtoCommands("Div linear expressions", rfDivLinearExpressions(), nextStateFunc(nsDivLinearExpressions)),
		buildProtoCommands("Xor", rfXor(), nextStateFunc(nsXor)),
		buildProtoCommands("ToBinary", rfToBinary(), nextStateFunc(nsToBinary)),
		buildProtoCommands("Select 2 variables", rfSelectVariables(), nextStateFunc(nsSelectVariables)),
		buildProtoCommands("Select variable constant", rfSelectVariableConstant(), nextStateFunc(nsSelectVariableConstant)),
		buildProtoCommands("Select constant variable", rfSelectConstantVariable(), nextStateFunc(nsSelectConstantVariable)),
		buildProtoCommands("Constant", rfConstant(), nextStateFunc(nsConstant)),
		buildProtoCommands("IsEqual 2 variables", rfIsEqualTwoVariables(), nextStateFunc(nsIsEqualVariables)),
		buildProtoCommands("IsEqual 2 linear expressions", rfIsEqualTwoLinearExpression(), nextStateFunc(nsIsEqualTwoLinearExpressions)),
		buildProtoCommands("IsEqual constant variable", rfIsEqualConstantVariable(), nextStateFunc(nsIsEqualConstantVariable)),
		buildProtoCommands("IsEqual variable constant", rfIsEqualVariableConstant(), nextStateFunc(nsIsEqualVariableConstant)),
		buildProtoCommands("FromBinary", rfFromBinary(), nextStateFunc(nsFromBinary)),
		buildProtoCommands("IsBoolean", rfIsBoolean(), nextStateFunc(nsIsBoolean)),
		buildProtoCommands("Must be less or eq var", rfMustBeLessOrEqVar(), nextStateFunc(nsMustBeLessOrEqVar)),
		buildProtoCommands("Must be less or eq const", rfMustBeLessOrEqConst(), nextStateFunc(nsMustBeLessOrEqConst)),
	}

	// generate randomly a sequence of commands
	var apiCommands = &commands.ProtoCommands{
		NewSystemUnderTestFunc: func(initialState commands.State) commands.SystemUnderTest {
			nc := newConstraintSystem()
			return &nc
		},
		InitialStateGen: gen.Const(1).Map(func(npv int) *csState {
			return &csState{
				nbPublicVariables: npv,
			}
		}),
		GenCommandFunc: func(state commands.State) gopter.Gen {
			return gen.OneConstOf(listFuncs...)
		},
	}

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 40

	properties := gopter.NewProperties(parameters)
	properties.Property("chaining functions from the API", commands.Prop(apiCommands))

	resTest := properties.Run(gopter.ConsoleReporter(false))
	if !resTest {
		t.Fatal("TestAPI fails")
	}

}
