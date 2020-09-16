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

// csState holds the expected state of a cs (commands.State)
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
	//st := state.(*csState)
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

	// checks if the internal variables are correctly constructed
	// if csRes.solver == r1c.SingleOutput {
	// 	for _, args := range csRes.internalVariables {

	// 		// the variable should be set
	// 		if args.visibility == backend.Unset {
	// 			return &gopter.PropResult{Status: gopter.PropFalse}
	// 		}

	// 		// the result should not be boolean constrained
	// 		if _, ok := csRes.cs.booleanVariables[args.visibility-1][args.id]; ok {
	// 			return &gopter.PropResult{Status: gopter.PropFalse}
	// 		}
	// 	}
	// } else if csRes.solver == r1c.BinaryDec {
	// 	for _, args := range csRes.internalVariables {

	// 		// the result should be boolean constrained
	// 		if _, ok := csRes.cs.booleanVariables[args.visibility-1][args.id]; !ok {
	// 			return &gopter.PropResult{Status: gopter.PropFalse}
	// 		}
	// 	}
	// }

	// checks the state of the constraint system
	// if len(csRes.cs.publicVariableNames) != st.nbPublicVariables ||
	// 	len(csRes.cs.publicVariables) != st.nbPublicVariables ||
	// 	len(csRes.cs.secretVariableNames) != st.nbSecretVariables ||
	// 	len(csRes.cs.secretVariables) != st.nbSecretVariables ||
	// 	len(csRes.cs.internalVariables) != st.nbInternalVariables ||
	// 	len(csRes.cs.constraints) != st.nbConstraints ||
	// 	len(csRes.cs.assertions) != st.nbAssertions {
	// 	return &gopter.PropResult{Status: gopter.PropFalse}
	// }
	return &gopter.PropResult{Status: gopter.PropTrue}
}

// ------------------------------------------------------------------------------
// a csResult should be updated by those numbers when the corresponding function
// is applied on the constraint system.

var nsAdd = deltaState{1, 1, 1, 1, 0} // ex: after calling add, we should have 1 public variable, 1 secret variable, 1 internal variable and 1 constraint more in the cs
var nsSub = deltaState{1, 1, 1, 1, 0}
var nsMul = deltaState{1, 1, 1, 1, 0}
var nsInverse = deltaState{1, 0, 1, 1, 0}
var nsDiv = deltaState{1, 1, 1, 1, 0}
var nsXor = deltaState{1, 1, 1, 1, 2}
var nsToBinary = deltaState{1, 0, 256, 1, 256}
var nsSelect = deltaState{1, 2, 1, 1, 1}
var nsConstant = deltaState{1, 0, 0, 0, 0}
var nsIsEqual = deltaState{1, 1, 0, 0, 1}
var nsFromBinary = deltaState{256, 0, 1, 1, 256}
var nsIsBoolean = deltaState{1, 0, 0, 0, 1}

// ------------------------------------------------------------------------------
// list of run functions

func rfAdd() runfunc {
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

		v := systemUnderTest.(*ConstraintSystem).Add(a, b)
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

func rfSub() runfunc {
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

func rfMul() runfunc {
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

		v := systemUnderTest.(*ConstraintSystem).Mul(a, b)
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

func rfInverse() runfunc {
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

func rfDiv() runfunc {
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

func rfSelect() runfunc {
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

func rfIsEqual() runfunc {
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
		buildProtoCommands("Add", rfAdd(), nextStateFunc(nsAdd)),
		buildProtoCommands("Sub", rfSub(), nextStateFunc(nsSub)),
		buildProtoCommands("Mul", rfMul(), nextStateFunc(nsMul)),
		buildProtoCommands("Inv", rfInverse(), nextStateFunc(nsInverse)),
		buildProtoCommands("Div", rfDiv(), nextStateFunc(nsDiv)),
		buildProtoCommands("Xor", rfXor(), nextStateFunc(nsXor)),
		buildProtoCommands("ToBinary", rfToBinary(), nextStateFunc(nsToBinary)),
		buildProtoCommands("Select", rfSelect(), nextStateFunc(nsSelect)),
		buildProtoCommands("Constant", rfConstant(), nextStateFunc(nsConstant)),
		buildProtoCommands("IsEqual", rfIsEqual(), nextStateFunc(nsIsEqual)),
		buildProtoCommands("FromBinary", rfFromBinary(), nextStateFunc(nsFromBinary)),
		buildProtoCommands("IsBoolean", rfIsBoolean(), nextStateFunc(nsIsBoolean)),
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
	parameters.MinSuccessfulTests = 5

	properties := gopter.NewProperties(parameters)
	properties.Property("chaining functions from the API", commands.Prop(apiCommands))

	resTest := properties.Run(gopter.ConsoleReporter(false))
	if !resTest {
		t.Fatal("TestAPI fails")
	}

}
