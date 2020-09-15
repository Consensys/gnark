package frontend

import (
	"math/big"
	"testing"

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

// contains the result of a modification of a constraint system (commands.Result)
type csResult struct {
	cs       *ConstraintSystem
	variable []Variable
}

type runfunc func(systemUnderTest commands.SystemUnderTest) commands.Result
type nextstatefunc func(state commands.State) commands.State

// the names of the public/secret inputs are variableName.String()
func incVariableName() {
	variableName.Add(&variableName, bOne)
}

func buildProtoCommands(name string, rf runfunc, ns nextstatefunc) *commands.ProtoCommand {
	return &commands.ProtoCommand{
		Name:              name,
		RunFunc:           rf,
		NextStateFunc:     ns,
		PostConditionFunc: postConditionAPI,
	}
}

// ------------------------------------------------------------------------------
// post condition should hold when applying a function on the system

func postConditionAPI(state commands.State, result commands.Result) *gopter.PropResult {
	st := state.(*csState)
	csRes := result.(csResult)

	// checks if the variable is correctly constructed
	for _, args := range csRes.variable {
		if args.isBoolean || args.val != nil || args.id != st.nbInternalVariables-1 {
			return &gopter.PropResult{Status: gopter.PropFalse}
		}
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
// a csResult should be updated by those numbers when the corresponding function
// is applied on the constraint system.

var nsAdd = csState{1, 1, 1, 1, 0} // ex: after calling add, we should have 1 public variable, 1 secret variable, 1 internal variable and 1 constraint more in the cs
var nsSub = csState{1, 1, 1, 1, 0}
var nsMul = csState{1, 1, 1, 1, 0}
var nsInverse = csState{1, 0, 1, 1, 0}
var nsDiv = csState{1, 1, 1, 1, 0}
var nsXor = csState{1, 1, 1, 1, 2}
var nsToBinary = csState{1, 0, 256, 1, 256}
var nsSelect = csState{1, 2, 1, 1, 1}
var nsConstant = csState{1, 0, 0, 1, 0}
var nsIsEqual = csState{1, 1, 0, 0, 1}
var nsFromBinary = csState{256, 0, 1, 1, 256}
var nsIsBoolean = csState{1, 0, 0, 0, 1}

// ------------------------------------------------------------------------------
// list of run functions

func rfAdd() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {
		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		b := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		v := systemUnderTest.(*ConstraintSystem).Add(a, b)
		vRes := []Variable{v}
		csRes := csResult{systemUnderTest.(*ConstraintSystem), vRes}
		return csRes
	}
	return res
}

func rfSub() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {
		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		b := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		v := systemUnderTest.(*ConstraintSystem).Sub(a, b)
		vRes := []Variable{v}
		csRes := csResult{systemUnderTest.(*ConstraintSystem), vRes}
		return csRes
	}
	return res
}

func rfMul() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {
		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		b := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		v := systemUnderTest.(*ConstraintSystem).Mul(a, b)
		vRes := []Variable{v}
		csRes := csResult{systemUnderTest.(*ConstraintSystem), vRes}
		return csRes
	}
	return res
}

func rfInverse() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {
		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		v := systemUnderTest.(*ConstraintSystem).Inverse(a)
		vRes := []Variable{v}
		csRes := csResult{systemUnderTest.(*ConstraintSystem), vRes}
		return csRes
	}
	return res
}

func rfDiv() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {
		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		b := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		v := systemUnderTest.(*ConstraintSystem).Div(a, b)
		vRes := []Variable{v}
		csRes := csResult{systemUnderTest.(*ConstraintSystem), vRes}
		return csRes
	}
	return res
}

func rfXor() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {
		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		b := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		v := systemUnderTest.(*ConstraintSystem).Xor(a, b)
		vRes := []Variable{v}
		csRes := csResult{systemUnderTest.(*ConstraintSystem), vRes}
		return csRes
	}
	return res
}

func rfToBinary() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {
		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		v := systemUnderTest.(*ConstraintSystem).ToBinary(a, 256)
		vRes := make([]Variable, len(v))
		for i, args := range v {
			vRes[i] = args
		}
		csRes := csResult{systemUnderTest.(*ConstraintSystem), vRes}
		return csRes
	}
	return res
}

func rfSelect() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {
		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		b := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		c := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		v := systemUnderTest.(*ConstraintSystem).Select(a, b, c)
		vRes := []Variable{v}
		csRes := csResult{systemUnderTest.(*ConstraintSystem), vRes}
		return csRes
	}
	return res
}

func rfConstant() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {
		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		v := systemUnderTest.(*ConstraintSystem).Constant(a)
		vRes := []Variable{v}
		csRes := csResult{systemUnderTest.(*ConstraintSystem), vRes}
		return csRes
	}
	return res
}

func rfIsEqual() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {
		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		b := systemUnderTest.(*ConstraintSystem).newSecretVariable(variableName.String())
		incVariableName()
		systemUnderTest.(*ConstraintSystem).AssertIsEqual(a, b)
		vRes := []Variable{}
		csRes := csResult{systemUnderTest.(*ConstraintSystem), vRes}
		return csRes
	}
	return res
}

func rfFromBinary() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {
		var a [256]Variable
		for i := 0; i < 256; i++ {
			a[i] = systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
			incVariableName()
		}
		v := systemUnderTest.(*ConstraintSystem).FromBinary(a[:]...)
		vRes := []Variable{v}
		csRes := csResult{systemUnderTest.(*ConstraintSystem), vRes}
		return csRes
	}
	return res
}

func rfIsBoolean() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {
		a := systemUnderTest.(*ConstraintSystem).newPublicVariable(variableName.String())
		incVariableName()
		systemUnderTest.(*ConstraintSystem).AssertIsBoolean(a)
		vRes := []Variable{}
		csRes := csResult{systemUnderTest.(*ConstraintSystem), vRes}
		return csRes
	}
	return res
}

func nextStateFunc(ns csState) nextstatefunc {

	res := func(state commands.State) commands.State {
		state.(*csState).nbPublicVariables += ns.nbPublicVariables
		state.(*csState).nbSecretVariables += ns.nbSecretVariables
		state.(*csState).nbInternalVariables += ns.nbInternalVariables
		state.(*csState).nbConstraints += ns.nbConstraints
		state.(*csState).nbAssertions += ns.nbAssertions
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
		buildProtoCommands("Div", rfInverse(), nextStateFunc(nsInverse)),
		buildProtoCommands("Xor", rfXor(), nextStateFunc(nsXor)),
		//buildProtoCommands("ToBinary", rfToBinary(), nextStateFunc(nsToBinary)),
		buildProtoCommands("Select", rfSelect(), nextStateFunc(nsSelect)),
		//buildProtoCommands("Constant", rfConstant(), nextStateFunc(nsConstant)),
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

	properties := gopter.NewProperties(parameters)
	properties.Property("chaining functions from the API", commands.Prop(apiCommands))

	properties.Run(gopter.ConsoleReporter(false))

}
