package frontend

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/internal/backend/compiled"
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
	cs                *ConstraintSystem      // constraint system after it has been modified using gnark API
	publicVariables   []Variable             // public variables created after calling a run function
	secretVariables   []Variable             // secret variables created aftrer calling a run funcion
	internalVariables []Variable             // variables resulting of the function call (from cs.Add, cs.Mul, etc)
	solver            compiled.SolvingMethod // according to the solving method, different features are checked
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
		expectedID := len(csRes.cs.public.variables) - len(csRes.publicVariables) + i
		if args.val != nil || args.id != expectedID {
			return false
		}
	}
	return true
}

func checkSecretVariables(csRes csResult) bool {
	for i, args := range csRes.secretVariables {
		expectedID := len(csRes.cs.secret.variables) - len(csRes.secretVariables) + i
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

	// witness = checkInternalVariables(csRes)
	// if !witness {
	// 	return &gopter.PropResult{Status: gopter.PropFalse}
	// }

	// checks the state of the constraint system
	if len(csRes.cs.public.variables) != st.nbPublicVariables ||
		len(csRes.cs.secret.variables) != st.nbSecretVariables ||
		len(csRes.cs.internal.variables) != st.nbInternalVariables ||
		len(csRes.cs.constraints) != st.nbConstraints ||
		len(csRes.cs.assertions) != st.nbAssertions {
		return &gopter.PropResult{Status: gopter.PropFalse}
	}
	return &gopter.PropResult{Status: gopter.PropTrue}
}

// ------------------------------------------------------------------------------
// list of run functions

// Add several variables
func rfAddSub() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable()
		pVariablesCreated = append(pVariablesCreated, a)
		incVariableName()

		b := systemUnderTest.(*ConstraintSystem).newSecretVariable()
		sVariablesCreated = append(sVariablesCreated, b)
		incVariableName()

		c := systemUnderTest.(*ConstraintSystem).newSecretVariable()
		sVariablesCreated = append(sVariablesCreated, c)
		incVariableName()

		u := systemUnderTest.(*ConstraintSystem).Add(a, b, 3, 4)
		v := systemUnderTest.(*ConstraintSystem).Sub(u, c)
		systemUnderTest.(*ConstraintSystem).Sub(v, 3)
		systemUnderTest.(*ConstraintSystem).Sub(3, v)
		systemUnderTest.(*ConstraintSystem).Sub(4, 3)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			compiled.SingleOutput}

		return csRes
	}
	return res
}

var nsAddSub = deltaState{1, 2, 0, 0, 0} // ex: after calling add, we should have 1 public variable, 3 secret variables, 0 internal variable, 0 constraint more in the cs

// mul variables
func rfMul() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable()
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		b := systemUnderTest.(*ConstraintSystem).newSecretVariable()
		incVariableName()
		sVariablesCreated = append(sVariablesCreated, b)

		c := systemUnderTest.(*ConstraintSystem).Mul(a, b, 3, 4, 5)
		iVariablesCreated = append(iVariablesCreated, c)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			compiled.SingleOutput}

		return csRes
	}
	return res
}

var nsMul = csState{1, 1, 1, 1, 0}

// inverse a variable
func rfInverse() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable()
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		v := systemUnderTest.(*ConstraintSystem).Inverse(a)
		iVariablesCreated = append(iVariablesCreated, v)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			compiled.SingleOutput}

		return csRes
	}
	return res
}

var nsInverse = deltaState{1, 0, 1, 1, 0}

// div 2 variables
func rfDiv() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable()
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		b := systemUnderTest.(*ConstraintSystem).newSecretVariable()
		incVariableName()
		sVariablesCreated = append(sVariablesCreated, b)

		u := systemUnderTest.(*ConstraintSystem).Div(a, b)
		iVariablesCreated = append(iVariablesCreated, u)

		v := systemUnderTest.(*ConstraintSystem).Div(a, 3)
		iVariablesCreated = append(iVariablesCreated, v)

		w := systemUnderTest.(*ConstraintSystem).Div(3, a)
		iVariablesCreated = append(iVariablesCreated, w)

		x := systemUnderTest.(*ConstraintSystem).Div(3, 3)
		iVariablesCreated = append(iVariablesCreated, x)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			compiled.SingleOutput}

		return csRes
	}
	return res
}

var nsDiv = deltaState{1, 1, 4, 4, 0}

// xor between two variables
func rfXor() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable()
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		b := systemUnderTest.(*ConstraintSystem).newSecretVariable()
		incVariableName()
		sVariablesCreated = append(sVariablesCreated, b)

		v := systemUnderTest.(*ConstraintSystem).Xor(a, b)
		iVariablesCreated = append(iVariablesCreated, v)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			compiled.SingleOutput}

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

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable()
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		iVariablesCreated := systemUnderTest.(*ConstraintSystem).ToBinary(a, 256)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			compiled.BinaryDec}

		return csRes
	}
	return res
}

var nsToBinary = deltaState{1, 0, 256, 1, 256}

// select constraint betwwen variableq
func rfSelect() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable()
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		b := systemUnderTest.(*ConstraintSystem).newSecretVariable()
		incVariableName()
		sVariablesCreated = append(sVariablesCreated, b)

		c := systemUnderTest.(*ConstraintSystem).newSecretVariable()
		incVariableName()
		sVariablesCreated = append(sVariablesCreated, c)

		u := systemUnderTest.(*ConstraintSystem).Select(a, b, c)
		iVariablesCreated = append(iVariablesCreated, u)

		v := systemUnderTest.(*ConstraintSystem).Select(a, 3, c)
		iVariablesCreated = append(iVariablesCreated, v)

		w := systemUnderTest.(*ConstraintSystem).Select(a, b, 3)
		iVariablesCreated = append(iVariablesCreated, w)

		systemUnderTest.(*ConstraintSystem).Select(a, 3, 3)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			compiled.SingleOutput}

		return csRes
	}
	return res
}

var nsSelect = deltaState{1, 2, 3, 3, 1}

// copy of variable
func rfConstant() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable()
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		systemUnderTest.(*ConstraintSystem).Constant(a)
		systemUnderTest.(*ConstraintSystem).Constant(3)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			compiled.SingleOutput}

		return csRes
	}
	return res
}

var nsConstant = deltaState{1, 0, 0, 0, 0}

// equality between 2 variables
func rfIsEqual() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable()
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		b := systemUnderTest.(*ConstraintSystem).newSecretVariable()
		incVariableName()
		sVariablesCreated = append(sVariablesCreated, b)

		systemUnderTest.(*ConstraintSystem).AssertIsEqual(a, b)

		u := systemUnderTest.(*ConstraintSystem).Add(a, b)
		v := systemUnderTest.(*ConstraintSystem).Mul(a, 3)
		systemUnderTest.(*ConstraintSystem).AssertIsEqual(u, v)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			compiled.SingleOutput}

		return csRes
	}
	return res
}

var nsIsEqual = deltaState{1, 1, 0, 0, 2}

// packing from binary variables
func rfFromBinary() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 256)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		for i := 0; i < 256; i++ {
			pVariablesCreated[i] = systemUnderTest.(*ConstraintSystem).newPublicVariable()
			incVariableName()
		}

		systemUnderTest.(*ConstraintSystem).FromBinary(pVariablesCreated...)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			compiled.SingleOutput}

		return csRes
	}
	return res
}

var nsFromBinary = deltaState{256, 0, 0, 0, 256}

// boolean constrain a variable
func rfIsBoolean() runfunc {
	res := func(systemUnderTest commands.SystemUnderTest) commands.Result {

		pVariablesCreated := make([]Variable, 0)
		sVariablesCreated := make([]Variable, 0)
		iVariablesCreated := make([]Variable, 0)

		a := systemUnderTest.(*ConstraintSystem).newPublicVariable()
		incVariableName()
		pVariablesCreated = append(pVariablesCreated, a)

		b := systemUnderTest.(*ConstraintSystem).newSecretVariable()
		incVariableName()
		sVariablesCreated = append(sVariablesCreated, b)

		// constrain the variable twice to check if just one assertion is added
		systemUnderTest.(*ConstraintSystem).AssertIsBoolean(a)
		systemUnderTest.(*ConstraintSystem).AssertIsBoolean(a)

		// constrain the variable twice to check if just one assertion is added
		systemUnderTest.(*ConstraintSystem).AssertIsBoolean(b)
		systemUnderTest.(*ConstraintSystem).AssertIsBoolean(b)

		csRes := csResult{
			systemUnderTest.(*ConstraintSystem),
			pVariablesCreated,
			sVariablesCreated,
			iVariablesCreated,
			compiled.SingleOutput}

		return csRes
	}
	return res
}

var nsIsBoolean = deltaState{1, 1, 0, 0, 2}

var nsMustBeLessOrEqVar = deltaState{1, 1, 1281, 771, 768}

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
// Test chaining the functions with normal behaviour
func TestAPI(t *testing.T) {

	// buillding the list of functions from gnark api
	listFuncs := []interface{}{
		buildProtoCommands("Add Sub", rfAddSub(), nextStateFunc(nsAddSub)),
		buildProtoCommands("Mul", rfMul(), nextStateFunc(nsMul)),
		buildProtoCommands("Inv", rfInverse(), nextStateFunc(nsInverse)),
		buildProtoCommands("Div", rfDiv(), nextStateFunc(nsDiv)),
		buildProtoCommands("Xor", rfXor(), nextStateFunc(nsXor)),
		buildProtoCommands("ToBinary", rfToBinary(), nextStateFunc(nsToBinary)),
		buildProtoCommands("Select 2 variables", rfSelect(), nextStateFunc(nsSelect)),
		buildProtoCommands("Constant", rfConstant(), nextStateFunc(nsConstant)),
		buildProtoCommands("IsEqual", rfIsEqual(), nextStateFunc(nsIsEqual)),
		buildProtoCommands("FromBinary", rfFromBinary(), nextStateFunc(nsFromBinary)),
		buildProtoCommands("IsBoolean", rfIsBoolean(), nextStateFunc(nsIsBoolean)),
		// buildProtoCommands("Must be less or eq var", rfMustBeLessOrEqVar(), nextStateFunc(nsMustBeLessOrEqVar)), // TODO restore once isBoolean is fixed
		// buildProtoCommands("Must be less or eq const", rfMustBeLessOrEqConst(), nextStateFunc(nsMustBeLessOrEqConst)), // TODO idem
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

// ------------------------------------------------------------------------------
// Test chaining the functions with unset variables

type addCircuit struct {
	A Variable
}

func (c *addCircuit) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	var unsetVar Variable
	a := cs.Add(unsetVar, c.A)
	cs.AssertIsEqual(a, 3)
	return nil
}

type subCircuit struct {
	A Variable
}

func (c *subCircuit) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	var unsetVar Variable
	a := cs.Sub(unsetVar, c.A)
	cs.AssertIsEqual(a, 3)
	return nil
}

type mulCircuit struct {
	A Variable
}

func (c *mulCircuit) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	var unsetVar Variable
	cs.Mul(unsetVar, c.A)
	return nil
}

type invCircuit struct {
	A Variable
}

func (c *invCircuit) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	var unsetVar Variable
	cs.Inverse(unsetVar)
	return nil
}

type divCircuit struct {
	A Variable
}

func (c *divCircuit) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	var unsetVar Variable
	cs.Div(unsetVar, c.A)
	return nil
}

type xorCircuit struct {
	A Variable
}

func (c *xorCircuit) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	var unsetVar Variable
	cs.Xor(unsetVar, c.A)
	return nil
}

type toBinaryCircuit struct {
	A Variable
}

func (c *toBinaryCircuit) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	var unsetVar Variable
	cs.ToBinary(unsetVar, 256)
	return nil
}

type fromBinaryCircuit struct {
	A Variable
}

func (c *fromBinaryCircuit) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	var unsetVar Variable
	a := cs.FromBinary(unsetVar)
	cs.AssertIsEqual(a, 3)
	return nil
}

type selectCircuit struct {
	A Variable
}

func (c *selectCircuit) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	var unsetVar Variable
	cs.Select(unsetVar, c.A, 1)
	return nil
}

type isEqualCircuit struct {
	A Variable
}

func (c *isEqualCircuit) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	var unsetVar Variable
	cs.AssertIsEqual(unsetVar, c.A)
	return nil
}

type isBooleanCircuit struct {
	A Variable
}

func (c *isBooleanCircuit) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	var unsetVar Variable
	cs.AssertIsBoolean(unsetVar)
	return nil
}

type isLessOrEq struct {
	A Variable
}

func (c *isLessOrEq) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	var unsetVar Variable
	cs.AssertIsLessOrEqual(unsetVar, c.A)
	return nil
}

func TestUnsetVariables(t *testing.T) {
	// TODO unset variables with markBoolean will panic.
	// doing
	// var a Variable
	// cs.AssertIsBoolean(a)
	// will panic.
	mapFuncs := map[string]Circuit{
		"add":          &addCircuit{},
		"sub":          &subCircuit{},
		"mul":          &mulCircuit{},
		"inv":          &invCircuit{},
		"div":          &divCircuit{},
		"xor":          &xorCircuit{},
		"toBinary":     &toBinaryCircuit{},
		"fromBinary":   &fromBinaryCircuit{},
		"selectBinary": &selectCircuit{},
		"isEqual":      &isEqualCircuit{},
		"isBoolean":    &isBooleanCircuit{},
		"isLessOrEq":   &isLessOrEq{},
	}

	for name, arg := range mapFuncs {
		t.Run(name, func(_t *testing.T) {
			_, err := Compile(ecc.UNKNOWN, backend.GROTH16, arg)
			if err == nil {
				_t.Fatal("An unset variable error should be caught when the circuit is compiled")
			}

			if err.Error() != ErrInputNotSet.Error() {
				_t.Fatal("expected input not set error, got " + err.Error())
			}
		})
	}

}

func TestPrintln(t *testing.T) {
	// must not panic.
	cs := newConstraintSystem()
	one := cs.newPublicVariable()

	cs.Println(nil)
	cs.Println(1)
	cs.Println("a")
	cs.Println(new(big.Int).SetInt64(2))
	cs.Println(one)

	cs.Println(nil, 1, "a", new(big.Int), one)
}
