/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package frontend

import (
	"fmt"
	"io"
	"math/big"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/internal/backend/compiled"
)

// ConstraintSystem represents a Groth16 like circuit
//
// All the APIs to define a circuit (see Circuit.Define) like Add, Sub, Mul, ...
// may take as input interface{}
//
// these interfaces are either Variables (/LinearExpressions) or constants (big.Int, strings, uint, fr.Element)
type ConstraintSystem struct {
	// Variables (aka wires)
	public struct {
		variables []Variable       // public inputs
		booleans  map[int]struct{} // keep track of boolean variables (we constrain them once)
	}
	secret struct {
		variables []Variable       // secret inputs
		booleans  map[int]struct{} // keep track of boolean variables (we constrain them once)
	}
	internal struct {
		variables []Variable       // internal variables
		booleans  map[int]struct{} // keep track of boolean variables (we constrain them once)
	}

	// Constraints
	constraints []compiled.R1C // list of R1C that yield an output (for example v3 == v1 * v2, return v3)
	assertions  []compiled.R1C // list of R1C that yield no output (for example ensuring v1 == v2)

	// Coefficients in the constraints
	coeffs    []big.Int      // list of unique coefficients.
	coeffsIDs map[string]int // map to fast check existence of a coefficient (key = coeff.Text(16))

	// Hints
	hints []compiled.Hint // solver hints

	// debug info
	logs                 []logEntry // list of logs to be printed when solving a circuit. The logs are called with the method Println
	debugInfoComputation []logEntry // list of logs storing information about computations (e.g. division by 0).If an computation fails, it prints it in a friendly format
	debugInfoAssertion   []logEntry // list of logs storing information about assertions. If an assertion fails, it prints it in a friendly format
	unsetVariables       []logEntry // unset variables. If a variable is unset, the error is caught when compiling the circuit

}

// CompiledConstraintSystem ...
type CompiledConstraintSystem interface {
	io.WriterTo
	io.ReaderFrom

	// GetNbVariables return number of internal, secret and public variables
	GetNbVariables() (internal, secret, public int)
	GetNbConstraints() int
	GetNbCoefficients() int

	// SetLoggerOutput replace existing logger output with provided one
	SetLoggerOutput(w io.Writer)

	CurveID() ecc.ID
	FrSize() int
}

// initialCapacity has quite some impact on frontend performance, especially on large circuits size
// we may want to add build tags to tune that
func newConstraintSystem(initialCapacity ...int) ConstraintSystem {
	capacity := 0
	if len(initialCapacity) > 0 {
		capacity = initialCapacity[0]
	}
	cs := ConstraintSystem{
		coeffs:      make([]big.Int, 4),
		coeffsIDs:   make(map[string]int),
		constraints: make([]compiled.R1C, 0, capacity),
		assertions:  make([]compiled.R1C, 0),
	}

	cs.coeffs[compiled.CoeffIdZero].SetInt64(0)
	cs.coeffs[compiled.CoeffIdOne].SetInt64(1)
	cs.coeffs[compiled.CoeffIdTwo].SetInt64(2)
	cs.coeffs[compiled.CoeffIdMinusOne].SetInt64(-1)

	cs.public.variables = make([]Variable, 0)
	cs.public.booleans = make(map[int]struct{})

	cs.secret.variables = make([]Variable, 0)
	cs.secret.booleans = make(map[int]struct{})

	cs.internal.variables = make([]Variable, 0, capacity)
	cs.internal.booleans = make(map[int]struct{})

	// by default the circuit is given on public wire equal to 1
	cs.public.variables[0] = cs.newPublicVariable()

	cs.hints = make([]compiled.Hint, 0)

	return cs
}

// NewHint initialize a variable whose value will be evaluated in the Prover by the constraint
// solver using the provided hint function
// hint function is provided at proof creation time and must match the hintID
// inputs must be either variables or convertible to big int
// /!\ warning /!\
// this doesn't add any constraint to the newly created wire
// from the backend point of view, it's equivalent to a user-supplied witness
// except, the solver is going to assign it a value, not the caller
func (cs *ConstraintSystem) NewHint(hintID hint.ID, inputs ...interface{}) Variable {
	// create resulting wire
	r := cs.newInternalVariable()

	// now we need to store the linear expressions of the expected input
	// that will be resolved in the solver
	hintInputs := make([]compiled.LinearExpression, len(inputs))

	// ensure inputs are set and pack them in a []uint64
	for i, in := range inputs {
		t := cs.Constant(in)
		hintInputs[i] = t.linExp.Clone() // TODO @gbotrel check that we need to clone here ?
	}

	// add the hint to the constraint system
	cs.hints = append(cs.hints, compiled.Hint{WireID: r.id, ID: hintID, Inputs: hintInputs})

	return r
}

// Println enables circuit debugging and behaves almost like fmt.Println()
//
// the print will be done once the R1CS.Solve() method is executed
//
// if one of the input is a Variable, its value will be resolved avec R1CS.Solve() method is called
func (cs *ConstraintSystem) Println(a ...interface{}) {
	var sbb strings.Builder

	// prefix log line with file.go:line
	if _, file, line, ok := runtime.Caller(1); ok {
		sbb.WriteString(filepath.Base(file))
		sbb.WriteByte(':')
		sbb.WriteString(strconv.Itoa(line))
		sbb.WriteByte(' ')
	}

	// for each argument, if it is a circuit structure and contains variable
	// we add the variables in the logEntry.toResolve part, and add %s to the format string in the log entry
	// if it doesn't contain variable, call fmt.Sprint(arg) instead
	entry := logEntry{}

	// this is call recursively on the arguments using reflection on each argument
	foundVariable := false

	var handler logValueHandler = func(name string, tInput reflect.Value) {

		v := tInput.Interface().(Variable)

		// if the variable is only in linExp form, we allocate it
		_v := cs.allocate(v)

		entry.toResolve = append(entry.toResolve, compiled.Pack(_v.id, 0, _v.visibility))

		if name == "" {
			sbb.WriteString("%s")
		} else {
			sbb.WriteString(fmt.Sprintf("%s: %%s ", name))
		}

		foundVariable = true
	}

	for i, arg := range a {
		if i > 0 {
			sbb.WriteByte(' ')
		}
		foundVariable = false
		parseLogValue(arg, "", handler)
		if !foundVariable {
			sbb.WriteString(fmt.Sprint(arg))
		}
	}
	sbb.WriteByte('\n')

	// set format string to be used with fmt.Sprintf, once the variables are solved in the R1CS.Solve() method
	entry.format = sbb.String()

	cs.logs = append(cs.logs, entry)
}

type logEntry struct {
	format    string
	toResolve []compiled.Term
}

var (
	bOne = new(big.Int).SetInt64(1)
)

// debug info in case a variable is not set
// func debugInfoUnsetVariable(term compiled.Term) logEntry {
// 	entry := logEntry{}
// 	stack := getCallStack()
// 	entry.format = stack[len(stack)-1]
// 	entry.toResolve = append(entry.toResolve, term)
// 	return entry
// }

func (cs *ConstraintSystem) one() Variable {
	return cs.public.variables[0]
}

// Term packs a variable and a coeff in a compiled.Term and returns it.
func (cs *ConstraintSystem) makeTerm(v Wire, coeff *big.Int) compiled.Term {
	return compiled.Pack(v.id, cs.coeffID(coeff), v.visibility)
}

// newR1C clones the linear expression associated with the variables (to avoid offseting the ID multiple time)
// and return a R1C
func newR1C(l, r, o Variable, s ...compiled.SolvingMethod) compiled.R1C {
	solver := compiled.SingleOutput
	if len(s) > 0 {
		solver = s[0]
	}

	// interestingly, this is key to groth16 performance.
	// l * r == r * l == o
	// but the "l" linear expression is going to end up in the A matrix
	// the "r" linear expression is going to end up in the B matrix
	// the less variable we have appearing in the B matrix, the more likely groth16.Setup
	// is going to produce infinity points in pk.G1.B and pk.G2.B, which will speed up proving time
	if solver == compiled.SingleOutput && len(l.linExp) > len(r.linExp) {
		l, r = r, l
	}

	return compiled.R1C{L: l.linExp.Clone(), R: r.linExp.Clone(), O: o.linExp.Clone(), Solver: solver}
}

// NbConstraints enables circuit profiling and helps debugging
// It returns the number of constraints created at the current stage of the circuit construction.
//
// The number returns included both the assertions and the non-assertion constraints
// (eg: the constraints which creates a new variable)
func (cs *ConstraintSystem) NbConstraints() int {
	return len(cs.constraints) + len(cs.assertions)
}

// LinearExpression packs a list of compiled.Term in a compiled.LinearExpression and returns it.
func (cs *ConstraintSystem) LinearExpression(terms ...compiled.Term) compiled.LinearExpression {
	res := make(compiled.LinearExpression, len(terms))
	for i, args := range terms {
		res[i] = args
	}
	return res
}

// reduces redundancy in linear expression
// It factorizes variable that appears multiple times with != coeff Ids
// To ensure the determinism in the compile process, variables are stored as public||secret||internal||unset
// for each visibility, the variables are sorted from lowest ID to highest ID
func (cs *ConstraintSystem) reduce(l compiled.LinearExpression) compiled.LinearExpression {
	// ensure our linear expression is sorted, by visibility and by variable ID
	if !sort.IsSorted(l) { // may not help
		sort.Sort(l)
	}

	var c big.Int
	for i := 1; i < len(l); i++ {
		pcID, pvID, pVis := l[i-1].Unpack()
		ccID, cvID, cVis := l[i].Unpack()
		if pVis == cVis && pvID == cvID {
			// we have redundancy
			c.Add(&cs.coeffs[pcID], &cs.coeffs[ccID])
			l[i-1].SetCoeffID(cs.coeffID(&c))
			l = append(l[:i], l[i+1:]...)
			i--
		}
	}

	return l
}

func (cs *ConstraintSystem) addAssertion(constraint compiled.R1C, debugInfo logEntry) {
	cs.assertions = append(cs.assertions, constraint)
	cs.debugInfoAssertion = append(cs.debugInfoAssertion, debugInfo)
}

// coeffID tries to fetch the entry where b is if it exits, otherwise appends b to
// the list of coeffs and returns the corresponding entry
func (cs *ConstraintSystem) coeffID(b *big.Int) int {

	// if the coeff is a int64, and has value -1, 0, 1 or 2, we have a fast path.
	if b.IsInt64() {
		v := b.Int64()
		switch v {
		case -1:
			return compiled.CoeffIdMinusOne
		case 0:
			return compiled.CoeffIdZero
		case 1:
			return compiled.CoeffIdOne
		case 2:
			return compiled.CoeffIdTwo
		}
	}

	// if the coeff is already stored, fetch its ID from the cs.coeffsIDs map
	key := b.Text(16)
	if idx, ok := cs.coeffsIDs[key]; ok {
		return idx
	}

	// else add it in the cs.coeffs map and update the cs.coeffsIDs map
	var bCopy big.Int
	bCopy.Set(b)
	resID := len(cs.coeffs)
	cs.coeffs = append(cs.coeffs, bCopy)
	cs.coeffsIDs[key] = resID
	return resID
}

// if v is unset and linExp is non empty, the variable is allocated
// resulting in one more constraint in the system. If v is set OR v is
// unset and linexp is emppty, it does nothing.
func (cs *ConstraintSystem) allocate(v Variable) Variable {
	if v.visibility == compiled.Unset && len(v.linExp) > 0 {
		iv := cs.newInternalVariable()
		one := cs.one()
		cs.constraints = append(cs.constraints, newR1C(v, one, iv))
		return iv
	}
	return v
}

// newInternalVariable creates a new wire, appends it on the list of wires of the circuit, sets
// the wire's id to the number of wires, and returns it
func (cs *ConstraintSystem) newInternalVariable() Variable {
	w := Wire{
		id:         len(cs.internal.variables),
		visibility: compiled.Internal,
	}
	v := cs.buildVarFromWire(w)
	cs.internal.variables = append(cs.internal.variables, v)
	return v
}

// newPublicVariable creates a new public input
func (cs *ConstraintSystem) newPublicVariable() Variable {

	idx := len(cs.public.variables)
	w := Wire{compiled.Public, idx, nil}

	v := cs.buildVarFromWire(w)
	cs.public.variables = append(cs.public.variables, v)
	return v
}

// newSecretVariable creates a new secret input
func (cs *ConstraintSystem) newSecretVariable() Variable {
	idx := len(cs.secret.variables)
	w := Wire{compiled.Secret, idx, nil}

	v := cs.buildVarFromWire(w)
	cs.secret.variables = append(cs.secret.variables, v)
	return v
}

type logValueHandler func(name string, tValue reflect.Value)

func appendName(baseName, name string) string {
	if baseName == "" {
		return name
	}
	return baseName + "_" + name
}

func parseLogValue(input interface{}, name string, handler logValueHandler) {
	tVariable := reflect.TypeOf(Variable{})

	tValue := reflect.ValueOf(input)
	if tValue.Kind() == reflect.Ptr {
		tValue = tValue.Elem()
	}
	switch tValue.Kind() {
	case reflect.Struct:
		switch tValue.Type() {
		case tVariable:
			handler(name, tValue)
			return
		default:
			for i := 0; i < tValue.NumField(); i++ {
				if tValue.Field(i).CanInterface() {
					value := tValue.Field(i).Interface()
					_name := appendName(name, tValue.Type().Field(i).Name)
					parseLogValue(value, _name, handler)
				}
			}
		}
	case reflect.Slice, reflect.Array:
		if tValue.Len() == 0 {
			fmt.Println("warning, got unitizalized slice (or empty array). Ignoring;")
			return
		}
		for j := 0; j < tValue.Len(); j++ {
			value := tValue.Index(j).Interface()
			entry := "[" + strconv.Itoa(j) + "]"
			_name := appendName(name, entry)
			parseLogValue(value, _name, handler)
		}
	}
}

// derived from: https://golang.org/pkg/runtime/#example_Frames
// we stop when func name == Define as it is where the gnark circuit code should start
func getCallStack() []string {
	// Ask runtime.Callers for up to 10 pcs
	pc := make([]uintptr, 10)
	n := runtime.Callers(3, pc)
	if n == 0 {
		// No pcs available. Stop now.
		// This can happen if the first argument to runtime.Callers is large.
		return nil
	}
	pc = pc[:n] // pass only valid pcs to runtime.CallersFrames
	frames := runtime.CallersFrames(pc)
	// Loop to get frames.
	// A fixed number of pcs can expand to an indefinite number of Frames.
	var toReturn []string
	for {
		frame, more := frames.Next()
		fe := strings.Split(frame.Function, "/")
		function := fe[len(fe)-1]
		toReturn = append(toReturn, fmt.Sprintf("%s\n\t%s:%d", function, frame.File, frame.Line))
		if !more {
			break
		}
		if strings.HasSuffix(function, "Define") {
			break
		}
	}
	return toReturn
}

func (cs *ConstraintSystem) buildVarFromWire(pv Wire) Variable {
	return Variable{pv, cs.LinearExpression(cs.makeTerm(pv, bOne))}
}

// creates a string formatted to display correctly a variable, from its linear expression representation
// (i.e. the linear expression leading to it)
func (cs *ConstraintSystem) buildLogEntryFromVariable(v Variable) logEntry {

	var res logEntry
	var sbb strings.Builder
	sbb.Grow(len(v.linExp) * len(" + (xx + xxxxxxxxxxxx"))

	for i := 0; i < len(v.linExp); i++ {
		if i > 0 {
			sbb.WriteString(" + ")
		}
		c := cs.coeffs[v.linExp[i].CoeffID()]
		sbb.WriteString(fmt.Sprintf("(%%s * %s)", c.String()))
	}
	res.format = sbb.String()
	res.toResolve = v.linExp.Clone()
	return res
}

// markBoolean marks the variable as boolean and return true
// if a constraint was added, false if the variable was already
// constrained as a boolean
func (cs *ConstraintSystem) markBoolean(v Variable) bool {
	switch v.visibility {
	case compiled.Internal:
		if _, ok := cs.internal.booleans[v.id]; ok {
			return false
		}
		cs.internal.booleans[v.id] = struct{}{}
	case compiled.Secret:
		if _, ok := cs.secret.booleans[v.id]; ok {
			return false
		}
		cs.secret.booleans[v.id] = struct{}{}
	case compiled.Public:
		if _, ok := cs.public.booleans[v.id]; ok {
			return false
		}
		cs.public.booleans[v.id] = struct{}{}
	default:
		panic("not implemented")
	}
	return true
}
