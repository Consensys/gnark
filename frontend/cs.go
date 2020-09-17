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
	"math/big"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/backend/r1cs/r1c"
	"github.com/consensys/gurvy"
)

// ConstraintSystem represents a Groth16 like circuit
type ConstraintSystem struct {
	publicVariableNames []string            // public inputs names
	publicVariables     []Variable          // public inputs
	secretVariableNames []string            // private inputs names
	secretVariables     []Variable          // private inputs
	internalVariables   []Variable          // internal variables
	coeffs              []big.Int           // list of unique coefficients.
	coeffsIDs           map[string]int      // helper map to check existence of a coefficient: string(b) -> ID, where coeffs[ID]=b (b is a big.Int)
	booleanVariables    [3]map[int]struct{} // helper to monitor boolean varialbes (to constrain them only once). One map for each of public, secret, internal variables.
	constraints         []r1c.R1C           // list of R1C that yield an output (for example v3 == v1 * v2, return v3)
	assertions          []r1c.R1C           // list of R1C that yield no output (for example ensuring v1 == v2)
	logs                []logEntry          // list of logs to be printed when solving a circuit. The logs are called with the method Println
	debugInfo           []logEntry          // list of logs storing information about assertions. If an assertion fails, it prints it in a friendly format
	oneTerm             r1c.Term
}

type logEntry struct {
	format    string
	toResolve []r1c.Term
}

// this has quite some impact on frontend performance, especially on large circuits size
// we may want to add build tags to tune that
const initialCapacity = 1e6

// newConstraintSystem outputs a new circuit
func newConstraintSystem() ConstraintSystem {
	cs := ConstraintSystem{
		publicVariableNames: make([]string, 1),
		publicVariables:     make([]Variable, 1),
		secretVariableNames: make([]string, 0),
		secretVariables:     make([]Variable, 0),
		internalVariables:   make([]Variable, 0, initialCapacity),
		coeffs:              make([]big.Int, 0),
		coeffsIDs:           make(map[string]int),
		booleanVariables:    [3]map[int]struct{}{make(map[int]struct{}), make(map[int]struct{}), make(map[int]struct{})},
		constraints:         make([]r1c.R1C, 0, initialCapacity),
		assertions:          make([]r1c.R1C, 0),
	}

	// first entry of circuit is backend.OneWire
	cs.publicVariableNames[0] = backend.OneWire
	cs.publicVariables[0] = Variable{backend.Public, 0, nil}
	cs.oneTerm = cs.Term(cs.publicVariables[0], bOne)

	return cs
}

var (
	bMinusOne = new(big.Int).SetInt64(-1)
	bZero     = new(big.Int)
	bOne      = new(big.Int).SetInt64(1)
	bTwo      = new(big.Int).SetInt64(2)
)

// Term packs a variable and a coeff in a r1c.Term and returns it.
func (cs *ConstraintSystem) Term(v Variable, coeff *big.Int) r1c.Term {
	if v.visibility == backend.Unset {
		panic("variable is not allocated.")
	}
	term := r1c.Pack(v.id, cs.coeffID(coeff), v.visibility)
	if coeff.Cmp(bZero) == 0 {
		term.SetCoeffValue(0)
	} else if coeff.Cmp(bOne) == 0 {
		term.SetCoeffValue(1)
	} else if coeff.Cmp(bTwo) == 0 {
		term.SetCoeffValue(2)
	} else if coeff.Cmp(bMinusOne) == 0 {
		term.SetCoeffValue(-1)
	}
	return term
}

// LinearExpression packs a list of r1c.Term in a r1c.LinearExpression and returns it.
// The point of this wrapper is to call every complex expression (Term, LinearExpression)
// from the cs only, and not have non homogeneous api.
func (cs *ConstraintSystem) LinearExpression(terms ...r1c.Term) r1c.LinearExpression {
	res := make(r1c.LinearExpression, len(terms))
	for i, args := range terms {
		res[i] = args
	}
	return res
}

func (cs *ConstraintSystem) addAssertion(constraint r1c.R1C, debugInfo logEntry) {
	cs.assertions = append(cs.assertions, constraint)
	cs.debugInfo = append(cs.debugInfo, debugInfo)
}

// toR1CS constructs a rank-1 constraint sytem
func (cs *ConstraintSystem) toR1CS(curveID gurvy.ID) r1cs.R1CS {

	// wires = intermediatevariables | secret inputs | public inputs

	// setting up the result
	res := r1cs.UntypedR1CS{
		NbWires:         len(cs.internalVariables) + len(cs.publicVariables) + len(cs.secretVariables),
		NbPublicWires:   len(cs.publicVariables),
		NbSecretWires:   len(cs.secretVariables),
		NbConstraints:   len(cs.constraints) + len(cs.assertions),
		NbCOConstraints: len(cs.constraints),
		Constraints:     make([]r1c.R1C, len(cs.constraints)+len(cs.assertions)),
		SecretWires:     cs.secretVariableNames,
		PublicWires:     cs.publicVariableNames,
		Coefficients:    cs.coeffs,
		Logs:            make([]backend.LogEntry, len(cs.logs)),
		DebugInfo:       make([]backend.LogEntry, len(cs.debugInfo)),
	}

	// computational constraints (= gates)
	copy(res.Constraints, cs.constraints)
	copy(res.Constraints[len(cs.constraints):], cs.assertions)

	// we just need to offset our ids, such that wires = [internalVariables | secretVariables | publicVariables]
	offsetIDs := func(exp r1c.LinearExpression) {
		for j := 0; j < len(exp); j++ {
			_, _, cID, cVisibility := exp[j].Unpack()
			switch cVisibility {
			case backend.Public:
				exp[j].SetConstraintID(cID + len(cs.internalVariables) + len(cs.secretVariables))
			case backend.Secret:
				exp[j].SetConstraintID(cID + len(cs.internalVariables))
			case backend.Unset:
				panic("shouldn't happen")
			}
		}
	}

	for i := 0; i < len(res.Constraints); i++ {
		offsetIDs(res.Constraints[i].L)
		offsetIDs(res.Constraints[i].R)
		offsetIDs(res.Constraints[i].O)
	}

	// we need to offset the ids in logs too
	for i := 0; i < len(cs.logs); i++ {
		entry := backend.LogEntry{
			Format: cs.logs[i].format,
		}
		for j := 0; j < len(cs.logs[i].toResolve); j++ {
			_, _, cID, cVisibility := cs.logs[i].toResolve[j].Unpack()
			switch cVisibility {
			case backend.Public:
				cID += len(cs.internalVariables) + len(cs.secretVariables)
			case backend.Secret:
				cID += len(cs.internalVariables)
			case backend.Unset:
				panic("shouldn't happen")
			}
			entry.ToResolve = append(entry.ToResolve, cID)
		}

		res.Logs[i] = entry
	}

	// offset ids in the debugInfo
	for i := 0; i < len(cs.debugInfo); i++ {
		entry := backend.LogEntry{
			Format: cs.debugInfo[i].format,
		}
		for j := 0; j < len(cs.debugInfo[i].toResolve); j++ {
			_, _, cID, cVisibility := cs.debugInfo[i].toResolve[j].Unpack()
			switch cVisibility {
			case backend.Public:
				cID += len(cs.internalVariables) + len(cs.secretVariables)
			case backend.Secret:
				cID += len(cs.internalVariables)
			case backend.Unset:
				panic("shouldn't happen")
			}
			entry.ToResolve = append(entry.ToResolve, cID)
		}

		res.DebugInfo[i] = entry
	}

	if curveID == gurvy.UNKNOWN {
		return &res
	}

	return res.ToR1CS(curveID)
}

// coeffID tries to fetch the entry where b is if it exits, otherwise appends b to
// the list of coeffs and returns the corresponding entry
func (cs *ConstraintSystem) coeffID(b *big.Int) int {

	// if the coeff is already stored, fetch its ID from the cs.coeffsIDs map
	key := b.String()
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

// Println ...
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
		entry.toResolve = append(entry.toResolve, r1c.Pack(v.id, 0, v.visibility))
		if name == "" {
			sbb.WriteString("%s")
		} else {
			sbb.WriteString(fmt.Sprintf("[%s: %%s]", name))
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

// newInternalVariable creates a new wire, appends it on the list of wires of the circuit, sets
// the wire's id to the number of wires, and returns it
func (cs *ConstraintSystem) newInternalVariable() Variable {
	res := Variable{
		id:         len(cs.internalVariables),
		visibility: backend.Internal,
	}
	cs.internalVariables = append(cs.internalVariables, res)
	return res
}

// newPublicVariable creates a new public input
func (cs *ConstraintSystem) newPublicVariable(name string) Variable {
	idx := len(cs.publicVariables)
	res := Variable{backend.Public, idx, nil}

	// checks if the name is not already picked
	for _, v := range cs.publicVariableNames {
		if v == name {
			panic("duplicate input name (public)")
		}
	}

	cs.publicVariableNames = append(cs.publicVariableNames, name)
	cs.publicVariables = append(cs.publicVariables, res)
	return res
}

// newSecretVariable creates a new secret input
func (cs *ConstraintSystem) newSecretVariable(name string) Variable {
	idx := len(cs.secretVariables)
	res := Variable{backend.Secret, idx, nil}

	// checks if the name is not already picked
	for _, v := range cs.publicVariableNames {
		if v == name {
			panic("duplicate input name (secret)")
		}
	}

	cs.secretVariableNames = append(cs.secretVariableNames, name)
	cs.secretVariables = append(cs.secretVariables, res)
	return res
}

// oneVariable returns the variable associated with backend.OneWire
func (cs *ConstraintSystem) oneVariable() Variable {
	return cs.publicVariables[0]
}

type logValueHandler func(name string, tValue reflect.Value)

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

				value := tValue.Field(i).Interface()
				parseLogValue(value, tValue.Type().Field(i).Name, handler)
			}
		}
	}
}

// derived from: https://golang.org/pkg/runtime/#example_Frames
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
