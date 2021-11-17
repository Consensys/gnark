/*
Copyright © 2021 ConsenSys Software Inc.

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
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/internal/backend/compiled"
	"github.com/consensys/gnark/internal/parser"
)

// Println enables circuit debugging and behaves almost like fmt.Println()
//
// the print will be done once the R1CS.Solve() method is executed
//
// if one of the input is a variable, its value will be resolved avec R1CS.Solve() method is called
func (cs *constraintSystem) Println(a ...interface{}) {
	var sbb strings.Builder

	// prefix log line with file.go:line
	if _, file, line, ok := runtime.Caller(1); ok {
		sbb.WriteString(filepath.Base(file))
		sbb.WriteByte(':')
		sbb.WriteString(strconv.Itoa(line))
		sbb.WriteByte(' ')
	}

	var log compiled.LogEntry

	for i, arg := range a {
		if i > 0 {
			sbb.WriteByte(' ')
		}
		if v, ok := arg.(variable); ok {
			v.assertIsSet(cs)

			sbb.WriteString("%s")
			// we set limits to the linear expression, so that the log printer
			// can evaluate it before printing it
			log.ToResolve = append(log.ToResolve, compiled.TermDelimitor)
			log.ToResolve = append(log.ToResolve, v.linExp...)
			log.ToResolve = append(log.ToResolve, compiled.TermDelimitor)
		} else {
			printArg(&log, &sbb, arg)
		}
	}
	sbb.WriteByte('\n')

	// set format string to be used with fmt.Sprintf, once the variables are solved in the R1CS.Solve() method
	log.Format = sbb.String()

	cs.logs = append(cs.logs, log)
}

func printArg(log *compiled.LogEntry, sbb *strings.Builder, a interface{}) {

	count := 0
	counter := func(visibility compiled.Visibility, name string, tValue reflect.Value) error {
		count++
		return nil
	}
	// ignoring error, counter() always return nil
	_ = parser.Visit(a, "", compiled.Unset, counter, tVariable)

	// no variables in nested struct, we use fmt std print function
	if count == 0 {
		sbb.WriteString(fmt.Sprint(a))
		return
	}

	sbb.WriteByte('{')
	printer := func(visibility compiled.Visibility, name string, tValue reflect.Value) error {
		count--
		sbb.WriteString(name)
		sbb.WriteString(": ")
		sbb.WriteString("%s")
		if count != 0 {
			sbb.WriteString(", ")
		}

		v := tValue.Interface().(variable)
		// we set limits to the linear expression, so that the log printer
		// can evaluate it before printing it
		log.ToResolve = append(log.ToResolve, compiled.TermDelimitor)
		log.ToResolve = append(log.ToResolve, v.linExp...)
		log.ToResolve = append(log.ToResolve, compiled.TermDelimitor)
		return nil
	}
	// ignoring error, printer() doesn't return errors
	_ = parser.Visit(a, "", compiled.Unset, printer, tVariable)
	sbb.WriteByte('}')
}

func (cs *constraintSystem) addDebugInfo(errName string, i ...interface{}) int {
	var l compiled.LogEntry

	const minLogSize = 500
	var sbb strings.Builder
	sbb.Grow(minLogSize)
	sbb.WriteString("[")
	sbb.WriteString(errName)
	sbb.WriteString("] ")

	for _, _i := range i {
		switch v := _i.(type) {
		case variable:
			if len(v.linExp) > 1 {
				sbb.WriteString("(")
			}
			l.WriteLinearExpression(v.linExp, &sbb)
			if len(v.linExp) > 1 {
				sbb.WriteString(")")
			}

		case string:
			sbb.WriteString(v)
		case int:
			sbb.WriteString(strconv.Itoa(v))
		case compiled.Term:
			l.WriteTerm(v, &sbb)
		default:
			panic("unsupported log type")
		}
	}
	sbb.WriteByte('\n')
	debug.WriteStack(&sbb)
	l.Format = sbb.String()

	cs.debugInfo = append(cs.debugInfo, l)
	return len(cs.debugInfo) - 1
}
