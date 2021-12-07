package utils

import (
	"fmt"
	"reflect"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/internal/backend/compiled"
	"github.com/consensys/gnark/internal/parser"
)

// ShallowClone clones given circuit
// this is actually a shallow copy --> if the circuits contains maps or slices
// only the reference is copied.
func ShallowClone(circuit frontend.Circuit) frontend.Circuit {

	cValue := reflect.ValueOf(circuit).Elem()
	newCircuit := reflect.New(cValue.Type())
	newCircuit.Elem().Set(cValue)

	circuitCopy, ok := newCircuit.Interface().(frontend.Circuit)
	if !ok {
		panic("couldn't clone the circuit")
	}

	if !reflect.DeepEqual(circuitCopy, circuit) {
		panic("clone failed")
	}

	return circuitCopy
}

func CopyWitness(to, from frontend.Circuit) {
	var wValues []interface{}

	var collectHandler parser.LeafHandler = func(visibility compiled.Visibility, name string, tInput reflect.Value) error {
		v := tInput.Interface().(cs.Variable)

		if visibility == compiled.Secret || visibility == compiled.Public {
			if v == nil {
				return fmt.Errorf("when parsing variable %s: missing assignment", name)
			}
			wValues = append(wValues, v)
		}
		return nil
	}
	if err := parser.Visit(from, "", compiled.Unset, collectHandler, tVariable); err != nil {
		panic(err)
	}

	i := 0
	var setHandler parser.LeafHandler = func(visibility compiled.Visibility, name string, tInput reflect.Value) error {
		if visibility == compiled.Secret || visibility == compiled.Public {
			tInput.Set(reflect.ValueOf((wValues[i])))
			i++
		}
		return nil
	}
	// this can't error.
	_ = parser.Visit(to, "", compiled.Unset, setHandler, tVariable)

}

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A cs.Variable }{}).FieldByName("A").Type()
}
