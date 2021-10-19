package utils

import (
	"fmt"
	"reflect"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/backend/compiled"
	"github.com/consensys/gnark/internal/parser"
)

// CloneCircuit clones given circuit
func CloneCircuit(circuit frontend.Circuit) frontend.Circuit {
	cValue := reflect.ValueOf(circuit).Elem()
	newCircuit := reflect.New(cValue.Type())
	newCircuit.Elem().Set(cValue)

	c, ok := newCircuit.Interface().(frontend.Circuit)
	if !ok {
		panic("couldn't clone the circuit")
	}
	return c
}

// ResetWitness parses the reachable frontend.Variable values in the given circuit and sets them to nil
func ResetWitness(c frontend.Circuit) {
	var setHandler parser.LeafHandler = func(visibility compiled.Visibility, name string, tInput reflect.Value) error {
		if visibility == compiled.Secret || visibility == compiled.Public {
			tInput.Set(reflect.ValueOf(frontend.Value(nil)))
		}
		return nil
	}
	// this can't error.
	_ = parser.Visit(c, "", compiled.Unset, setHandler, reflect.TypeOf(frontend.Variable{}))
}

func CopyWitness(to, from frontend.Circuit) {
	var wValues []interface{}

	var collectHandler parser.LeafHandler = func(visibility compiled.Visibility, name string, tInput reflect.Value) error {
		v := tInput.Interface().(frontend.Variable)

		if visibility == compiled.Secret || visibility == compiled.Public {
			if v.WitnessValue == nil {
				return fmt.Errorf("when parsing variable %s: missing assignment", name)
			}
			wValues = append(wValues, v.WitnessValue)
		}
		return nil
	}
	if err := parser.Visit(from, "", compiled.Unset, collectHandler, reflect.TypeOf(frontend.Variable{})); err != nil {
		panic(err)
	}

	i := 0
	var setHandler parser.LeafHandler = func(visibility compiled.Visibility, name string, tInput reflect.Value) error {
		if visibility == compiled.Secret || visibility == compiled.Public {
			tInput.Set(reflect.ValueOf(frontend.Value(wValues[i])))
			i++
		}
		return nil
	}
	// this can't error.
	_ = parser.Visit(to, "", compiled.Unset, setHandler, reflect.TypeOf(frontend.Variable{}))

}
