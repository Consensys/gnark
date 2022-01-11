package utils

import (
	"fmt"
	"reflect"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
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

	var collectHandler schema.LeafHandler = func(visibility schema.Visibility, name string, tInput reflect.Value) error {
		v := tInput.Interface().(frontend.Variable)

		if visibility == schema.Secret || visibility == schema.Public {
			if v == nil {
				return fmt.Errorf("when parsing variable %s: missing assignment", name)
			}
			wValues = append(wValues, v)
		}
		return nil
	}
	if _, err := schema.Parse(from, tVariable, collectHandler); err != nil {
		panic(err)
	}

	i := 0
	var setHandler schema.LeafHandler = func(visibility schema.Visibility, name string, tInput reflect.Value) error {
		if visibility == schema.Secret || visibility == schema.Public {
			tInput.Set(reflect.ValueOf((wValues[i])))
			i++
		}
		return nil
	}
	// this can't error.
	_, _ = schema.Parse(to, tVariable, setHandler)

}

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A frontend.Variable }{}).FieldByName("A").Type()
}
