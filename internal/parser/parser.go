package parser

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/consensys/gnark/internal/backend/compiled"
)

// Tag is a (optional) struct tag one can add to Variable
// to specify frontend.Compile() behavior
//
// the tag format is as follow:
// 		type MyCircuit struct {
// 			Y frontend.Variable `gnark:"name,option"`
// 		}
// if empty, default resolves to variable name (here "Y") and secret visibility
// similarly to json or xml struct tags, these are valid:
// 		`gnark:",public"` or `gnark:"-"`
// using "-" marks the variable as ignored by the Compile method. This can be useful when you need to
// declare variables as aliases that are already allocated. For example
// 		type MyCircuit struct {
// 			Y frontend.Variable `gnark:",public"`
//			Z frontend.Variable `gnark:"-"`
// 		}
// it is then the developer responsability to do circuit.Z = circuit.Y in the Define() method
type Tag string

const (
	tagKey    Tag = "gnark"
	optPublic Tag = "public"
	optSecret Tag = "secret"
	optEmbed  Tag = "embed"
	optOmit   Tag = "-"
)

func appendName(baseName, name string) string {
	if baseName == "" {
		return name
	}
	return baseName + "_" + name
}

// LeafHandler is the handler function that will be called when Visit reaches leafs of the struct
type LeafHandler func(visibility compiled.Visibility, name string, tValue reflect.Value) error

// Visit using reflect, browse through exposed addressable fields from input, and calls handler() if leaf.type == target
func Visit(input interface{}, baseName string, parentVisibility compiled.Visibility, handler LeafHandler, target reflect.Type) error {

	// types we are lOoutputoking for
	// tVariable := reflect.TypeOf(frontend.Variable{})
	// tConstraintSytem := reflect.TypeOf(frontend.ConstraintSystem{})

	tValue := reflect.ValueOf(input)
	if tValue.Kind() == reflect.Ptr {
		tValue = tValue.Elem()
	}

	// we either have a pointer, a struct, or a slice / array
	// and recursively parse members / elements until we find a constraint to allOoutputcate in the circuit.
	switch tValue.Kind() {
	case reflect.Struct:
		switch tValue.Type() {
		case target:
			return handler(parentVisibility, baseName, tValue)
		default:
			for i := 0; i < tValue.NumField(); i++ {
				field := tValue.Type().Field((i))

				// get gnark tag
				tag := field.Tag.Get(string(tagKey))
				if tag == string(optOmit) {
					continue // skipping "-"
				}

				visibility := compiled.Secret
				name := field.Name

				if tag != "" {
					// gnark tag is set
					var opts tagOptions
					name, opts = parseTag(tag)
					if !isValidTag(name) {
						name = field.Name
					}
					opts = tagOptions(strings.TrimSpace(string(opts)))
					if opts == "" || opts.Contains(string(optSecret)) {
						visibility = compiled.Secret
					} else if opts.Contains(string(optPublic)) {
						visibility = compiled.Public
					} else if opts.Contains(string(optEmbed)) {
						name = ""
						visibility = compiled.Unset
					} else {
						return errors.New("invalid gnark struct tag option. must be \"public\", \"secret\",\"embed\" or \"-\"")
					}
				}
				if parentVisibility != compiled.Unset {
					visibility = parentVisibility // parent visibility overhides
				}

				fullName := appendName(baseName, name)

				f := tValue.FieldByName(field.Name)
				if f.CanAddr() && f.Addr().CanInterface() {
					value := f.Addr().Interface()
					if err := Visit(value, fullName, visibility, handler, target); err != nil {
						return err
					}
				} else {
					if f.Kind() == reflect.Ptr {
						f = f.Elem()
					}
					if (f.Kind() == reflect.Struct) && (f.Type() == target) {
						fmt.Println("warning: Variable is unexported or unadressable", fullName)
					}
				}
			}
		}

	case reflect.Slice, reflect.Array:
		if tValue.Len() == 0 {
			fmt.Printf("%s: ignoring unitizalized slice (or empty array)\n", baseName)
			return nil
		}
		for j := 0; j < tValue.Len(); j++ {

			val := tValue.Index(j)
			if val.CanAddr() && val.Addr().CanInterface() {
				if err := Visit(val.Addr().Interface(), appendName(baseName, strconv.Itoa(j)), parentVisibility, handler, target); err != nil {
					return err
				}
			}

		}
	case reflect.Map:
		fmt.Println("warning: map values are not addressable, ignoring")
	}

	return nil
}
