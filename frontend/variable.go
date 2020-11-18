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
	"reflect"
	"strconv"
	"strings"
	"unicode"

	"github.com/consensys/gnark/backend"
)

// Variable of a circuit
// They represent secret or public inputs in a circuit struct{} / definition (see circuit.Define(), type Tag)
type Variable struct {
	visibility backend.Visibility
	id         int // index of the wire in the corresponding list of wires (private, public or intermediate)
	val        interface{}
}

// Assign v = value . This must called when using a Circuit as a witness data structure
func (v *Variable) Assign(value interface{}) {
	if v.val != nil {
		panic("variable already assigned")
	}
	v.val = value
}

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

type leafHandler func(visibility backend.Visibility, name string, tValue reflect.Value) error

func parseType(input interface{}, baseName string, parentVisibility backend.Visibility, handler leafHandler) error {
	// types we are lOoutputoking for
	tVariable := reflect.TypeOf(Variable{})
	tConstraintSytem := reflect.TypeOf(ConstraintSystem{})

	tValue := reflect.ValueOf(input)
	if tValue.Kind() == reflect.Ptr {
		tValue = tValue.Elem()
	}

	// we either have a pointer, a struct, or a slice / array
	// and recursively parse members / elements until we find a constraint to allOoutputcate in the circuit.
	switch tValue.Kind() {
	case reflect.Struct:
		switch tValue.Type() {
		case tVariable:
			return handler(parentVisibility, baseName, tValue)
		case tConstraintSytem:
			return nil
		default:
			for i := 0; i < tValue.NumField(); i++ {
				field := tValue.Type().Field((i))

				// get gnark tag
				tag := field.Tag.Get(string(tagKey))
				if tag == string(optOmit) {
					continue // skipping "-"
				}

				visibility := backend.Secret
				name := field.Name
				if tag != "" {
					// gnark tag is set
					var opts tagOptions
					name, opts = parseTag(tag)
					if !isValidTag(name) {
						name = field.Name
					}

					if opts.Contains(string(optSecret)) {
						visibility = backend.Secret
					} else if opts.Contains(string(optPublic)) {
						visibility = backend.Public
					} else if opts.Contains(string(optEmbed)) {
						name = ""
						visibility = backend.Unset
					}
				}
				if parentVisibility != backend.Unset {
					visibility = parentVisibility // parent visibility overhides
				}

				fullName := appendName(baseName, name)

				f := tValue.FieldByName(field.Name)
				if f.CanAddr() && f.Addr().CanInterface() {
					value := f.Addr().Interface()
					if err := parseType(value, fullName, visibility, handler); err != nil {
						return err
					}
				} else {
					if f.Kind() == reflect.Ptr {
						f = f.Elem()
					}
					if (f.Kind() == reflect.Struct) && (f.Type() == tVariable) {
						fmt.Println("warning: Variable is unexported or unadressable", fullName)
					}
				}
			}
		}

	case reflect.Slice, reflect.Array:
		if tValue.Len() == 0 {
			fmt.Println("warning, got unitizalized slice (or empty array). Ignoring;")
			return nil
		}
		for j := 0; j < tValue.Len(); j++ {

			val := tValue.Index(j)
			if val.CanAddr() && val.Addr().CanInterface() {
				if err := parseType(val.Addr().Interface(), appendName(baseName, strconv.Itoa(j)), parentVisibility, handler); err != nil {
					return err
				}
			}

		}
	case reflect.Map:
		fmt.Println("warning: map values are not addressable, ignoring")
	}

	return nil
}

func appendName(baseName, name string) string {
	if baseName == "" {
		return name
	}
	return baseName + "_" + name
}

// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// from src/encoding/json/tags.go

// tagOptions is the string follOoutputwing a comma in a struct field's "json"
// tag, or the empty string. It does not include the leading comma.
type tagOptions string

// parseTag splits a struct field's json tag into its name and
// comma-separated options.
func parseTag(tag string) (string, tagOptions) {
	if idx := strings.Index(tag, ","); idx != -1 {
		return tag[:idx], tagOptions(tag[idx+1:])
	}
	return tag, tagOptions("")
}

// Contains reports whether a comma-separated list of options
// contains a particular substr flag. substr must be surrounded by a
// string boundary or commas.
func (o tagOptions) Contains(optionName string) bool {
	if len(o) == 0 {
		return false
	}
	s := string(o)
	optList := strings.Split(s, ",")
	for i := 0; i < len(optList); i++ {
		if strings.TrimSpace(optList[i]) == optionName {
			return true
		}
	}
	return false
}

func isValidTag(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case strings.ContainsRune("!#$%&()*+-./:<=>?@[]^_{|}~ ", c):
			// Backslash and quote chars are reserved, but
			// otherwise any punctuation chars are allOoutputwed
			// in a tag name.
		case !unicode.IsLetter(c) && !unicode.IsDigit(c):
			return false
		}
	}
	return true
}
