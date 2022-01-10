/*
Copyright © 2022 ConsenSys Software Inc.

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

package schema

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/consensys/gnark/internal/backend/compiled"
)

// Schema represents the structure of a gnark circuit (/ witness)
type Schema []Field

// LeafHandler is the handler function that will be called when Visit reaches leafs of the struct
type LeafHandler func(visibility compiled.Visibility, name string, tValue reflect.Value) error

// Parse filters recursively input data struct and keeps only the fields containing slices, arrays of elements of
// type frontend.Variable and return the corresponding  Slices are converted to arrays.
//
// If handler is specified, handler will be called on each encountered leaf (of type tLeaf)
func Parse(circuit interface{}, tLeaf reflect.Type, handler LeafHandler) (Schema, error) {
	// note circuit is of type interface{} instead of frontend.Circuit to avoid import cycle
	// same for tLeaf it is in practice always frontend.Variable
	return parse(nil, circuit, tLeaf, "", "", "", compiled.Unset, handler)
}

// Instantiate builds a concrete type using reflect matching the provided schema
//
// It replaces leafs by provided type, such that one can do:
//		struct { A []frontend.Variable} -> Schema -> struct {A [12]fr.Element}
func (s Schema) Instantiate(leafType reflect.Type) interface{} {

	// first, let's replace the Field by reflect.StructField
	is := toStructField(s, leafType)

	// now create the correspoinding type
	typ := reflect.StructOf(is)

	// instantiate the type
	v := reflect.New(typ).Elem()

	// return interface
	return v.Addr().Interface()
}

// toStructField recurse through Field and builds corresponding reflect.StructField
func toStructField(fields []Field, leafType reflect.Type) []reflect.StructField {
	r := make([]reflect.StructField, len(fields))

	for i, f := range fields {
		r[i] = reflect.StructField{
			Name: f.Name,
			Tag:  structTag(f.NameTag, f.Visibility),
		}
		switch f.Type {
		case Leaf:
			r[i].Type = leafType
		case Array:
			if len(f.SubFields) > 0 {
				// array of structs
				r[i].Type = reflect.ArrayOf(f.ArraySize, reflect.StructOf(toStructField(f.SubFields[0].SubFields, leafType)))
			} else {
				// array of leaf
				r[i].Type = reflect.ArrayOf(f.ArraySize, leafType)
			}
		case Struct:
			r[i].Type = reflect.StructOf(toStructField(f.SubFields, leafType))
		}
	}

	return r
}

func structTag(baseNameTag string, visibility compiled.Visibility) reflect.StructTag {
	if visibility == compiled.Unset {
		if baseNameTag != "" {
			return reflect.StructTag(fmt.Sprintf("gnark:\"%s\" json:\"%s\"", baseNameTag, baseNameTag))
		}
		return ""
	}
	if baseNameTag == "" {
		return reflect.StructTag(fmt.Sprintf("gnark:\",%s\"", visibility.String()))
	}
	return reflect.StructTag(fmt.Sprintf("gnark:\"%s,%s\" json:\"%s\"", baseNameTag, visibility.String(), baseNameTag))
}

// parentFullName: the name of parent with its ancestors separated by "_"
// parentGoName: the name of parent (Go struct definition)
// parentTagName: may be empty, set if a struct tag with name is set
func parse(r []Field, input interface{}, target reflect.Type, parentFullName, parentGoName, parentTagName string, parentVisibility compiled.Visibility, handler LeafHandler) ([]Field, error) {
	tValue := reflect.ValueOf(input)

	// get pointed value if needed
	if tValue.Kind() == reflect.Ptr {
		tValue = tValue.Elem()
	}

	// stop condition
	// if tValue.Kind() == reflect.Interface {
	if tValue.Type() == target {
		if handler != nil {
			v := parentVisibility
			if v == compiled.Unset {
				v = compiled.Secret
			}

			if err := handler(v, parentFullName, tValue); err != nil {
				return nil, err
			}
		}
		// we just add it to our current fields
		return append(r, Field{
			Name:       parentGoName,
			NameTag:    parentTagName,
			Type:       Leaf,
			Visibility: parentVisibility,
		}), nil
	}
	// }

	// struct
	if tValue.Kind() == reflect.Struct {
		var subFields []Field

		// get visible fields
		fields := reflect.VisibleFields(tValue.Type())

		for _, f := range fields {
			// check if the gnark tag is set
			tag, ok := f.Tag.Lookup(string(tagKey))
			if ok && tag == string(optOmit) {
				continue // skipping "-"
			}

			// default visibility is Unset
			visibility := compiled.Unset

			// variable name is field name, unless overriden by gnark tag value
			name := f.Name
			var nameTag string

			if ok && tag != "" {
				// gnark tag is set
				var opts tagOptions
				nameTag, opts = parseTag(tag)
				if !isValidTag(nameTag) {
					nameTag = ""
				}
				opts = tagOptions(strings.TrimSpace(string(opts)))
				if opts == "" || opts.contains(string(optSecret)) {
					visibility = compiled.Secret
				} else if opts.contains(string(optPublic)) {
					visibility = compiled.Public
				} else {
					return r, fmt.Errorf("invalid gnark struct tag option on %s. must be \"public\", \"secret\" or \"-\"", getFullName(parentGoName, name, nameTag))
				}
			}

			if ((parentVisibility == compiled.Public) && (visibility == compiled.Secret)) ||
				((parentVisibility == compiled.Secret) && (visibility == compiled.Public)) {
				// TODO @gbotrel maybe we should just force it to take the parent value.
				return r, fmt.Errorf("conflicting visibility. %s (%s) has a parent with different visibility attribute", getFullName(parentGoName, name, nameTag), visibility.String())
			}

			fValue := tValue.FieldByIndex(f.Index)

			if fValue.CanAddr() && fValue.Addr().CanInterface() {
				value := fValue.Addr().Interface()
				var err error
				subFields, err = parse(subFields, value, target, getFullName(parentFullName, name, nameTag), name, nameTag, visibility, handler)
				if err != nil {
					return r, err
				}
			}
		}

		if parentGoName == "" {
			// root
			return subFields, nil
		}
		// we just add it to our current fields
		// if parentVisibility == compiled.Unset {
		// 	parentVisibility = compiled.Secret // default visibility to Secret
		// }
		if len(subFields) == 0 {
			// nothing to add in the schema
			return r, nil
		}
		return append(r, Field{
			Name:       parentGoName,
			NameTag:    parentTagName,
			Type:       Struct,
			SubFields:  subFields,
			Visibility: parentVisibility, // == compiled.Secret,
		}), nil

	}

	if tValue.Kind() == reflect.Slice || tValue.Kind() == reflect.Array {
		if tValue.Len() == 0 {
			if reflect.SliceOf(target) == tValue.Type() {
				fmt.Printf("ignoring uninitizalized slice: %s %s\n", parentGoName, reflect.SliceOf(target).String())
			}
			return r, nil
		}

		// []frontend.Variable
		// [n]frontend.Variable
		// [] / [n] of something else.
		if reflect.SliceOf(target) == tValue.Type() || reflect.ArrayOf(tValue.Len(), target) == tValue.Type() {
			// if parentVisibility == compiled.Unset {
			// 	parentVisibility = compiled.Secret // default visibility to Secret
			// }

			for j := 0; j < tValue.Len(); j++ {
				val := tValue.Index(j)
				if val.CanAddr() && val.Addr().CanInterface() {
					fqn := getFullName(parentFullName, strconv.Itoa(j), "")
					if _, err := parse(nil, val.Addr().Interface(), target, fqn, fqn, parentTagName, parentVisibility, handler); err != nil {
						return nil, err
					}
				}
			}

			return append(r, Field{
				Name:       parentGoName,
				NameTag:    parentTagName,
				Type:       Array,
				Visibility: parentVisibility,
				ArraySize:  tValue.Len(),
			}), nil
		}

		// we have a slice / array of things that may contain variables
		var subFields []Field
		var err error
		for j := 0; j < tValue.Len(); j++ {
			val := tValue.Index(j)
			if val.CanAddr() && val.Addr().CanInterface() {
				fqn := getFullName(parentFullName, strconv.Itoa(j), "")
				subFields, err = parse(subFields, val.Addr().Interface(), target, fqn, fqn, parentTagName, parentVisibility, handler)
				if err != nil {
					return nil, err
				}
			}
		}
		if len(subFields) == 0 {
			// nothing to add
			return r, nil
		}
		return append(r, Field{
			Name:       parentGoName,
			NameTag:    parentTagName,
			Type:       Array,
			SubFields:  subFields[:1], // TODO @gbotrel we should ensure that elements are not heterogeneous?
			Visibility: parentVisibility,
			ArraySize:  tValue.Len(),
		}), nil

	}

	return r, nil
}

// specify parentName, name and tag
// returns fully qualified name
func getFullName(parentFullName, name, tagName string) string {
	n := name
	if tagName != "" {
		n = tagName
	}
	if parentFullName == "" {
		return n
	}
	return parentFullName + "_" + n
}

// Count returns the the number of target type associated with Secret or Public visibility
// through gnark struct tags
func Count(input interface{}, target reflect.Type) (nbSecret, nbPublic int) {
	collectHandler := func(v compiled.Visibility, name string, _ reflect.Value) error {
		if v == compiled.Secret {
			nbSecret++
		} else if v == compiled.Public {
			nbPublic++
		}
		return nil
	}
	_, _ = parse(nil, input, target, "", "", "", compiled.Unset, collectHandler)
	return
}

// TODO @gbotrel this should probably not be here.
func Copy(from interface{}, fromType reflect.Type, to interface{}, toType reflect.Type) {
	var wValues []interface{}

	var collectHandler LeafHandler = func(v compiled.Visibility, _ string, tInput reflect.Value) error {
		wValues = append(wValues, tInput.Interface())
		return nil
	}
	_, _ = Parse(from, fromType, collectHandler)

	if len(wValues) == 0 {
		return
	}

	i := 0
	var setHandler LeafHandler = func(v compiled.Visibility, _ string, tInput reflect.Value) error {
		tInput.Set(reflect.ValueOf((wValues[i])))
		i++
		return nil
	}
	// this can't error.
	_, _ = Parse(to, toType, setHandler)
}
