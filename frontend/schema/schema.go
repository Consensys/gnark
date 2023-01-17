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
	"io"
	"reflect"
	"strconv"
	"strings"
)

// Schema represents the structure of a gnark circuit (/ witness)
type Schema struct {
	Fields   []Field
	NbPublic int
	NbSecret int
}

// LeafHandler is the handler function that will be called when Visit reaches leafs of the struct
type LeafHandler func(field *Field, tValue reflect.Value) error

// An object implementing an init hook knows how to "init" itself
// when parsed at compile time
type InitHook interface {
	GnarkInitHook() // TODO @gbotrel find a better home for this
}

// Parse filters recursively input data struct and keeps only the fields containing slices, arrays of elements of
// type frontend.Variable and return the corresponding  Slices are converted to arrays.
//
// If handler is specified, handler will be called on each encountered leaf (of type tLeaf)
func Parse(circuit interface{}, tLeaf reflect.Type, handler LeafHandler) (*Schema, error) {
	// note circuit is of type interface{} instead of frontend.Circuit to avoid import cycle
	// same for tLeaf it is in practice always frontend.Variable

	var nbPublic, nbSecret int
	fields, err := parse(nil, circuit, tLeaf, "", "", "", Unset, handler, &nbPublic, &nbSecret)
	if err != nil {
		return nil, err
	}

	return &Schema{Fields: fields, NbPublic: nbPublic, NbSecret: nbSecret}, nil
}

// Instantiate builds a concrete type using reflect matching the provided schema
//
// It replaces leafs by provided type, such that one can do:
//
//	struct { A []frontend.Variable} -> Schema -> struct {A [12]fr.Element}
//
// Default behavior is to add "json:,omitempty" to the generated struct
func (s *Schema) Instantiate(leafType reflect.Type, omitEmptyTag ...bool) interface{} {
	omitEmpty := true
	if len(omitEmptyTag) == 1 {
		omitEmpty = omitEmptyTag[0]
	}

	// first, let's replace the Field by reflect.StructField
	// we also collect in bfs order the slice capacity to allocate
	structFields := makeStruct(s.Fields, leafType, omitEmpty)

	// now create the corresponding type
	concreteType := reflect.StructOf(structFields)

	// instantiate the type
	instance := reflect.New(concreteType).Elem()

	// allocate the slices;
	chCapacity := make(chan int, 1)

	// this go routine is going to do a DFS on the schema and return the expected size length
	go iterateOnSliceLen(&Field{SubFields: s.Fields}, chCapacity)

	// this function is going to do a DFS on the concrete instance and allocated the slices
	allocateSlices(instance.Addr().Interface(), chCapacity, leafType)
	close(chCapacity)

	// return interface
	return instance.Addr().Interface()
}

func iterateOnSliceLen(f *Field, chCapacity chan int) {
	if f.Type == Slice {
		chCapacity <- f.NbElements
	}
	if (f.Type == Slice || f.Type == Array) && len(f.SubFields) == 1 {
		// special case where we just stored the first element and have to repeat.
		for i := 0; i < f.NbElements; i++ {
			iterateOnSliceLen(&f.SubFields[0], chCapacity)
		}
	} else {
		for _, subField := range f.SubFields {
			iterateOnSliceLen(&subField, chCapacity)
		}
	}

}

// func bfs(is []reflect.StructField) []int {

// }

// WriteSequence writes the expected sequence order of the witness on provided writer
// witness elements are identified by their tag name, or if unset, struct & field name
//
// The expected sequence matches the binary encoding protocol [public | secret]
func (s *Schema) WriteSequence(w io.Writer) error {
	var public, secret []string

	var a int
	instance := s.Instantiate(reflect.TypeOf(a), false)

	collectHandler := func(f *Field, _ reflect.Value) error {
		if f.Visibility == Public {
			public = append(public, f.FullName)
		} else if f.Visibility == Secret {
			secret = append(secret, f.FullName)
		}
		return nil
	}
	if _, err := Parse(instance, reflect.TypeOf(a), collectHandler); err != nil {
		return err
	}

	if _, err := io.WriteString(w, "public:\n"); err != nil {
		return err
	}
	for _, p := range public {
		if _, err := io.WriteString(w, p); err != nil {
			return err
		}
		if _, err := w.Write([]byte{'\n'}); err != nil {
			return err
		}
	}

	if _, err := io.WriteString(w, "secret:\n"); err != nil {
		return err
	}
	for _, s := range secret {
		if _, err := io.WriteString(w, s); err != nil {
			return err
		}
		if _, err := w.Write([]byte{'\n'}); err != nil {
			return err
		}
	}

	return nil
}

// makeStruct recurse through Field and builds corresponding reflect.StructField
func makeStruct(fields []Field, leafType reflect.Type, omitEmpty bool) []reflect.StructField {
	r := make([]reflect.StructField, len(fields))

	for i, f := range fields {
		r[i] = reflect.StructField{
			Name: f.Name,
			Tag:  structTag(f.Tag, f.Visibility, omitEmpty),
		}
		switch f.Type {
		case Leaf:
			r[i].Type = leafType
		case Array:
			r[i].Type = makeArray(&f, leafType, omitEmpty)
		case Slice:
			r[i].Type = makeSlice(&f, leafType, omitEmpty)
		case Struct:
			r[i].Type = reflect.StructOf(makeStruct(f.SubFields, leafType, omitEmpty))
		}
	}

	return r
}

func makeArray(f *Field, leafType reflect.Type, omitEmpty bool) reflect.Type {
	n := f.NbElements

	// we ignore other subfields; they will be useful when instiating the concrete type
	// and looking for slice capacities.
	switch f.SubFields[0].Type {
	case Leaf:
		return reflect.ArrayOf(n, leafType)
	case Struct:
		return reflect.ArrayOf(n, reflect.StructOf(makeStruct(f.SubFields[0].SubFields, leafType, omitEmpty)))
	case Array:
		return reflect.ArrayOf(n, makeArray(&f.SubFields[0], leafType, omitEmpty))
	case Slice:
		return reflect.ArrayOf(n, makeSlice(&f.SubFields[0], leafType, omitEmpty))
	}
	panic("invalid array type")
}

func makeSlice(f *Field, leafType reflect.Type, omitEmpty bool) reflect.Type {
	// we ignore other subfields; they will be useful when instiating the concrete type
	// and looking for slice capacities.
	switch f.SubFields[0].Type {
	case Leaf:
		return reflect.SliceOf(leafType)
	case Struct:
		return reflect.SliceOf(reflect.StructOf(makeStruct(f.SubFields[0].SubFields, leafType, omitEmpty)))
	case Array:
		return reflect.SliceOf(makeArray(&f.SubFields[0], leafType, omitEmpty))
	case Slice:
		return reflect.SliceOf(makeSlice(&f.SubFields[0], leafType, omitEmpty))
	}
	panic("invalid slice type")
}

func structTag(baseNameTag string, visibility Visibility, omitEmpty bool) reflect.StructTag {
	sOmitEmpty := ""
	if omitEmpty {
		sOmitEmpty = ",omitempty"
	}
	if visibility == Unset {
		if baseNameTag != "" {
			return reflect.StructTag(fmt.Sprintf("gnark:\"%s\" json:\"%s%s\"", baseNameTag, baseNameTag, sOmitEmpty))
		}
		return ""
	}
	if baseNameTag == "" {
		if !omitEmpty {
			return reflect.StructTag(fmt.Sprintf("gnark:\",%s\"", visibility.String()))
		}
		return reflect.StructTag(fmt.Sprintf("gnark:\",%s\" json:\",omitempty\"", visibility.String()))
	}
	return reflect.StructTag(fmt.Sprintf("gnark:\"%s,%s\" json:\"%s%s\"", baseNameTag, visibility.String(), baseNameTag, sOmitEmpty))
}

// parentFullName: the name of parent with its ancestors separated by "_"
// parentGoName: the name of parent (Go struct definition)
// parentTagName: may be empty, set if a struct tag with name is set
func parse(r []Field, input interface{}, target reflect.Type, parentFullName, parentGoName, parentTagName string, parentVisibility Visibility, handler LeafHandler, nbPublic, nbSecret *int) ([]Field, error) {
	tValue := reflect.ValueOf(input)

	// get pointed value if needed
	if tValue.Kind() == reflect.Ptr {
		tValue = tValue.Elem()
	}

	// stop condition
	if tValue.Type() == target {
		f := Field{
			Name:       parentGoName,
			Tag:        parentTagName,
			FullName:   parentFullName,
			Visibility: parentVisibility,
			Type:       Leaf,
			SubFields:  nil,
			NbElements: 1,
		}
		if f.Visibility == Unset {
			f.Visibility = Secret
		}
		if handler != nil {
			if err := handler(&f, tValue); err != nil {
				return nil, fmt.Errorf("leaf handler: %w", err)
			}
		}
		if f.Visibility == Secret {
			(*nbSecret) += f.NbElements
		} else if f.Visibility == Public {
			(*nbPublic) += f.NbElements
		}
		return append(r, f), nil
	}

	// struct
	if tValue.Kind() == reflect.Struct {
		var subFields []Field

		// get visible fields
		fields := reflect.VisibleFields(tValue.Type())

		for _, f := range fields {
			// check if the gnark tag is set
			tag, ok := f.Tag.Lookup(string(tagKey))
			if ok && tag == string(TagOptOmit) {
				continue // skipping "-"
			}

			// default visibility is Unset
			visibility := Unset

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
				switch {
				case opts.contains(TagOptSecret):
					visibility = Secret
				case opts.contains(TagOptPublic):
					visibility = Public
				case opts == "" && parentFullName == "":
					// our promise is to set visibility to secret for empty-tagged elements.
					visibility = Secret
				case opts == "":
					// even though we have the promise, then in tests we have
					// assumed that sub-elements without any tags assume parents
					// visibility (see below). For compatibility, make the same
					// assumption.
					visibility = parentVisibility
				case opts.contains(TagOptInherit) && parentFullName != "":
					// we have been asked explicitly to inherit the visibility
					visibility = parentVisibility
				case opts.contains(TagOptInherit):
					// but we can not inherit the visibility for top-level
					// elements. Return an error.
					return r, fmt.Errorf("can not inherit visibility for top-level element %s", getFullName(parentGoName, name, nameTag))
				default:
					return r, fmt.Errorf("invalid gnark struct tag option on %s. must be \"public\", \"secret\" or \"-\"", getFullName(parentGoName, name, nameTag))
				}
			}

			if ((parentVisibility == Public) && (visibility == Secret)) ||
				((parentVisibility == Secret) && (visibility == Public)) {
				return r, fmt.Errorf("conflicting visibility. %s (%s) has a parent with different visibility attribute", getFullName(parentGoName, name, nameTag), visibility.String())
			}

			// inherit parent visibility
			if visibility == Unset {
				visibility = parentVisibility
			}

			fValue := tValue.FieldByIndex(f.Index)

			if fValue.CanAddr() && fValue.Addr().CanInterface() {
				value := fValue.Addr().Interface()
				if ih, hasInitHook := value.(InitHook); hasInitHook {
					ih.GnarkInitHook()
				}
				var err error
				subFields, err = parse(subFields, value, target, getFullName(parentFullName, name, nameTag), name, nameTag, visibility, handler, nbPublic, nbSecret)
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
		// if parentVisibility == Unset {
		// 	parentVisibility = Secret // default visibility to Secret
		// }
		if len(subFields) == 0 {
			// nothing to add in the schema
			return r, nil
		}
		return append(r, Field{
			Name:       parentGoName,
			Tag:        parentTagName,
			Type:       Struct,
			SubFields:  subFields,
			Visibility: parentVisibility, // == Secret,
		}), nil

	}

	isSlice := tValue.Kind() == reflect.Slice
	isArray := tValue.Kind() == reflect.Array
	if isSlice || isArray {
		if tValue.Len() == 0 {
			if reflect.SliceOf(target) == tValue.Type() {
				fmt.Printf("ignoring uninitizalized slice: %s %s\n", parentGoName, reflect.SliceOf(target).String())
			}
			return r, nil
		}

		// []frontend.Variable
		// [n]frontend.Variable
		// [] / [n] of something else.
		isSliceOfLeaf := reflect.SliceOf(target) == tValue.Type()
		isArrayOfLeaf := reflect.ArrayOf(tValue.Len(), target) == tValue.Type()
		if isSliceOfLeaf || isArrayOfLeaf {
			// if parentVisibility == Unset {
			// 	parentVisibility = Secret // default visibility to Secret
			// }

			for j := 0; j < tValue.Len(); j++ {
				val := tValue.Index(j)
				if val.CanAddr() && val.Addr().CanInterface() {
					fqn := getFullName(parentFullName, strconv.Itoa(j), "")
					if _, err := parse(nil, val.Addr().Interface(), target, fqn, fqn, parentTagName, parentVisibility, handler, nbPublic, nbSecret); err != nil {
						return nil, err
					}
				}
			}

			newField := Field{
				Name:       parentGoName,
				Tag:        parentTagName,
				Visibility: parentVisibility,
				SubFields:  []Field{{Type: Leaf}},
				NbElements: tValue.Len(),
			}
			if isSliceOfLeaf {
				newField.Type = Slice
			} else {
				newField.Type = Array
			}
			return append(r, newField), nil
		}

		// we have a slice / array of things that may contain variables
		var subFields []Field
		var err error
		for j := 0; j < tValue.Len(); j++ {
			val := tValue.Index(j)
			if val.CanAddr() && val.Addr().CanInterface() {
				fqn := getFullName(parentFullName, strconv.Itoa(j), "")
				subFields, err = parse(subFields, val.Addr().Interface(), target, fqn, fqn, parentTagName, parentVisibility, handler, nbPublic, nbSecret)
				if err != nil {
					return nil, err
				}
			}
		}
		if len(subFields) == 0 {
			// nothing to add
			return r, nil
		}

		consistentChild := true
		for i := 1; i < len(subFields); i++ {
			if !consistentField(subFields[0], subFields[i]) {
				consistentChild = false
				break
			}
		}
		newField := Field{
			Name:       parentGoName,
			Tag:        parentTagName,
			SubFields:  subFields,
			Visibility: parentVisibility,
			NbElements: len(subFields), // note that here we don't use tValue.Len() in case we had some empty slices
		}
		if isSlice {
			newField.Type = Slice
		} else {
			newField.Type = Array
		}
		if consistentChild {
			// since all the childs represent same objects with same sizes, we don't need to store
			// duplicate entries here.
			newField.SubFields = newField.SubFields[:1]
		}
		return append(r, newField), nil
	}

	return r, nil
}

// allocateSlices recurse through the structure of the input to allocate slices
func allocateSlices(input interface{}, chCapacity <-chan int, target reflect.Type) {
	tValue := reflect.ValueOf(input)

	// get pointed value if needed
	if tValue.Kind() == reflect.Ptr {
		tValue = tValue.Elem()
	}

	if tValue.Type() == target {
		return
	}

	if tValue.Kind() == reflect.Slice {
		// do slice allocation
		n := <-chCapacity
		tValue.Set(reflect.MakeSlice(tValue.Type(), n, n))

		for j := 0; j < tValue.Len(); j++ {
			val := tValue.Index(j)
			if val.CanAddr() && val.Addr().CanInterface() {
				allocateSlices(val.Addr().Interface(), chCapacity, target)
			}
		}
		return
	}

	// struct
	if tValue.Kind() == reflect.Struct {

		// get visible fields
		fields := reflect.VisibleFields(tValue.Type())

		for _, f := range fields {
			tag, ok := f.Tag.Lookup(string(tagKey))
			if ok && tag == string(TagOptOmit) {
				continue // skipping "-"
			}

			fValue := tValue.FieldByIndex(f.Index)

			if fValue.CanAddr() && fValue.Addr().CanInterface() {
				value := fValue.Addr().Interface()
				allocateSlices(value, chCapacity, target)
			}
		}

		return
	}

	if tValue.Kind() == reflect.Array {
		// we have a slice / array of things that may contain variables
		for j := 0; j < tValue.Len(); j++ {
			val := tValue.Index(j)
			if val.CanAddr() && val.Addr().CanInterface() {
				allocateSlices(val.Addr().Interface(), chCapacity, target)
			}
		}

		return
	}
}

// fields are consistent if they are of the same type (struct or array/slice or leaf)
// if they are of type struct, they must have the same type of subfields
// if they are of type array/slice, their lenght can differ, but the underlying subfield
// graph must be the same.
func consistentField(f1, f2 Field) bool {
	if f1.Type != f2.Type {
		return false
	}
	switch f1.Type {
	case Struct, Array, Slice:
		if len(f1.SubFields) != len(f2.SubFields) || f1.NbElements != f2.NbElements {
			return false
		}
		for i, s := range f1.SubFields {
			if !consistentField(s, f2.SubFields[i]) {
				return false
			}
		}
		return true
	case Leaf:
		return true
	default:
		panic("not implemented")
	}
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

// TODO @gbotrel this should probably not be here.
func Copy(from interface{}, fromType reflect.Type, to interface{}, toType reflect.Type) {
	var wValues []interface{}

	collectHandler := func(f *Field, tInput reflect.Value) error {
		wValues = append(wValues, tInput.Interface())
		return nil
	}
	_, _ = Parse(from, fromType, collectHandler)

	if len(wValues) == 0 {
		return
	}

	i := 0
	setHandler := func(f *Field, tInput reflect.Value) error {
		tInput.Set(reflect.ValueOf((wValues[i])))
		i++
		return nil
	}
	// this can't error.
	_, _ = Parse(to, toType, setHandler)
}
