package frontend

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unicode"
)

// TODO make a clearer spec on that
const (
	tagKey    = "gnark"
	optPublic = "public"
	optSecret = "secret"
	optEmbed  = "embed"
	optOmit   = "-"
)

type attrVisibility uint8

const (
	unset attrVisibility = iota
	secret
	public
)

type leafHandler func(visibility attrVisibility, name string, tInput reflect.Value) error

func parseType(input interface{}, baseName string, parentVisibility attrVisibility, handler leafHandler) error {
	// types we are looking for
	tCircuitVariable := reflect.TypeOf(Variable{})
	tConstraintSytem := reflect.TypeOf(CS{})

	tValue := reflect.ValueOf(input)
	// TODO if it's not a PTR, return an error
	tInput := tValue.Elem()

	// we either have a pointer, a struct, or a slice / array
	// and recursively parse members / elements until we find a constraint to allocate in the circuit.
	switch tInput.Kind() {
	case reflect.Struct:
		switch tInput.Type() {
		case tCircuitVariable:
			return handler(parentVisibility, baseName, tInput)
		case tConstraintSytem:
			return nil
		default:
			for i := 0; i < tInput.NumField(); i++ {
				field := tInput.Type().Field((i))

				// get gnark tag
				tag := field.Tag.Get(tagKey)
				if tag == optOmit {
					continue // skipping "-"
				}

				visibility := secret
				name := field.Name
				if tag != "" {
					// gnark tag is set
					var opts tagOptions
					name, opts = parseTag(tag)
					if !isValidTag(name) {
						name = field.Name
					}

					if opts.Contains(optSecret) {
						visibility = secret
					} else if opts.Contains(optPublic) {
						visibility = public
					} else if opts.Contains(optEmbed) {
						name = ""
						visibility = unset
					}
				}
				if parentVisibility != unset {
					visibility = parentVisibility // parent visibility overhides
				}

				fullName := appendName(baseName, name)

				f := tInput.FieldByName(field.Name)
				if f.CanAddr() && f.Addr().CanInterface() {
					value := f.Addr().Interface()
					if err := parseType(value, fullName, visibility, handler); err != nil {
						return err
					}
				}
			}
		}

	// case reflect.Interface:
	// 	switch tInput.Type() {
	// 	case tCircuitVariable:
	// 		return handler(parentVisibility, baseName, tInput)
	// 	default:
	// 		return nil
	// 	}
	case reflect.Slice, reflect.Array:
		if tInput.Len() == 0 {
			fmt.Println("warning, got unitizalized slice (or empty array). Ignoring;")
			return nil
		}
		for j := 0; j < tInput.Len(); j++ {

			val := tInput.Index(j)
			if val.CanAddr() && val.Addr().CanInterface() {
				if err := parseType(val.Addr().Interface(), appendName(baseName, strconv.Itoa(j)), parentVisibility, handler); err != nil {
					return err
				}
			}

		}
	case reflect.Map:
		// TODO untested
		if tInput.Len() == 0 {
			fmt.Println("warning, got unitizalized map. Ignoring;")
			return nil
		}
		iter := tInput.MapRange()

		for iter.Next() {
			val := iter.Value()
			if val.CanAddr() && val.Addr().CanInterface() {
				if err := parseType(val.Addr().Interface(), appendName(baseName, iter.Key().String()), parentVisibility, handler); err != nil {
					return err
				}
			}
		}

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

// tagOptions is the string following a comma in a struct field's "json"
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
			// otherwise any punctuation chars are allowed
			// in a tag name.
		case !unicode.IsLetter(c) && !unicode.IsDigit(c):
			return false
		}
	}
	return true
}
