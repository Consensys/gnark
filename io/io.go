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

// Package io offers (de)serialization APIs for gnark objects
// consider it unstable until v1.X.X release cycle
package io

import (
	"errors"
	"io"
	"os"

	"github.com/consensys/gurvy"
	"github.com/fxamacker/cbor"
)

// CurveSpecific objects must know which curve they are tied to
type CurveSpecific interface {
	GetCurveID() gurvy.ID
}

var errInvalidCurve = errors.New("trying to deserialize an object serialized with another curve")

// WriteFile serialize object into file
func WriteFile(path string, from CurveSpecific) error {
	// create file
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return Write(f, from)
}

// ReadFile read and deserialize input into object
// provided interface must be a pointer
func ReadFile(path string, into CurveSpecific) error {
	// open file
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return Read(f, into)
}

// Write object from into provided writer
// encodes the curveID in the first bytes
func Write(writer io.Writer, from CurveSpecific) error {
	encoder := cbor.NewEncoder(writer, cbor.CanonicalEncOptions())

	// encode the curve type in the first bytes
	if err := encoder.Encode(from.GetCurveID()); err != nil {
		return err
	}

	// encode our object
	if err := encoder.Encode(from); err != nil {
		return err
	}

	return nil
}

// PeekCurveID reads the first bytes of the file and tries to decode and return the curveID
func PeekCurveID(file string) (gurvy.ID, error) {
	// open file
	reader, err := os.Open(file)
	if err != nil {
		return gurvy.UNKNOWN, err
	}
	defer reader.Close()

	// gzip reader
	decoder := cbor.NewDecoder(reader)

	// decode the curve ID
	var curveID gurvy.ID
	if err = decoder.Decode(&curveID); err != nil {
		return gurvy.UNKNOWN, err
	}
	return curveID, nil
}

// Read reads bytes from reader and construct object into
func Read(reader io.Reader, into CurveSpecific) error {
	decoder := cbor.NewDecoder(reader)

	// decode the curve type, and ensure it matches
	var curveID gurvy.ID
	if err := decoder.Decode(&curveID); err != nil {
		return err
	}
	if curveID != into.GetCurveID() {
		return errInvalidCurve
	}

	if err := decoder.Decode(into); err != nil {
		return err
	}

	return nil
}
