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

// Package encoding offers (de)serialization APIs for gnark objects
// it uses CBOR, is schema-less and that may change until v1.X.X release cycle
package encoding

import (
	"errors"
	"io"
	"os"

	"github.com/consensys/gurvy"
	"github.com/fxamacker/cbor"
)

var errInvalidCurve = errors.New("trying to deserialize an object serialized with another curve")

// Write serialize object into file
func Write(path string, from interface{}, curveID gurvy.ID) error {
	// create file
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return Serialize(f, from, curveID)
}

// Read read and deserialize input into object
// provided interface must be a pointer
func Read(path string, into interface{}, expectedCurveID gurvy.ID) error {
	// open file
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return Deserialize(f, into, expectedCurveID)
}

// Serialize object from into provided writer
// encodes the curveID in the first bytes
func Serialize(writer io.Writer, from interface{}, curveID gurvy.ID) error {
	encoder := cbor.NewEncoder(writer, cbor.CanonicalEncOptions())

	// encode the curve type in the first bytes
	if err := encoder.Encode(curveID); err != nil {
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

// Deserialize reads bytes from reader and construct object into
func Deserialize(reader io.Reader, into interface{}, expectedCurveID gurvy.ID) error {
	decoder := cbor.NewDecoder(reader)

	// decode the curve type, and ensure it matches
	var curveID gurvy.ID
	if err := decoder.Decode(&curveID); err != nil {
		return err
	}
	if curveID != expectedCurveID {
		return errInvalidCurve
	}

	if err := decoder.Decode(into); err != nil {
		return err
	}

	return nil
}
