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

package gob

import (
	"compress/gzip"
	"encoding/gob"
	"errors"
	"io"
	"os"

	"github.com/consensys/gnark/cs/internal/curve"
	"github.com/consensys/gnark/ecc"
)

var (
	ErrInvalidCurve = errors.New("trying to deserialize an object serialized with another curve")
)

// Write serialize object into file
// uses gob + gzip
func Write(path string, from interface{}) error {
	// create file
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return Serialize(f, from)
}

// Read read and deserialize input into object
// provided interface must be a pointer
// uses gob + gzip
func Read(path string, into interface{}) error {
	// open file
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return Deserialize(f, into)
}

// Serialize object from into f
// uses gob + gzip
func Serialize(f io.Writer, from interface{}) error {
	// create a gzip writer
	writer := gzip.NewWriter(f)
	defer writer.Close()

	// gzip writer
	encoder := gob.NewEncoder(writer)

	// encode the curve type in the first bytes
	if err := encoder.Encode(curve.CurveID); err != nil {
		return err
	}

	// encode our object
	if err := encoder.Encode(from); err != nil {
		return err
	}

	return nil
}

// PeekCurveID reads the first bytes of the file and tries to decode and return the curveID
func PeekCurveID(file string) (ecc.ID, error) {
	// open file
	f, err := os.Open(file)
	if err != nil {
		return ecc.UNKNOWN, err
	}
	defer f.Close()

	// create a gzip reader from the opened file
	reader, err := gzip.NewReader(f)
	if err != nil {
		return ecc.UNKNOWN, err
	}
	defer reader.Close()

	// gzip reader
	decoder := gob.NewDecoder(reader)

	// decode the curve ID
	var curveID ecc.ID
	if err = decoder.Decode(&curveID); err != nil {
		return ecc.UNKNOWN, err
	}
	return curveID, nil
}

// Deserialize f into object into
// uses gob + gzip
func Deserialize(f io.Reader, into interface{}) error {
	// create a gzip reader from the opened file
	reader, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer reader.Close()

	// gzip reader
	decoder := gob.NewDecoder(reader)

	// decode the curve type, and ensure it matches
	var curveID ecc.ID
	if err = decoder.Decode(&curveID); err != nil {
		return err
	}
	if curveID != curve.CurveID {
		return ErrInvalidCurve
	}

	if err = decoder.Decode(into); err != nil {
		return err
	}

	return nil
}
