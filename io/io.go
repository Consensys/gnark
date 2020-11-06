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

// Package io offers (de)serialization APIs for gnark objects.
//
// Unstable until v1.X.X release cycle
package io

import (
	"encoding/binary"
	"errors"
	"io"
	"os"

	"github.com/consensys/gurvy"
	"github.com/fxamacker/cbor/v2"
)

// WriterRawTo is the interface that wraps the WriteRawTo method.
//
// WriteRawTo writes data to w until there's no more data to write or
// when an error occurs. The return value n is the number of bytes
// written. Any error encountered during the write is also returned.
//
// WriteRawTo may not compress the data (as opposed to WriteTo)
type WriterRawTo interface {
	WriteRawTo(w io.Writer) (n int64, err error)
}

// CurveObject must know which curve they are tied to
type CurveObject interface {
	GetCurveID() gurvy.ID
}

var errInvalidCurve = errors.New("trying to deserialize an object serialized with another curve")

// WriteFile serialize object into file
func WriteFile(path string, from CurveObject) error {
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
func ReadFile(path string, into CurveObject) error {
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
func Write(writer io.Writer, from CurveObject) error {
	encoder := cbor.NewEncoder(writer)

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

// WriteCurveID writes 2 bytes on the writer with specified curveID encoded as BigEndian Uint16
func WriteCurveID(w io.Writer, id gurvy.ID) error {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], uint16(id))

	_, err := w.Write(buf[:])
	return err
}

// ReadCurveID reads the first 2 bytes of the reader return the curveID
// returns gurvy.UNKNOWN and an error if couldn't ready 2 bytes from io.Reader or if Read returned err != EOF
func ReadCurveID(reader io.Reader) (gurvy.ID, error) {
	var buf [2]byte

	n, err := reader.Read(buf[:])
	if n != 2 {
		return gurvy.UNKNOWN, errors.New("couldn't read 2 bytes and decode curveID")
	}
	if err != nil && err != io.EOF {
		return gurvy.UNKNOWN, err
	}

	return gurvy.ID(binary.BigEndian.Uint16(buf[:])), nil
}

// Read reads bytes from reader and construct object into
func Read(reader io.Reader, into CurveObject) error {
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
