// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package witness provides serialization helpers to encode a witness into a []byte.
//
// Binary protocol
//
// 	Full witness     ->  [uint32(nbElements) | publicVariables | secretVariables]
// 	Public witness   ->  [uint32(nbElements) | publicVariables ]
//
// where
// 	* `nbElements == len(publicVariables) [+ len(secretVariables)]`.
// 	* each variable (a *field element*) is encoded as a big-endian byte array, where `len(bytes(variable)) == len(bytes(modulus))`
//
// Ordering
//
// First, `publicVariables`, then `secretVariables`. Each subset is ordered from the order of definition in the circuit structure.
// For example, with this circuit on `ecc.BN254`
//
// 	type Circuit struct {
// 	    X frontend.Variable
// 	    Y frontend.Variable `gnark:",public"`
// 	    Z frontend.Variable
// 	}
//
// A valid witness would be:
// 	* `[uint32(3)|bytes(Y)|bytes(X)|bytes(Z)]`
// 	* Hex representation with values `Y = 35`, `X = 3`, `Z = 2`
// 	`00000003000000000000000000000000000000000000000000000000000000000000002300000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000002`
package witness

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend/schema"
)

var (
	ErrInvalidWitness = errors.New("invalid witness")
	errMissingSchema  = errors.New("missing Schema")
	errMissingCurveID = errors.New("missing CurveID")
)

// Witness represents a zkSNARK witness.
//
// A witness can be in 3 states:
// 1. Assignment (ie assigning values to a frontend.Circuit object)
// 2. Witness (this object: an ordered vector of field elements + metadata)
// 3. Serialized (Binary or JSON) using MarshalBinary or MarshalJSON
type Witness struct {
	Vector  Vector         //  TODO @gbotrel the result is an interface for now may change to generic Witness[fr.Element] in an upcoming PR
	Schema  *schema.Schema // optional, Binary encoding needs no schema
	CurveID ecc.ID         // should be redundant with generic impl
}

func New(curveID ecc.ID, schema *schema.Schema) (*Witness, error) {
	v, err := newVector(curveID)
	if err != nil {
		return nil, err
	}

	return &Witness{
		CurveID: curveID,
		Vector:  v,
		Schema:  schema,
	}, nil
}

// Public extracts the public part of the witness and returns a new witness object
func (w *Witness) Public() (*Witness, error) {
	if w.Vector == nil {
		return nil, fmt.Errorf("%w: empty witness", ErrInvalidWitness)
	}
	if w.Schema == nil {
		return nil, errMissingSchema
	}
	v, err := newFrom(w.Vector, w.Schema.NbPublic)
	if err != nil {
		return nil, err
	}
	return &Witness{
		CurveID: w.CurveID,
		Vector:  v,
		Schema:  w.Schema,
	}, nil
}

// MarshalBinary implements encoding.BinaryMarshaler
// Only the vector of field elements is marshalled: the curveID and the Schema are omitted.
func (w *Witness) MarshalBinary() (data []byte, err error) {
	var buf bytes.Buffer

	if w.Vector == nil {
		return nil, fmt.Errorf("%w: empty witness", ErrInvalidWitness)
	}

	if _, err = w.Vector.WriteTo(&buf); err != nil {
		return
	}
	return buf.Bytes(), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler
func (w *Witness) UnmarshalBinary(data []byte) error {

	var r io.Reader
	r = bytes.NewReader(data)
	if w.Schema != nil {
		// if schema is set we can do a limit reader
		maxSize := 4 + (w.Schema.NbPublic+w.Schema.NbSecret)*w.CurveID.Info().Fr.Bytes
		r = io.LimitReader(r, int64(maxSize))
	}

	v, err := newVector(w.CurveID)
	if err != nil {
		return err
	}
	_, err = v.ReadFrom(r)
	if err != nil {
		return err
	}
	w.Vector = v

	return nil
}

// MarshalJSON implements json.Marshaler
//
// Only the vector of field elements is marshalled: the curveID and the Schema are omitted.
func (w *Witness) MarshalJSON() (r []byte, err error) {
	if w.Schema == nil {
		return nil, errMissingSchema
	}
	if w.Vector == nil {
		return nil, fmt.Errorf("%w: empty witness", ErrInvalidWitness)
	}

	typ := w.Vector.Type()

	instance := w.Schema.Instantiate(reflect.PtrTo(typ))
	if err := w.toAssignment(instance, reflect.PtrTo(typ)); err != nil {
		return nil, err
	}

	if debug.Debug {
		return json.MarshalIndent(instance, "  ", "    ")
	} else {
		return json.Marshal(instance)
	}
}

// UnmarshalJSON implements json.Unmarshaler
func (w *Witness) UnmarshalJSON(data []byte) error {
	if w.Schema == nil {
		return errMissingSchema
	}
	v, err := newVector(w.CurveID)
	if err != nil {
		return err
	}

	typ := v.Type()

	// we instantiate an object matching the schema, with leaf type == field element
	// note that we pass a pointer here to have nil for zero values
	instance := w.Schema.Instantiate(reflect.PtrTo(typ))

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	// field.Element (gnark-crypto) implements json.Unmarshaler
	if err := dec.Decode(instance); err != nil {
		return err
	}

	// optimistic approach: first try to unmarshall everything. then only the public part if it fails
	// note that our instance has leaf type == *fr.Element, so the zero value is nil
	// and is going to make the newWitness method error since it doesn't accept missing assignments
	_, err = v.FromAssignment(instance, reflect.PtrTo(typ), false)
	if err != nil {
		// try with public only
		_, err := v.FromAssignment(instance, reflect.PtrTo(typ), true)
		if err != nil {
			return err
		}
		w.Vector = v
		return nil
	}
	w.Vector = v
	return nil
}

func (w *Witness) toAssignment(to interface{}, toLeafType reflect.Type) error {
	if w.Schema == nil {
		return errMissingSchema
	}
	if w.Vector == nil {
		return fmt.Errorf("%w: empty witness", ErrInvalidWitness)
	}

	// we check the size of the underlying vector to determine if we have the full witness
	// or only the public part
	n := w.Vector.Len()

	nbSecret, nbPublic := w.Schema.NbSecret, w.Schema.NbPublic

	var publicOnly bool
	if n == nbPublic {
		// public witness only
		publicOnly = true
	} else if n == (nbPublic + nbSecret) {
		// full witness
		publicOnly = false
	} else {
		// invalid witness size
		return fmt.Errorf("%w: got %d elements, expected either %d (public) or %d (full)", ErrInvalidWitness, n, nbPublic, nbPublic+nbSecret)
	}
	w.Vector.ToAssignment(to, toLeafType, publicOnly)

	return nil
}
