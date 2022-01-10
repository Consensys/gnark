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
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
	witness_bls12377 "github.com/consensys/gnark/internal/backend/bls12-377/witness"
	witness_bls12381 "github.com/consensys/gnark/internal/backend/bls12-381/witness"
	witness_bls24315 "github.com/consensys/gnark/internal/backend/bls24-315/witness"
	witness_bn254 "github.com/consensys/gnark/internal/backend/bn254/witness"
	witness_bw6633 "github.com/consensys/gnark/internal/backend/bw6-633/witness"
	witness_bw6761 "github.com/consensys/gnark/internal/backend/bw6-761/witness"
	"github.com/consensys/gnark/internal/backend/compiled"
)

// Witness ...
type Witness struct {
	Vector  interface{}   //  TODO @gbotrel the result is an interface for now may change to generic Witness[fr.Element] in an upcoming PR
	Schema  schema.Schema // optional, Binary encoding needs no schema
	CurveID ecc.ID        // should be redundant with generic impl
}

var (
	errMissingSchema  = errors.New("missing Schema")
	errEmptyWitness   = errors.New("empty witness")
	errInvalidWitness = errors.New("invalid witness")
	errMissingCurveID = errors.New("missing CurveID")
)

// New build an orderded vector of field elements from the given assignment (frontend.Circuit)
// if PublicOnly is specified, returns the public part of the witness only
// else returns [public | secret]. The result can then be serialized to / from json & binary
//
// Returns an error if the assignment has missing entries
func New(assignment frontend.Circuit, curveID ecc.ID, opts ...func(opt *WitnessOption) error) (*Witness, error) {
	opt, err := options(opts...)
	if err != nil {
		return nil, err
	}

	return newWitness(assignment, curveID, opt.publicOnly)
}

func newWitness(assignment interface{}, curveID ecc.ID, publicOnly bool) (*Witness, error) {
	var err error
	var vector interface{}
	var schema schema.Schema

	switch curveID {
	case ecc.BN254:
		_witness := &witness_bn254.Witness{}
		schema, err = _witness.FromAssignment(assignment, publicOnly)
		vector = _witness
	case ecc.BLS12_377:
		_witness := &witness_bls12377.Witness{}
		schema, err = _witness.FromAssignment(assignment, publicOnly)
		vector = _witness
	case ecc.BLS12_381:
		_witness := &witness_bls12381.Witness{}
		schema, err = _witness.FromAssignment(assignment, publicOnly)
		vector = _witness
	case ecc.BW6_761:
		_witness := &witness_bw6761.Witness{}
		schema, err = _witness.FromAssignment(assignment, publicOnly)
		vector = _witness
	case ecc.BLS24_315:
		_witness := &witness_bls24315.Witness{}
		schema, err = _witness.FromAssignment(assignment, publicOnly)
		vector = _witness
	case ecc.BW6_633:
		_witness := &witness_bw6633.Witness{}
		schema, err = _witness.FromAssignment(assignment, publicOnly)
		vector = _witness
	default:
		panic("not implemented")
	}

	if err != nil {
		return nil, err
	}
	return &Witness{
		CurveID: curveID,
		Vector:  vector,
		Schema:  schema,
	}, nil
}

// MarshalBinary implements encoding.BinaryMarshaler
func (w *Witness) MarshalBinary() (data []byte, err error) {
	var buf bytes.Buffer
	switch wt := w.Vector.(type) {
	case *witness_bls12377.Witness:
		_, err = wt.WriteTo(&buf)
	case *witness_bls12381.Witness:
		_, err = wt.WriteTo(&buf)
	case *witness_bls24315.Witness:
		_, err = wt.WriteTo(&buf)
	case *witness_bn254.Witness:
		_, err = wt.WriteTo(&buf)
	case *witness_bw6633.Witness:
		_, err = wt.WriteTo(&buf)
	case *witness_bw6761.Witness:
		_, err = wt.WriteTo(&buf)
	default:
		return nil, fmt.Errorf("%w: type not supported %s", errInvalidWitness, reflect.TypeOf(w.Vector).String())
	}
	if err != nil {
		return
	}
	return buf.Bytes(), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler
func (w *Witness) UnmarshalBinary(data []byte) error {
	var err error
	r := bytes.NewReader(data)

	switch w.CurveID {
	case ecc.BN254:
		_witness := &witness_bn254.Witness{}
		_, err = _witness.ReadFrom(r)
		w.Vector = _witness
	case ecc.BLS12_377:
		_witness := &witness_bls12377.Witness{}
		_, err = _witness.ReadFrom(r)
		w.Vector = _witness
	case ecc.BLS12_381:
		_witness := &witness_bls12381.Witness{}
		_, err = _witness.ReadFrom(r)
		w.Vector = _witness
	case ecc.BW6_761:
		_witness := &witness_bw6761.Witness{}
		_, err = _witness.ReadFrom(r)
		w.Vector = _witness
	case ecc.BLS24_315:
		_witness := &witness_bls24315.Witness{}
		_, err = _witness.ReadFrom(r)
		w.Vector = _witness
	case ecc.BW6_633:
		_witness := &witness_bw6633.Witness{}
		_, err = _witness.ReadFrom(r)
		w.Vector = _witness
	default:
		return errMissingCurveID
	}

	// TODO @gbotrel if we have a schema, we can do some post-unmarshalling validation here

	return err
}

// MarshalJSON implements json.Marshaler
func (w *Witness) MarshalJSON() (r []byte, err error) {
	if len(w.Schema) == 0 {
		return nil, errMissingSchema
	}
	typ, err := w.getType()
	if err != nil {
		return nil, err
	}

	instance := w.Schema.Instantiate(typ)
	if err := w.copyTo(instance, typ); err != nil {
		return nil, err
	}

	return json.Marshal(instance)
}

// UnmarshalJSON implements json.Unmarshaler
func (w *Witness) UnmarshalJSON(data []byte) error {
	if len(w.Schema) == 0 {
		return errMissingSchema
	}

	typ, err := w.getType()
	if err != nil {
		return err
	}

	// we instantiate an object matching the schema, with leaf type == field element
	// note that we pass a pointer here to have nil for zero values
	instance := w.Schema.Instantiate(reflect.PtrTo(typ))

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	// field.Element (gnark-crypto) implements json.Unmarshaler
	if err := dec.Decode(instance); err != nil {
		return err
	}

	// now we re-create an object, this type with leaf type == Variable , to mimic a assignment
	assignment := w.Schema.Instantiate(tVariable)

	// we copy the parsed variable to the circuit
	schema.Copy(instance, reflect.PtrTo(typ), assignment, tVariable)

	// optimistic approach: first try to unmarshall everything. then only the public part if it fails
	// note that our instance has leaf type == *fr.Element, so the zero value is nil
	// and is going to make the newWitness method error since it doesn't accept missing assignments
	toReturn, err := newWitness(assignment, w.CurveID, false)
	if err != nil {
		// try with public only
		toReturn, err := newWitness(assignment, w.CurveID, true)
		if err != nil {
			return err
		}
		toReturn.Schema = w.Schema
		*w = *toReturn
		return nil
	}
	toReturn.Schema = w.Schema
	*w = *toReturn
	return nil
}

func (w *Witness) copyTo(to interface{}, toLeafType reflect.Type) error {
	if w.Vector == nil {
		return errEmptyWitness
	}

	n, err := w.len()
	if err != nil {
		return err
	}

	nbSecret, nbPublic := schema.Count(to, toLeafType)

	var publicOnly bool
	if n == nbPublic {
		// public witness only
		publicOnly = true
	} else if n == (nbPublic + nbSecret) {
		// full witness
		publicOnly = false
	} else {
		// invalid witness size
		return fmt.Errorf("%w: got %d elements, expected either %d (public) or %d (full)", errInvalidWitness, n, nbPublic, nbPublic+nbSecret)
	}

	switch wt := w.Vector.(type) {
	case *witness_bls12377.Witness:
		wt.CopyTo(to, toLeafType, publicOnly)
	case *witness_bls12381.Witness:
		wt.CopyTo(to, toLeafType, publicOnly)
	case *witness_bls24315.Witness:
		wt.CopyTo(to, toLeafType, publicOnly)
	case *witness_bn254.Witness:
		wt.CopyTo(to, toLeafType, publicOnly)
	case *witness_bw6633.Witness:
		wt.CopyTo(to, toLeafType, publicOnly)
	case *witness_bw6761.Witness:
		wt.CopyTo(to, toLeafType, publicOnly)
	default:
		panic("not implemented")
	}

	return nil

	// could check schema if present against to structure.
	// if w.Schema != nil && !reflect.DeepEqual(w.Schema, s) {
	// 	return errors.New("schema are different")
	// }

}

func (w *Witness) len() (int, error) {
	switch wt := w.Vector.(type) {
	case *witness_bls12377.Witness:
		return len(*wt), nil
	case *witness_bls12381.Witness:
		return len(*wt), nil
	case *witness_bls24315.Witness:
		return len(*wt), nil
	case *witness_bn254.Witness:
		return len(*wt), nil
	case *witness_bw6633.Witness:
		return len(*wt), nil
	case *witness_bw6761.Witness:
		return len(*wt), nil
	default:
		return 0, fmt.Errorf("%w: invalid type %s", errInvalidWitness, reflect.TypeOf(wt).String())
	}
}

func (w *Witness) getType() (reflect.Type, error) {
	switch w.Vector.(type) {
	case *witness_bls12377.Witness:
		w.CurveID = ecc.BLS12_377
		return witness_bls12377.T, nil
	case *witness_bls12381.Witness:
		w.CurveID = ecc.BLS12_381
		return witness_bls12381.T, nil
	case *witness_bls24315.Witness:
		w.CurveID = ecc.BLS24_315
		return witness_bls24315.T, nil
	case *witness_bn254.Witness:
		w.CurveID = ecc.BN254
		return witness_bn254.T, nil
	case *witness_bw6633.Witness:
		w.CurveID = ecc.BW6_633
		return witness_bw6633.T, nil
	case *witness_bw6761.Witness:
		w.CurveID = ecc.BW6_761
		return witness_bw6761.T, nil
	default:
		if w.Vector == nil {
			// try with the curveID
			switch w.CurveID {
			case ecc.BLS12_377:
				return witness_bls12377.T, nil
			case ecc.BLS12_381:
				return witness_bls12381.T, nil
			case ecc.BLS24_315:
				return witness_bls24315.T, nil
			case ecc.BN254:
				return witness_bn254.T, nil
			case ecc.BW6_633:
				return witness_bw6633.T, nil
			case ecc.BW6_761:
				return witness_bw6761.T, nil
			}
		}
		return nil, errors.New("can't infer witness type from vector or curveID")
	}
}

// WriteSequence writes the expected sequence order of the witness on provided writer
// witness elements are identified by their tag name, or if unset, struct & field name
func WriteSequence(w io.Writer, circuit frontend.Circuit) error {
	var public, secret []string
	collectHandler := func(visibility compiled.Visibility, name string, tInput reflect.Value) error {
		if visibility == compiled.Public {
			public = append(public, name)
		} else if visibility == compiled.Secret {
			secret = append(secret, name)
		}
		return nil
	}
	if _, err := schema.Parse(circuit, tVariable, collectHandler); err != nil {
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

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A frontend.Variable }{}).FieldByName("A").Type()
}

// default options
func options(opts ...func(*WitnessOption) error) (WitnessOption, error) {
	// apply options
	opt := WitnessOption{
		publicOnly: false,
	}
	for _, option := range opts {
		if err := option(&opt); err != nil {
			return opt, err
		}
	}

	return opt, nil
}

type WitnessOption struct {
	publicOnly bool
}

func PublicOnly() func(opt *WitnessOption) error {
	return func(opt *WitnessOption) error {
		opt.publicOnly = true
		return nil
	}
}
