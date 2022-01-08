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
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
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

// New build an orderded vector of field elements from the given witness (frontend.Circuit)
// if PublicOnly is specified, returns the public part of the witness only
// else returns [public | secret]. The result can then be serialized to / from json & binary
//
// Returns an error if the witness has missing assignments
func New(witness frontend.Circuit, curveID ecc.ID, opts ...func(opt *WitnessOption) error) (*Witness, error) {
	opt, err := options(opts...)
	if err != nil {
		return nil, err
	}

	return newWitness(witness, curveID, opt.publicOnly)
}

func newWitness(witness interface{}, curveID ecc.ID, publicOnly bool) (*Witness, error) {
	var err error
	var vector interface{}
	var schema schema.Schema

	switch curveID {
	case ecc.BN254:
		_witness := &witness_bn254.Witness{}
		schema, err = _witness.FromAssignment(witness, publicOnly)
		vector = _witness
	case ecc.BLS12_377:
		_witness := &witness_bls12377.Witness{}
		schema, err = _witness.FromAssignment(witness, publicOnly)
		vector = _witness
	case ecc.BLS12_381:
		_witness := &witness_bls12381.Witness{}
		schema, err = _witness.FromAssignment(witness, publicOnly)
		vector = _witness
	case ecc.BW6_761:
		_witness := &witness_bw6761.Witness{}
		schema, err = _witness.FromAssignment(witness, publicOnly)
		vector = _witness
	case ecc.BLS24_315:
		_witness := &witness_bls24315.Witness{}
		schema, err = _witness.FromAssignment(witness, publicOnly)
		vector = _witness
	case ecc.BW6_633:
		_witness := &witness_bw6633.Witness{}
		schema, err = _witness.FromAssignment(witness, publicOnly)
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
		return nil, errors.New("invalid witness type " + reflect.TypeOf(w.Vector).String())
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
		return errors.New("witness.CurveID must be set to call UnmarshalBinary")
	}

	// TODO @gbotrel if we have a schema, we can do some post-unmarshalling validation here

	return err
}

// MarshalJSON implements json.Marshaler
func (w *Witness) MarshalJSON() (r []byte, err error) {
	if len(w.Schema) == 0 {
		return nil, errors.New("witness.Schema must be set to MarshalJSON")
	}
	typ, err := w.getType()
	if err != nil {
		return nil, err
	}

	i := w.Schema.Instantiate(typ)
	if err := w.copyTo(i, typ); err != nil {
		return nil, err
	}

	return json.Marshal(i)
}

// UnmarshalJSON implements json.Unmarshaler
func (w *Witness) UnmarshalJSON(data []byte) error {
	if len(w.Schema) == 0 {
		return errors.New("witness.Schema must be set to UnmarshalJSON")
	}

	typ, err := w.getType()
	if err != nil {
		return err
	}
	i := w.Schema.Instantiate(typ)
	if err := json.Unmarshal(data, i); err != nil {
		return err
	}

	// optimistic approach; try public + secret
	toReturn, err := newWitness(i, w.CurveID, false)
	if err != nil {
		// try public only
		toReturn, err := newWitness(i, w.CurveID, true)
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
		return errors.New("witness is empty")
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
		return fmt.Errorf("invalid witness size. got %d, expected either %d (public) or %d (full)", n, nbPublic, nbPublic+nbSecret)
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
		return 0, errors.New("invalid witness type")
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

// WriteFullTo encodes the witness to a slice of []fr.Element and write the []byte on provided writer
func WriteFullTo(w io.Writer, curveID ecc.ID, witness frontend.Circuit) (int64, error) {
	_w, err := New(witness, curveID)
	if err != nil {
		return 0, err
	}
	data, err := _w.MarshalBinary()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(data)
	return int64(n), err
}

// WritePublicTo encodes the witness to a slice of []fr.Element and write the result on provided writer
func WritePublicTo(w io.Writer, curveID ecc.ID, publicWitness frontend.Circuit) (int64, error) {
	_w, err := New(publicWitness, curveID, PublicOnly())
	if err != nil {
		return 0, err
	}
	ww := &witness_bn254.Witness{}
	ww.FromPublicAssignment(publicWitness)
	data, err := _w.MarshalBinary()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(data)
	return int64(n), err
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

// ReadPublicFrom reads bytes from provided reader and attempts to reconstruct
// a statically typed witness, with big.Int values
// The stream must match the binary protocol to encode witnesses
// This function will read at most the number of expected bytes
// If it can't fully re-construct the witness from the reader, returns an error
// if the provided witness has 0 public Variables this function returns 0, nil
func ReadPublicFrom(r io.Reader, curveID ecc.ID, witness frontend.Circuit) (int64, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return 0, err
	}
	w := Witness{
		CurveID: curveID,
	}
	if err := w.UnmarshalBinary(data); err != nil {
		return 0, err
	}
	err = w.copyTo(witness, tVariable)

	return int64(len(data)), err
}

// ReadFullFrom reads bytes from provided reader and attempts to reconstruct
// a statically typed witness, with big.Int values
// The stream must match the binary protocol to encode witnesses
// This function will read at most the number of expected bytes
// If it can't fully re-construct the witness from the reader, returns an error
// if the provided witness has 0 public Variables and 0 secret Variables this function returns 0, nil
func ReadFullFrom(r io.Reader, curveID ecc.ID, witness frontend.Circuit) (int64, error) {
	nbSecrets, nbPublic := schema.Count(witness, tVariable)

	if nbPublic == 0 && nbSecrets == 0 {
		return 0, nil
	}

	// first 4 bytes have number of bytes
	var buf [4]byte
	if read, err := io.ReadFull(r, buf[:4]); err != nil {
		return int64(read), err
	}
	sliceLen := binary.BigEndian.Uint32(buf[:4])
	if int(sliceLen) != (nbPublic + nbSecrets) {
		return 4, errors.New("invalid witness size")
	}

	elementSize := curveID.Info().Fr.Bytes
	expectedSize := elementSize * (nbPublic + nbSecrets)

	lr := io.LimitReader(r, int64(expectedSize*elementSize))
	read := 4

	bufElement := make([]byte, elementSize)

	reader := func(targetVisibility, visibility compiled.Visibility, name string, tInput reflect.Value) error {
		if visibility == targetVisibility {
			r, err := io.ReadFull(lr, bufElement)
			read += r
			if err != nil {
				return err
			}
			tInput.Set(reflect.ValueOf(new(big.Int).SetBytes(bufElement)))
		}
		return nil
	}

	publicReader := func(visibility compiled.Visibility, name string, tInput reflect.Value) error {
		return reader(compiled.Public, visibility, name, tInput)
	}

	secretReader := func(visibility compiled.Visibility, name string, tInput reflect.Value) error {
		return reader(compiled.Secret, visibility, name, tInput)
	}

	// public
	if _, err := schema.Parse(witness, tVariable, publicReader); err != nil {
		return int64(read), err
	}

	// secret
	if _, err := schema.Parse(witness, tVariable, secretReader); err != nil {
		return int64(read), err
	}

	return int64(read), nil
}

// ToJSON outputs a JSON string with variableName: value
// values are first converted to field element (mod base curve modulus)
func ToJSON(witness frontend.Circuit, curveID ecc.ID) (string, error) {
	switch curveID {
	case ecc.BN254:
		return witness_bn254.ToJSON(witness)
	case ecc.BLS12_377:
		return witness_bls12377.ToJSON(witness)
	case ecc.BLS12_381:
		return witness_bls12381.ToJSON(witness)
	case ecc.BW6_761:
		return witness_bw6761.ToJSON(witness)
	case ecc.BLS24_315:
		return witness_bls24315.ToJSON(witness)
	case ecc.BW6_633:
		return witness_bw6633.ToJSON(witness)
	default:
		panic("not implemented")
	}
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
