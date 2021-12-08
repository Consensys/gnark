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
// 	    X cs.Variable
// 	    Y cs.Variable `gnark:",public"`
// 	    Z cs.Variable
// 	}
//
// A valid witness would be:
// 	* `[uint32(3)|bytes(Y)|bytes(X)|bytes(Z)]`
// 	* Hex representation with values `Y = 35`, `X = 3`, `Z = 2`
// 	`00000003000000000000000000000000000000000000000000000000000000000000002300000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000002`
package witness

import (
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs"
	witness_bls12377 "github.com/consensys/gnark/internal/backend/bls12-377/witness"
	witness_bls12381 "github.com/consensys/gnark/internal/backend/bls12-381/witness"
	witness_bls24315 "github.com/consensys/gnark/internal/backend/bls24-315/witness"
	witness_bn254 "github.com/consensys/gnark/internal/backend/bn254/witness"
	witness_bw6633 "github.com/consensys/gnark/internal/backend/bw6-633/witness"
	witness_bw6761 "github.com/consensys/gnark/internal/backend/bw6-761/witness"
	"github.com/consensys/gnark/internal/backend/compiled"
	"github.com/consensys/gnark/internal/parser"
)

// WriteFullTo encodes the witness to a slice of []fr.Element and write the []byte on provided writer
func WriteFullTo(w io.Writer, curveID ecc.ID, witness frontend.Circuit) (int64, error) {
	switch curveID {
	case ecc.BN254:
		_witness := &witness_bn254.Witness{}
		if err := _witness.FromFullAssignment(witness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	case ecc.BLS12_377:
		_witness := &witness_bls12377.Witness{}
		if err := _witness.FromFullAssignment(witness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	case ecc.BLS12_381:
		_witness := &witness_bls12381.Witness{}
		if err := _witness.FromFullAssignment(witness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	case ecc.BW6_761:
		_witness := &witness_bw6761.Witness{}
		if err := _witness.FromFullAssignment(witness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	case ecc.BLS24_315:
		_witness := &witness_bls24315.Witness{}
		if err := _witness.FromFullAssignment(witness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	case ecc.BW6_633:
		_witness := &witness_bw6633.Witness{}
		if err := _witness.FromFullAssignment(witness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)

	default:
		panic("not implemented")
	}
}

// WritePublicTo encodes the witness to a slice of []fr.Element and write the result on provided writer
func WritePublicTo(w io.Writer, curveID ecc.ID, publicWitness frontend.Circuit) (int64, error) {
	switch curveID {
	case ecc.BN254:
		_witness := &witness_bn254.Witness{}
		if err := _witness.FromPublicAssignment(publicWitness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	case ecc.BLS12_377:
		_witness := &witness_bls12377.Witness{}
		if err := _witness.FromPublicAssignment(publicWitness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	case ecc.BLS12_381:
		_witness := &witness_bls12381.Witness{}
		if err := _witness.FromPublicAssignment(publicWitness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	case ecc.BW6_761:
		_witness := &witness_bw6761.Witness{}
		if err := _witness.FromPublicAssignment(publicWitness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	case ecc.BLS24_315:
		_witness := &witness_bls24315.Witness{}
		if err := _witness.FromPublicAssignment(publicWitness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	case ecc.BW6_633:
		_witness := &witness_bw6633.Witness{}
		if err := _witness.FromPublicAssignment(publicWitness); err != nil {
			return 0, err
		}
		return _witness.WriteTo(w)
	default:
		panic("not implemented")
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
	if err := parser.Visit(circuit, "", compiled.Unset, collectHandler, tVariable); err != nil {
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
	nbPublic := 0
	collectHandler := func(visibility compiled.Visibility, name string, tInput reflect.Value) error {
		if visibility == compiled.Public {
			nbPublic++
		}
		return nil
	}
	_ = parser.Visit(witness, "", compiled.Unset, collectHandler, tVariable)

	if nbPublic == 0 {
		return 0, nil
	}

	// first 4 bytes have number of bytes
	var buf [4]byte
	if read, err := io.ReadFull(r, buf[:4]); err != nil {
		return int64(read), err
	}
	sliceLen := binary.BigEndian.Uint32(buf[:4])
	if int(sliceLen) != nbPublic {
		return 4, errors.New("invalid witness size")
	}

	elementSize := curveID.Info().Fr.Bytes

	expectedSize := elementSize * nbPublic

	lr := io.LimitReader(r, int64(expectedSize*elementSize))
	read := 4

	bufElement := make([]byte, elementSize)
	reader := func(visibility compiled.Visibility, name string, tInput reflect.Value) error {
		if visibility == compiled.Public {
			r, err := io.ReadFull(lr, bufElement)
			read += r
			if err != nil {
				return err
			}
			tInput.Set(reflect.ValueOf(new(big.Int).SetBytes(bufElement)))
		}
		return nil
	}

	if err := parser.Visit(witness, "", compiled.Unset, reader, tVariable); err != nil {
		return int64(read), err
	}

	return int64(read), nil
}

// ReadFullFrom reads bytes from provided reader and attempts to reconstruct
// a statically typed witness, with big.Int values
// The stream must match the binary protocol to encode witnesses
// This function will read at most the number of expected bytes
// If it can't fully re-construct the witness from the reader, returns an error
// if the provided witness has 0 public Variables and 0 secret Variables this function returns 0, nil
func ReadFullFrom(r io.Reader, curveID ecc.ID, witness frontend.Circuit) (int64, error) {
	nbPublic := 0
	nbSecrets := 0
	collectHandler := func(visibility compiled.Visibility, name string, tInput reflect.Value) error {
		if visibility == compiled.Public {
			nbPublic++
		} else if visibility == compiled.Secret {
			nbSecrets++
		}
		return nil
	}
	_ = parser.Visit(witness, "", compiled.Unset, collectHandler, tVariable)

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
	if err := parser.Visit(witness, "", compiled.Unset, publicReader, tVariable); err != nil {
		return int64(read), err
	}

	// secret
	if err := parser.Visit(witness, "", compiled.Unset, secretReader, tVariable); err != nil {
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
	tVariable = reflect.ValueOf(struct{ A cs.Variable }{}).FieldByName("A").Type()
}
