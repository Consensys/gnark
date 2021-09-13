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
// 	* `nbElements == len(publicVariables) + len(secretVariables)`.
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
	"io"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc"
	witness_bls12377 "github.com/consensys/gnark/internal/backend/bls12-377/witness"
	witness_bls12381 "github.com/consensys/gnark/internal/backend/bls12-381/witness"
	witness_bls24315 "github.com/consensys/gnark/internal/backend/bls24-315/witness"
	witness_bn254 "github.com/consensys/gnark/internal/backend/bn254/witness"
	witness_bw6761 "github.com/consensys/gnark/internal/backend/bw6-761/witness"
	"github.com/consensys/gnark/internal/backend/compiled"
	"github.com/consensys/gnark/internal/parser"

	"github.com/consensys/gnark/frontend"
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
	default:
		panic("not implemented")
	}
}

// WriteSequence writes the expected sequence order of the witness on provided writer
// witness elements are identified by their tag name, or if unset, struct & field name
func WriteSequence(w io.Writer, circuit frontend.Circuit) error {
	var public, secret []string
	var collectHandler parser.LeafHandler = func(visibility compiled.Visibility, name string, tInput reflect.Value) error {
		if visibility == compiled.Public {
			public = append(public, name)
		} else if visibility == compiled.Secret {
			secret = append(secret, name)
		}
		return nil
	}
	if err := parser.Visit(circuit, "", compiled.Unset, collectHandler, reflect.TypeOf(frontend.Variable{})); err != nil {
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
