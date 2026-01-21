package frontend

import (
	"math/big"
	"reflect"

	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend/schema"
)

// NewWitness build an ordered vector of field elements from the given
// assignment from a type implementing [Circuit] interface.
//
// if [PublicOnly] is specified, returns the public part of the witness only
// (`[public]`). Otherwise it returns both public and secret parts of the
// witness (`[public | secret]`).
//
// For serialization, the returned witness implements different serialization
// methods to allow serializing into binary and JSON formats.
//
// For deserializing purposes, use [witness.New] to create an empty witness and
// then use [witness.Witness.Fill] or [witness.Witness.ReadBinary] to fill the
// witness values.
//
// See ExampleWitness in witness package for usage.
func NewWitness(assignment Circuit, field *big.Int, opts ...WitnessOption) (witness.Witness, error) {
	opt, err := options(opts...)
	if err != nil {
		return nil, err
	}

	// count the leaves
	s, err := schema.Walk(field, assignment, tVariable, nil)
	if err != nil {
		return nil, err
	}
	if opt.publicOnly {
		s.Secret = 0
	}

	// allocate the witness
	w, err := witness.New(field)
	if err != nil {
		return nil, err
	}

	// write the public | secret values in a chan
	chValues := make(chan any)
	go func() {
		defer close(chValues)
		schema.Walk(field, assignment, tVariable, func(leaf schema.LeafInfo, tValue reflect.Value) error {
			if leaf.Visibility == schema.Public {
				chValues <- tValue.Interface()
			}
			return nil
		})
		if !opt.publicOnly {
			schema.Walk(field, assignment, tVariable, func(leaf schema.LeafInfo, tValue reflect.Value) error {
				if leaf.Visibility == schema.Secret {
					chValues <- tValue.Interface()
				}
				return nil
			})
		}
	}()
	if err := w.Fill(s.Public, s.Secret, chValues); err != nil {
		return nil, err
	}

	return w, nil
}

// NewSchema returns the schema corresponding to the circuit structure.
//
// This is used to JSON (un)marshall witnesses.
func NewSchema(field *big.Int, circuit Circuit) (*schema.Schema, error) {
	return schema.New(field, circuit, tVariable)
}

// default options
func options(opts ...WitnessOption) (witnessConfig, error) {
	// apply options
	opt := witnessConfig{
		publicOnly: false,
	}
	for _, option := range opts {
		if err := option(&opt); err != nil {
			return opt, err
		}
	}

	return opt, nil
}

// WitnessOption sets optional parameter to witness instantiation from an assignment
type WitnessOption func(*witnessConfig) error

type witnessConfig struct {
	publicOnly bool
}

// PublicOnly enables to instantiate a witness with the public part only of the assignment
func PublicOnly() WitnessOption {
	return func(opt *witnessConfig) error {
		opt.publicOnly = true
		return nil
	}
}
