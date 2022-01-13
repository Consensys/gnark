package frontend

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/witness"
)

// NewWitness build an orderded vector of field elements from the given assignment (Circuit)
// if PublicOnly is specified, returns the public part of the witness only
// else returns [public | secret]. The result can then be serialized to / from json & binary
//
// Returns an error if the assignment has missing entries
func NewWitness(assignment Circuit, curveID ecc.ID, opts ...WitnessOption) (*witness.Witness, error) {
	opt, err := options(opts...)
	if err != nil {
		return nil, err
	}

	w, err := witness.New(curveID, nil)
	if err != nil {
		return nil, err
	}

	w.Schema, err = w.Vector.FromAssignment(assignment, tVariable, opt.publicOnly)
	if err != nil {
		return nil, err
	}

	return w, nil
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

// WitnessOption sets optional parameter to witness instantiation from an assigment
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
