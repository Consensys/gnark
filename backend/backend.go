// Copyright 2020 ConsenSys AG
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

// Package backend implements Zero Knowledge Proof systems: it consumes circuit compiled with gnark/frontend.
package backend

import (
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/logger"
	"github.com/rs/zerolog"
)

// ID represent a unique ID for a proving scheme
type ID uint16

const (
	UNKNOWN ID = iota
	GROTH16
	PLONK
)

// Implemented return the list of proof systems implemented in gnark
func Implemented() []ID {
	return []ID{GROTH16, PLONK}
}

// String returns the string representation of a proof system
func (id ID) String() string {
	switch id {
	case GROTH16:
		return "groth16"
	case PLONK:
		return "plonk"
	default:
		return "unknown"
	}
}

// ProverOption defines option for altering the behaviour of the prover in
// Prove, ReadAndProve and IsSolved methods. See the descriptions of functions
// returning instances of this type for implemented options.
type ProverOption func(*ProverConfig) error

// ProverConfig is the configuration for the prover with the options applied.
type ProverConfig struct {
	Force         bool                      // defaults to false
	HintFunctions map[hint.ID]hint.Function // defaults to all built-in hint functions
	CircuitLogger zerolog.Logger            // defaults to gnark.Logger
}

// NewProverConfig returns a default ProverConfig with given prover options opts
// applied.
func NewProverConfig(opts ...ProverOption) (ProverConfig, error) {
	log := logger.Logger()
	opt := ProverConfig{CircuitLogger: log, HintFunctions: make(map[hint.ID]hint.Function)}
	for _, v := range hint.GetRegistered() {
		opt.HintFunctions[hint.UUID(v)] = v
	}
	for _, option := range opts {
		if err := option(&opt); err != nil {
			return ProverConfig{}, err
		}
	}
	return opt, nil
}

// IgnoreSolverError is a prover option that indicates that the Prove algorithm
// should complete even if constraint system is not solved. In that case, Prove
// will output an invalid Proof, but will execute all algorithms which is useful
// for test and benchmarking purposes.
func IgnoreSolverError() ProverOption {
	return func(opt *ProverConfig) error {
		opt.Force = true
		return nil
	}
}

// WithHints is a prover option that specifies additional hint functions to be used
// by the constraint solver.
func WithHints(hintFunctions ...hint.Function) ProverOption {
	log := logger.Logger()
	return func(opt *ProverConfig) error {
		// it is an error to register hint function several times, but as the
		// prover already checks it then omit here.
		for _, h := range hintFunctions {
			uuid := hint.UUID(h)
			if _, ok := opt.HintFunctions[uuid]; ok {
				log.Warn().Int("hintID", int(uuid)).Str("name", hint.Name(h)).Msg("duplicate hint function")
			} else {
				opt.HintFunctions[uuid] = h
			}
		}
		return nil
	}
}

// WithCircuitLogger is a prover option that specifies zerolog.Logger as a destination for the
// logs printed by api.Println(). By default, uses gnark/logger.
// zerolog.Nop() will disable logging
func WithCircuitLogger(l zerolog.Logger) ProverOption {
	return func(opt *ProverConfig) error {
		opt.CircuitLogger = l
		return nil
	}
}
