package test

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
)

var (
	ErrCompilationNotDeterministic = errors.New("compilation is not deterministic")
	ErrInvalidWitnessSolvedCS      = errors.New("invalid witness solved the constraint system")
	ErrInvalidWitnessVerified      = errors.New("invalid witness resulted in a valid proof")
)

// Run ...
func Run(t frontend.TestableCircuit, opts ...func(opt *TestingOption) error) error {
	// apply options
	opt := TestingOption{
		witnessSerialization: true,
		backends:             []backend.ID{backend.GROTH16},
		curves:               ecc.Implemented(),
	}
	for _, option := range opts {
		if err := option(&opt); err != nil {
			return err
		}
	}

	var buf bytes.Buffer
	var currentWitness frontend.Circuit

	// for each {curve, backend} tuple
	for _, curve := range opt.curves {
		for _, b := range opt.backends {

			currentWitness = nil

			wrapError := func(err error) error {
				toReturn := fmt.Errorf("%s(%s): %w", b.String(), curve.String(), err)
				json, err := witness.ToJSON(currentWitness, curve)
				if err != nil {
					return fmt.Errorf("%s(%s): %w", b.String(), curve.String(), err)
				}
				if currentWitness != nil {
					toReturn = fmt.Errorf("%w\nwitness:%s", toReturn, json)
				}
				return toReturn
			}

			// 1- compile the circuit
			ccs, err := frontend.Compile(curve, b, t)
			if err != nil {
				return wrapError(err)
			}

			_ccs, err := frontend.Compile(curve, b, t)
			if err != nil {
				return wrapError(err)
			}

			if !reflect.DeepEqual(ccs, _ccs) {
				return wrapError(ErrCompilationNotDeterministic)
			}

			// TODO @gbotrel check stats for non regression
			// // ensure we didn't introduce regressions that make circuits less efficient
			// nbConstraints := ccs.GetNbConstraints()
			// internal, secret, public := ccs.GetNbVariables()
			// checkStats(t, name, nbConstraints, internal, secret, public, curve, backend.GROTH16)

			switch b {
			case backend.GROTH16:
				pk, vk, err := groth16.Setup(ccs)
				if err != nil {
					return wrapError(err)
				}

				// ensure prove / verify works well with valid witnesses
				validWitnesses := t.ValidWitnesses(curve)
				for _, w := range validWitnesses {
					currentWitness = w
					proof, err := groth16.Prove(ccs, pk, w)
					if err != nil {
						return wrapError(err)
					}
					if err := groth16.Verify(proof, vk, w); err != nil {
						return wrapError(err)
					}

					// same thing through serialized witnesses
					if opt.witnessSerialization {
						buf.Reset()

						if _, err := witness.WriteFullTo(&buf, curve, w); err != nil {
							return wrapError(err)
						}

						correctProof, err := groth16.ReadAndProve(ccs, pk, &buf)
						if err != nil {
							return wrapError(err)
						}

						buf.Reset()

						_, err = witness.WritePublicTo(&buf, curve, w)
						if err != nil {
							return wrapError(err)
						}

						if err = groth16.ReadAndVerify(correctProof, vk, &buf); err != nil {
							return wrapError(err)
						}
					}
				}

				// ensure prove / verify fails with invalid witness
				invalidWitnesses := t.InvalidWitnesses(curve)
				for _, w := range invalidWitnesses {
					currentWitness = w

					if err := groth16.IsSolved(ccs, w); err == nil {
						return wrapError(ErrInvalidWitnessSolvedCS)
					}

					proof, _ := groth16.Prove(ccs, pk, w, backend.IgnoreSolverError)

					if err := groth16.Verify(proof, vk, w); err == nil {
						return wrapError(ErrInvalidWitnessVerified)
					}
				}

			case backend.PLONK:
				panic("need to implement PLONK")
			default:
				panic("backend not implemented")
			}
		}
	}

	return nil
}

func Fuzz(t frontend.FuzzableCircuit, opts ...func(opt *TestingOption) error) error {
	fmt.Println("fuzzing!")
	return nil
}

type TestingOption struct {
	backends             []backend.ID
	curves               []ecc.ID
	witnessSerialization bool
}
