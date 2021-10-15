package test

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/stretchr/testify/require"
)

var (
	ErrCompilationNotDeterministic = errors.New("compilation is not deterministic")
	ErrInvalidWitnessSolvedCS      = errors.New("invalid witness solved the constraint system")
	ErrInvalidWitnessVerified      = errors.New("invalid witness resulted in a valid proof")
)

// Assert is a helper to test circuits
type Assert struct {
	*require.Assertions
	compiled map[string]frontend.CompiledConstraintSystem // cache compilation
}

// NewAssert returns an Assert helper
func NewAssert(t *testing.T) *Assert {
	return &Assert{require.New(t), make(map[string]frontend.CompiledConstraintSystem)}
}

// TODO @gbotrel cache plonk.NewSRS(..) per curve, to avoid slow tests.
// TODO @gbotrel proverSucceeded / failed must check first without backend (ie constraint system)

func (assert *Assert) ProverSucceeded(circuit frontend.Circuit, validWitness frontend.Circuit, opts ...func(opt *TestingOption) error) {
	opt, err := options(opts...)
	assert.NoError(err, "parsing TestingOption")

	var buf bytes.Buffer
	var currentWitness frontend.Circuit

	// for each {curve, backend} tuple
	for _, curve := range opt.curves {
		for _, b := range opt.backends {
			currentWitness = nil

			fail := func(err error) {
				toReturn := fmt.Errorf("%s(%s): %w", b.String(), curve.String(), err)
				json, err := witness.ToJSON(currentWitness, curve)
				if err != nil {
					toReturn = fmt.Errorf("%s(%s): %w", b.String(), curve.String(), err)
				} else if currentWitness != nil {
					toReturn = fmt.Errorf("%w\nwitness:%s", toReturn, json)
				}
				assert.FailNow(toReturn.Error())
			}

			// 1- compile the circuit
			ccs, err := assert.compile(circuit, curve, b)
			if err != nil {
				fail(err)
			}

			_ccs, err := assert.compile(circuit, curve, b)
			if err != nil {
				fail(err)
			}

			if !reflect.DeepEqual(ccs, _ccs) {
				fail(ErrCompilationNotDeterministic)
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
					fail(err)
				}

				// ensure prove / verify works well with valid witnesses
				currentWitness = validWitness
				proof, err := groth16.Prove(ccs, pk, validWitness)
				if err != nil {
					fail(err)
				}
				if err := groth16.Verify(proof, vk, validWitness); err != nil {
					fail(err)
				}

				// same thing through serialized witnesses
				if opt.witnessSerialization {
					buf.Reset()

					if _, err := witness.WriteFullTo(&buf, curve, validWitness); err != nil {
						fail(err)
					}

					correctProof, err := groth16.ReadAndProve(ccs, pk, &buf)
					if err != nil {
						fail(err)
					}

					buf.Reset()

					_, err = witness.WritePublicTo(&buf, curve, validWitness)
					if err != nil {
						fail(err)
					}

					if err = groth16.ReadAndVerify(correctProof, vk, &buf); err != nil {
						fail(err)
					}
				}

			case backend.PLONK:
				srs, err := plonk.NewSRS(ccs)
				if err != nil {
					fail(err)
				}

				pk, vk, err := plonk.Setup(ccs, srs)
				if err != nil {
					fail(err)
				}

				currentWitness = validWitness
				correctProof, err := plonk.Prove(ccs, pk, validWitness)
				if err != nil {
					fail(err)
				}
				if err := plonk.Verify(correctProof, vk, validWitness); err != nil {
					fail(err)
				}

				// witness serialization tests.
				if opt.witnessSerialization {
					buf.Reset()

					_, err := witness.WriteFullTo(&buf, curve, validWitness)
					if err != nil {
						fail(err)
					}

					correctProof, err := plonk.ReadAndProve(ccs, pk, &buf)
					if err != nil {
						fail(err)
					}

					buf.Reset()

					_, err = witness.WritePublicTo(&buf, curve, validWitness)
					if err != nil {
						fail(err)
					}

					err = plonk.ReadAndVerify(correctProof, vk, &buf)
					if err != nil {
						fail(err)
					}
				}

			default:
				panic("backend not implemented")
			}
		}
	}

}

func (assert *Assert) ProverFailed(circuit frontend.Circuit, invalidWitness frontend.Circuit, opts ...func(opt *TestingOption) error) {
	opt, err := options(opts...)
	assert.NoError(err, "parsing TestingOption")

	var currentWitness frontend.Circuit

	// for each {curve, backend} tuple
	for _, curve := range opt.curves {
		for _, b := range opt.backends {

			currentWitness = nil

			fail := func(err error) {
				toReturn := fmt.Errorf("%s(%s): %w", b.String(), curve.String(), err)
				json, err := witness.ToJSON(currentWitness, curve)
				if err != nil {
					toReturn = fmt.Errorf("%s(%s): %w", b.String(), curve.String(), err)
				} else if currentWitness != nil {
					toReturn = fmt.Errorf("%w\nwitness:%s", toReturn, json)
				}
				assert.FailNow(toReturn.Error())
			}

			// 1- compile the circuit
			ccs, err := assert.compile(circuit, curve, b)
			if err != nil {
				fail(err)
			}

			_ccs, err := assert.compile(circuit, curve, b)
			if err != nil {
				fail(err)
			}

			if !reflect.DeepEqual(ccs, _ccs) {
				fail(ErrCompilationNotDeterministic)
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
					fail(err)
				}

				// ensure prove / verify fails with invalid witness
				currentWitness = invalidWitness

				if err := groth16.IsSolved(ccs, invalidWitness); err == nil {
					fail(ErrInvalidWitnessSolvedCS)
				}

				proof, _ := groth16.Prove(ccs, pk, invalidWitness, backend.IgnoreSolverError)

				if err := groth16.Verify(proof, vk, invalidWitness); err == nil {
					fail(ErrInvalidWitnessVerified)
				}

			case backend.PLONK:
				srs, err := plonk.NewSRS(ccs)
				if err != nil {
					fail(err)
				}

				pk, vk, err := plonk.Setup(ccs, srs)
				if err != nil {
					fail(err)
				}

				currentWitness = invalidWitness
				incorrectProof, err := plonk.Prove(ccs, pk, invalidWitness, backend.IgnoreSolverError)
				if err != nil {
					fail(err)
				}
				if err := plonk.Verify(incorrectProof, vk, invalidWitness); err == nil {
					fail(err)
				}
			default:
				panic("backend not implemented")
			}
		}
	}
}

func (assert *Assert) compile(circuit frontend.Circuit, curveID ecc.ID, backendID backend.ID) (frontend.CompiledConstraintSystem, error) {
	key := curveID.String() + backendID.String() + reflect.TypeOf(circuit).String()

	// check if we already compiled it
	if ccs, ok := assert.compiled[key]; ok {
		return ccs, nil
	}

	// else compile it and ensure it is deterministic
	ccs, err := frontend.Compile(curveID, backendID, circuit)
	if err != nil {
		return nil, err
	}

	_ccs, err := frontend.Compile(curveID, backendID, circuit)
	if err != nil {
		return nil, err
	}

	if !reflect.DeepEqual(ccs, _ccs) {
		return nil, ErrCompilationNotDeterministic
	}

	return ccs, nil
}

func (assert *Assert) SolvingSucceeded(circuit frontend.Circuit, validWitness frontend.Circuit, opts ...func(opt *TestingOption) error) {
	// TODO @gbotrel
	opt, err := options(opts...)
	assert.NoError(err, "parsing TestingOption")

	var currentWitness frontend.Circuit

	// for each {curve, backend} tuple
	for _, curve := range opt.curves {
		for _, b := range opt.backends {

			currentWitness = nil

			fail := func(err error) {
				toReturn := fmt.Errorf("%s(%s): %w", b.String(), curve.String(), err)
				json, err := witness.ToJSON(currentWitness, curve)
				if err != nil {
					toReturn = fmt.Errorf("%s(%s): %w", b.String(), curve.String(), err)
				} else if currentWitness != nil {
					toReturn = fmt.Errorf("%w\nwitness:%s", toReturn, json)
				}
				assert.FailNow(toReturn.Error())
			}

			// 1- compile the circuit
			ccs, err := assert.compile(circuit, curve, b)
			if err != nil {
				fail(err)
			}

			switch b {
			case backend.GROTH16:
				if err := groth16.IsSolved(ccs, validWitness, opt.proverOpts...); err != nil {
					fail(err)
				}

			case backend.PLONK:
				if err := plonk.IsSolved(ccs, validWitness, opt.proverOpts...); err != nil {
					fail(err)
				}
			default:
				panic("not implemented")
			}

		}
	}
}

func (assert *Assert) SolvingFailed(circuit frontend.Circuit, invalidWitness frontend.Circuit, opts ...func(opt *TestingOption) error) {
	// TODO @gbotrel
	opt, err := options(opts...)
	assert.NoError(err, "parsing TestingOption")

	var currentWitness frontend.Circuit

	// for each {curve, backend} tuple
	for _, curve := range opt.curves {
		for _, b := range opt.backends {

			currentWitness = nil

			fail := func(err error) {
				toReturn := fmt.Errorf("%s(%s): %w", b.String(), curve.String(), err)
				json, err := witness.ToJSON(currentWitness, curve)
				if err != nil {
					toReturn = fmt.Errorf("%s(%s): %w", b.String(), curve.String(), err)
				} else if currentWitness != nil {
					toReturn = fmt.Errorf("%w\nwitness:%s", toReturn, json)
				}
				assert.FailNow(toReturn.Error())
			}

			// 1- compile the circuit
			ccs, err := assert.compile(circuit, curve, b)
			if err != nil {
				fail(err)
			}

			switch b {
			case backend.GROTH16:
				if err := groth16.IsSolved(ccs, invalidWitness, opt.proverOpts...); err == nil {
					fail(err)
				}

			case backend.PLONK:
				if err := plonk.IsSolved(ccs, invalidWitness, opt.proverOpts...); err == nil {
					fail(err)
				}
			default:
				panic("not implemented")
			}

		}
	}
}

func options(opts ...func(*TestingOption) error) (TestingOption, error) {
	// apply options
	opt := TestingOption{
		witnessSerialization: true,
		backends:             backend.Implemented(),
		curves:               ecc.Implemented(),
	}
	for _, option := range opts {
		if err := option(&opt); err != nil {
			return TestingOption{}, err
		}
	}
	return opt, nil
}

func Fuzz(circuit frontend.Circuit) error {
	panic("not implemented")
}

type TestingOption struct {
	backends             []backend.ID
	curves               []ecc.ID
	witnessSerialization bool
	proverOpts           []func(opt *backend.ProverOption) error
}

func WithBackends(b backend.ID, backends ...backend.ID) func(opt *TestingOption) error {
	return func(opt *TestingOption) error {
		opt.backends = []backend.ID{b}
		opt.backends = append(opt.backends, backends...)
		return nil
	}
}

func WithCurves(c ecc.ID, curves ...ecc.ID) func(opt *TestingOption) error {
	return func(opt *TestingOption) error {
		opt.curves = []ecc.ID{c}
		opt.curves = append(opt.curves, curves...)
		return nil
	}
}

func NoSerialization() func(opt *TestingOption) error {
	return func(opt *TestingOption) error {
		opt.witnessSerialization = false
		return nil
	}
}

func WithProverOpts(proverOpts ...func(opt *backend.ProverOption) error) func(opt *TestingOption) error {
	return func(opt *TestingOption) error {
		opt.proverOpts = proverOpts
		return nil
	}
}
