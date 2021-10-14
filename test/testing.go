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
}

// NewAssert returns an Assert helper
func NewAssert(t *testing.T) *Assert {
	return &Assert{require.New(t)}
}

// TODO @gbotrel cache plonk.NewSRS(..) per curve, to avoid slow tests.
// TODO @gbotrel proverSucceeded / failed must check first without backend (ie constraint system)

func (assert *Assert) ProverSucceeded(circuit frontend.Circuit, validWitnesses []frontend.Circuit, opts ...func(opt *TestingOption) error) {
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
			ccs, err := frontend.Compile(curve, b, circuit)
			if err != nil {
				fail(err)
			}

			_ccs, err := frontend.Compile(curve, b, circuit)
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
				for _, w := range validWitnesses {
					currentWitness = w
					proof, err := groth16.Prove(ccs, pk, w)
					if err != nil {
						fail(err)
					}
					if err := groth16.Verify(proof, vk, w); err != nil {
						fail(err)
					}

					// same thing through serialized witnesses
					if opt.witnessSerialization {
						buf.Reset()

						if _, err := witness.WriteFullTo(&buf, curve, w); err != nil {
							fail(err)
						}

						correctProof, err := groth16.ReadAndProve(ccs, pk, &buf)
						if err != nil {
							fail(err)
						}

						buf.Reset()

						_, err = witness.WritePublicTo(&buf, curve, w)
						if err != nil {
							fail(err)
						}

						if err = groth16.ReadAndVerify(correctProof, vk, &buf); err != nil {
							fail(err)
						}
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

				for _, w := range validWitnesses {
					currentWitness = w
					correctProof, err := plonk.Prove(ccs, pk, w)
					if err != nil {
						fail(err)
					}
					if err := plonk.Verify(correctProof, vk, w); err != nil {
						fail(err)
					}

					// witness serialization tests.
					if opt.witnessSerialization {
						buf.Reset()

						_, err := witness.WriteFullTo(&buf, curve, w)
						if err != nil {
							fail(err)
						}

						correctProof, err := plonk.ReadAndProve(ccs, pk, &buf)
						if err != nil {
							fail(err)
						}

						buf.Reset()

						_, err = witness.WritePublicTo(&buf, curve, w)
						if err != nil {
							fail(err)
						}

						err = plonk.ReadAndVerify(correctProof, vk, &buf)
						if err != nil {
							fail(err)
						}
					}
				}

			default:
				panic("backend not implemented")
			}
		}
	}

}

func (assert *Assert) ProverFailed(circuit frontend.Circuit, invalidWitnesses []frontend.Circuit, opts ...func(opt *TestingOption) error) {
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
			ccs, err := frontend.Compile(curve, b, circuit)
			if err != nil {
				fail(err)
			}

			_ccs, err := frontend.Compile(curve, b, circuit)
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
				for _, w := range invalidWitnesses {
					currentWitness = w

					if err := groth16.IsSolved(ccs, w); err == nil {
						fail(ErrInvalidWitnessSolvedCS)
					}

					proof, _ := groth16.Prove(ccs, pk, w, backend.IgnoreSolverError)

					if err := groth16.Verify(proof, vk, w); err == nil {
						fail(ErrInvalidWitnessVerified)
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

				for _, w := range invalidWitnesses {
					currentWitness = w
					incorrectProof, err := plonk.Prove(ccs, pk, w, backend.IgnoreSolverError)
					if err != nil {
						fail(err)
					}
					if err := plonk.Verify(incorrectProof, vk, w); err == nil {
						fail(err)
					}
				}
			default:
				panic("backend not implemented")
			}
		}
	}
}

func (assert *Assert) SolvingSucceeded(circuit frontend.Circuit, validWitnesses []frontend.Circuit, opts ...func(opt *TestingOption) error) {
	// TODO @gbotrel
}

func (assert *Assert) SolvingFailed(circuit frontend.Circuit, invalidWitnesses []frontend.Circuit, opts ...func(opt *TestingOption) error) {
	// TODO @gbotrel
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
