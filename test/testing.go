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

func (assert *Assert) ProverSucceeded(circuit frontend.Circuit, validWitness frontend.Circuit, opts ...func(opt *TestingOption) error) {
	opt := assert.options(opts...)

	var buf bytes.Buffer

	// for each {curve, backend} tuple
	for _, curve := range opt.curves {
		for _, b := range opt.backends {

			checkError := func(err error) { assert.checkError(err, b, curve, validWitness) }

			// 1- compile the circuit
			ccs, err := assert.compile(circuit, curve, b)
			checkError(err)

			// must not error with big int test engine
			err = isSolved(circuit, validWitness, curve)
			checkError(err)

			switch b {
			case backend.GROTH16:
				pk, vk, err := groth16.Setup(ccs)
				checkError(err)

				// ensure prove / verify works well with valid witnesses
				proof, err := groth16.Prove(ccs, pk, validWitness)
				checkError(err)

				err = groth16.Verify(proof, vk, validWitness)
				checkError(err)

				// same thing through serialized witnesses
				if opt.witnessSerialization {
					buf.Reset()

					_, err = witness.WriteFullTo(&buf, curve, validWitness)
					checkError(err)

					correctProof, err := groth16.ReadAndProve(ccs, pk, &buf)
					checkError(err)

					buf.Reset()

					_, err = witness.WritePublicTo(&buf, curve, validWitness)
					checkError(err)

					err = groth16.ReadAndVerify(correctProof, vk, &buf)
					checkError(err)
				}

			case backend.PLONK:
				srs, err := NewKZGSRS(ccs)
				checkError(err)

				pk, vk, err := plonk.Setup(ccs, srs)
				checkError(err)

				correctProof, err := plonk.Prove(ccs, pk, validWitness)
				checkError(err)

				err = plonk.Verify(correctProof, vk, validWitness)
				checkError(err)

				// witness serialization tests.
				if opt.witnessSerialization {
					buf.Reset()

					_, err := witness.WriteFullTo(&buf, curve, validWitness)
					checkError(err)

					correctProof, err := plonk.ReadAndProve(ccs, pk, &buf)
					checkError(err)

					buf.Reset()

					_, err = witness.WritePublicTo(&buf, curve, validWitness)
					checkError(err)

					err = plonk.ReadAndVerify(correctProof, vk, &buf)
					checkError(err)
				}

			default:
				panic("backend not implemented")
			}
		}
	}

}

func (assert *Assert) ProverFailed(circuit frontend.Circuit, invalidWitness frontend.Circuit, opts ...func(opt *TestingOption) error) {
	opt := assert.options(opts...)

	for _, curve := range opt.curves {
		for _, b := range opt.backends {

			checkError := func(err error) { assert.checkError(err, b, curve, invalidWitness) }
			mustError := func(err error) { assert.mustError(err, b, curve, invalidWitness) }

			// 1- compile the circuit
			ccs, err := assert.compile(circuit, curve, b)
			checkError(err)

			// must error with big int test engine
			err = isSolved(circuit, invalidWitness, curve)
			mustError(err)

			switch b {
			case backend.GROTH16:
				pk, vk, err := groth16.Setup(ccs)
				checkError(err)

				err = groth16.IsSolved(ccs, invalidWitness)
				mustError(err)

				proof, _ := groth16.Prove(ccs, pk, invalidWitness, backend.IgnoreSolverError)

				err = groth16.Verify(proof, vk, invalidWitness)
				mustError(err)

			case backend.PLONK:
				srs, err := NewKZGSRS(ccs)
				checkError(err)

				pk, vk, err := plonk.Setup(ccs, srs)
				checkError(err)

				err = plonk.IsSolved(ccs, invalidWitness)
				mustError(err)

				incorrectProof, _ := plonk.Prove(ccs, pk, invalidWitness, backend.IgnoreSolverError)
				err = plonk.Verify(incorrectProof, vk, invalidWitness)
				mustError(err)

			default:
				panic("backend not implemented")
			}
		}
	}
}

func (assert *Assert) SolvingSucceeded(circuit frontend.Circuit, validWitness frontend.Circuit, opts ...func(opt *TestingOption) error) {
	opt := assert.options(opts...)

	for _, curve := range opt.curves {
		for _, b := range opt.backends {

			checkError := func(err error) { assert.checkError(err, b, curve, validWitness) }

			// 1- compile the circuit
			ccs, err := assert.compile(circuit, curve, b)
			checkError(err)

			// must not error with big int test engine
			err = isSolved(circuit, validWitness, curve)
			checkError(err)

			switch b {
			case backend.GROTH16:
				err := groth16.IsSolved(ccs, validWitness, opt.proverOpts...)
				checkError(err)

			case backend.PLONK:
				plonk.IsSolved(ccs, validWitness, opt.proverOpts...)
				checkError(err)
			default:
				panic("not implemented")
			}

		}
	}
}

func (assert *Assert) SolvingFailed(circuit frontend.Circuit, invalidWitness frontend.Circuit, opts ...func(opt *TestingOption) error) {
	opt := assert.options(opts...)

	for _, curve := range opt.curves {
		for _, b := range opt.backends {

			checkError := func(err error) { assert.checkError(err, b, curve, invalidWitness) }
			mustError := func(err error) { assert.mustError(err, b, curve, invalidWitness) }

			// 1- compile the circuit
			ccs, err := assert.compile(circuit, curve, b)
			checkError(err)

			// must error with big int test engine
			err = isSolved(circuit, invalidWitness, curve)
			mustError(err)

			switch b {
			case backend.GROTH16:
				err := groth16.IsSolved(ccs, invalidWitness, opt.proverOpts...)
				mustError(err)
			case backend.PLONK:
				err := plonk.IsSolved(ccs, invalidWitness, opt.proverOpts...)
				mustError(err)
			default:
				panic("not implemented")
			}

		}
	}
}

func Fuzz(circuit frontend.Circuit) error {
	panic("not implemented")
}

// compile the given circuit for given curve and backend, if not already present in cache
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

// default options
func (assert *Assert) options(opts ...func(*TestingOption) error) TestingOption {
	// apply options
	opt := TestingOption{
		witnessSerialization: true,
		backends:             backend.Implemented(),
		curves:               ecc.Implemented(),
	}
	for _, option := range opts {
		err := option(&opt)
		assert.NoError(err, "parsing TestingOption")
	}

	if testing.Short() {
		// if curves are all there, we just test with bn254
		if reflect.DeepEqual(opt.curves, ecc.Implemented()) {
			opt.curves = []ecc.ID{ecc.BN254}
		}
	}
	return opt
}

// ensure the error is set, else fails the test
func (assert *Assert) mustError(err error, backendID backend.ID, curve ecc.ID, w frontend.Circuit) {
	if err != nil {
		return
	}
	e := fmt.Errorf("did not error (but should have) %s(%s): %w", backendID.String(), curve.String(), err)
	json, err := witness.ToJSON(w, curve)
	if err != nil {
		e = fmt.Errorf("did not error (but should have) %s(%s): %w", backendID.String(), curve.String(), err)
	} else if w != nil {
		e = fmt.Errorf("did not error (but should have) %w\nwitness:%s", e, json)
	}
	assert.FailNow(e.Error())
}

// ensure the error is nil, else fails the test
func (assert *Assert) checkError(err error, backendID backend.ID, curve ecc.ID, w frontend.Circuit) {
	if err == nil {
		return
	}
	e := fmt.Errorf("%s(%s): %w", backendID.String(), curve.String(), err)
	json, err := witness.ToJSON(w, curve)
	if err != nil {
		e = fmt.Errorf("%s(%s): %w", backendID.String(), curve.String(), err)
	} else if w != nil {
		e = fmt.Errorf("%w\nwitness:%s", e, json)
	}
	assert.FailNow(e.Error())
}
