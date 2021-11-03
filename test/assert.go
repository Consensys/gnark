/*
Copyright © 2021 ConsenSys Software Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
	"github.com/consensys/gnark/internal/utils"
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

// NewAssert returns an Assert helper embedding a testify/require object for convenience
//
// The Assert object caches the compiled circuit:
//
// the first call to assert.ProverSucceeded/Failed will compile the circuit for n curves, m backends
// and subsequent calls will re-use the result of the compilation, if available.
func NewAssert(t *testing.T) *Assert {
	return &Assert{require.New(t), make(map[string]frontend.CompiledConstraintSystem)}
}

// ProverSucceeded fails the test if any of the following step errored:
//
// 1. compiles the circuit (or fetch it from the cache)
// 2. using the test execution engine, executes the circuit with provided witness
// 3. run Setup / Prove / Verify with the backend
// 4. if set, (de)serializes the witness and call ReadAndProve and ReadAndVerify on the backend
//
// By default, this tests on all curves and proving schemes supported by gnark. See available TestingOption.
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
			err = IsSolved(circuit, validWitness, curve)
			checkError(err)

			switch b {
			case backend.GROTH16:
				pk, vk, err := groth16.Setup(ccs)
				checkError(err)

				// ensure prove / verify works well with valid witnesses
				proof, err := groth16.Prove(ccs, pk, validWitness, opt.proverOpts...)
				checkError(err)

				err = groth16.Verify(proof, vk, validWitness)
				checkError(err)

				// same thing through serialized witnesses
				if opt.witnessSerialization {
					buf.Reset()

					_, err = witness.WriteFullTo(&buf, curve, validWitness)
					checkError(err)

					correctProof, err := groth16.ReadAndProve(ccs, pk, &buf, opt.proverOpts...)
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

				correctProof, err := plonk.Prove(ccs, pk, validWitness, opt.proverOpts...)
				checkError(err)

				err = plonk.Verify(correctProof, vk, validWitness)
				checkError(err)

				// witness serialization tests.
				if opt.witnessSerialization {
					buf.Reset()

					_, err := witness.WriteFullTo(&buf, curve, validWitness)
					checkError(err)

					correctProof, err := plonk.ReadAndProve(ccs, pk, &buf, opt.proverOpts...)
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

	// TODO may not be the right place, but ensures all our tests call these minimal tests
	// (like filling a witness with zeroes, or binary values, ...)
	assert.Fuzz(circuit, 5, opts...)
}

// ProverSucceeded fails the test if any of the following step errored:
//
// 1. compiles the circuit (or fetch it from the cache)
// 2. using the test execution engine, executes the circuit with provided witness (must fail)
// 3. run Setup / Prove / Verify with the backend (must fail)
//
// By default, this tests on all curves and proving schemes supported by gnark. See available TestingOption.
func (assert *Assert) ProverFailed(circuit frontend.Circuit, invalidWitness frontend.Circuit, opts ...func(opt *TestingOption) error) {
	opt := assert.options(opts...)

	popts := append(opt.proverOpts, backend.IgnoreSolverError)

	for _, curve := range opt.curves {
		for _, b := range opt.backends {

			checkError := func(err error) { assert.checkError(err, b, curve, invalidWitness) }
			mustError := func(err error) { assert.mustError(err, b, curve, invalidWitness) }

			// 1- compile the circuit
			ccs, err := assert.compile(circuit, curve, b)
			checkError(err)

			// must error with big int test engine
			err = IsSolved(circuit, invalidWitness, curve)
			mustError(err)

			switch b {
			case backend.GROTH16:
				pk, vk, err := groth16.Setup(ccs)
				checkError(err)

				err = groth16.IsSolved(ccs, invalidWitness)
				mustError(err)

				proof, _ := groth16.Prove(ccs, pk, invalidWitness, popts...)

				err = groth16.Verify(proof, vk, invalidWitness)
				mustError(err)

			case backend.PLONK:
				srs, err := NewKZGSRS(ccs)
				checkError(err)

				pk, vk, err := plonk.Setup(ccs, srs)
				checkError(err)

				err = plonk.IsSolved(ccs, invalidWitness)
				mustError(err)

				incorrectProof, _ := plonk.Prove(ccs, pk, invalidWitness, popts...)
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
			assert.solvingSucceeded(circuit, validWitness, b, curve, &opt)
		}
	}
}

func (assert *Assert) solvingSucceeded(circuit frontend.Circuit, validWitness frontend.Circuit, b backend.ID, curve ecc.ID, opt *TestingOption) {
	checkError := func(err error) { assert.checkError(err, b, curve, validWitness) }

	// 1- compile the circuit
	ccs, err := assert.compile(circuit, curve, b)
	checkError(err)

	// must not error with big int test engine
	err = IsSolved(circuit, validWitness, curve)
	checkError(err)

	switch b {
	case backend.GROTH16:
		err := groth16.IsSolved(ccs, validWitness, opt.proverOpts...)
		checkError(err)

	case backend.PLONK:
		err := plonk.IsSolved(ccs, validWitness, opt.proverOpts...)
		checkError(err)
	default:
		panic("not implemented")
	}

}

func (assert *Assert) SolvingFailed(circuit frontend.Circuit, invalidWitness frontend.Circuit, opts ...func(opt *TestingOption) error) {
	opt := assert.options(opts...)

	for _, curve := range opt.curves {
		for _, b := range opt.backends {
			assert.solvingFailed(circuit, invalidWitness, b, curve, &opt)
		}
	}
}

func (assert *Assert) solvingFailed(circuit frontend.Circuit, invalidWitness frontend.Circuit, b backend.ID, curve ecc.ID, opt *TestingOption) {
	checkError := func(err error) { assert.checkError(err, b, curve, invalidWitness) }
	mustError := func(err error) { assert.mustError(err, b, curve, invalidWitness) }

	// 1- compile the circuit
	ccs, err := assert.compile(circuit, curve, b)
	if err != nil {
		fmt.Println(reflect.TypeOf(circuit).String())
	}
	checkError(err)

	// must error with big int test engine
	err = IsSolved(circuit, invalidWitness, curve)
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

// Fuzz fuzzes the given circuit by instantiating "randomized" witnesses and cross checking
// execution result between constraint system solver and big.Int test execution engine
//
// note: this is experimental and will be more tightly integrated with go1.18 built-in fuzzing
func (assert *Assert) Fuzz(circuit frontend.Circuit, fuzzCount int, opts ...func(opt *TestingOption) error) {
	opt := assert.options(opts...)

	// first we clone the circuit
	// then we parse the frontend.Variable and set them to a random value  or from our interesting pool
	// (% of allocations to be tuned)
	w := utils.ShallowClone(circuit)

	fillers := []filler{randomFiller, binaryFiller, seedFiller}

	for _, curve := range opt.curves {
		for _, b := range opt.backends {

			// this puts the compiled circuit in the cache
			// we do this here in case our fuzzWitness method mutates some references in the circuit
			// (like []frontend.Variable) before cleaning up
			_, err := assert.compile(circuit, curve, b)
			assert.NoError(err)
			valid := 0
			// "fuzz" with zeros
			valid += assert.fuzzer(zeroFiller, circuit, w, b, curve, &opt)

			for i := 0; i < fuzzCount; i++ {
				for _, f := range fillers {
					valid += assert.fuzzer(f, circuit, w, b, curve, &opt)
				}
			}
			utils.ResetWitness(w)

			// ensure we're clean for next users.
			// if we reached that point; compiled work so the circuit was clean and this does nothing
			// except ensuring the witness cloning / fuzzing didn't mutate circuit
			utils.ResetWitness(circuit)

			// fmt.Println(reflect.TypeOf(circuit).String(), valid)
		}
	}
}

func (assert *Assert) fuzzer(fuzzer filler, circuit, w frontend.Circuit, b backend.ID, curve ecc.ID, opt *TestingOption) int {
	// fuzz a witness
	fuzzer(w, curve)

	err := IsSolved(circuit, w, curve)

	if err == nil {
		// valid witness
		assert.solvingSucceeded(circuit, w, b, curve, opt)
		return 1
	}

	// invalid witness
	assert.solvingFailed(circuit, w, b, curve, opt)
	return 0
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

	// add the compiled circuit to the cache
	assert.compiled[key] = ccs

	// fmt.Println(key, ccs.GetNbConstraints())

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
		opt.witnessSerialization = false
	}
	return opt
}

// ensure the error is set, else fails the test
func (assert *Assert) mustError(err error, backendID backend.ID, curve ecc.ID, w frontend.Circuit) {
	if err != nil {
		return
	}
	var json string
	json, err = witness.ToJSON(w, curve)
	if err != nil {
		json = err.Error()
	}
	e := fmt.Errorf("did not error (but should have) %s(%s)\nwitness:%s", backendID.String(), curve.String(), json)

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
