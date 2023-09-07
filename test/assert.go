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
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/frontend/schema"
	gnarkio "github.com/consensys/gnark/io"
	"github.com/stretchr/testify/require"
)

var (
	ErrCompilationNotDeterministic = errors.New("compilation is not deterministic")
	ErrInvalidWitnessSolvedCS      = errors.New("invalid witness solved the constraint system")
	ErrInvalidWitnessVerified      = errors.New("invalid witness resulted in a valid proof")
)

// Assert is a helper to test circuits
type Assert struct {
	t *testing.T
	*require.Assertions
}

// NewAssert returns an Assert helper embedding a testify/require object for convenience
//
// The Assert object caches the compiled circuit:
//
// the first call to assert.ProverSucceeded/Failed will compile the circuit for n curves, m backends
// and subsequent calls will re-use the result of the compilation, if available.
func NewAssert(t *testing.T) *Assert {
	return &Assert{t: t, Assertions: require.New(t)}
}

// Run runs the test function fn as a subtest. The subtest is parametrized by
// the description strings descs.
func (a *Assert) Run(fn func(assert *Assert), descs ...string) {
	desc := strings.Join(descs, "/")
	a.t.Run(desc, func(t *testing.T) {
		assert := &Assert{t, require.New(t)}
		fn(assert)
	})
}

// Log logs using the test instance logger.
func (assert *Assert) Log(v ...interface{}) {
	assert.t.Log(v...)
}

// ProverSucceeded fails the test if any of the following step errored:
//
// 1. compiles the circuit (or fetch it from the cache)
// 2. using the test execution engine, executes the circuit with provided witness
// 3. run Setup / Prove / Verify with the backend
// 4. if set, (de)serializes the witness and call ReadAndProve and ReadAndVerify on the backend
//
// By default, this tests on all curves and proving schemes supported by gnark. See available TestingOption.
//
// Deprecated: use CheckCircuit instead
func (assert *Assert) ProverSucceeded(circuit frontend.Circuit, validAssignment frontend.Circuit, opts ...TestingOption) {
	// copy the options
	newOpts := make([]TestingOption, len(opts), len(opts)+2)
	copy(newOpts, opts)
	newOpts = append(newOpts, WithValidAssignment(validAssignment))

	assert.CheckCircuit(circuit, newOpts...)
}

// ProverSucceeded fails the test if any of the following step errored:
//
// 1. compiles the circuit (or fetch it from the cache)
// 2. using the test execution engine, executes the circuit with provided witness (must fail)
// 3. run Setup / Prove / Verify with the backend (must fail)
//
// By default, this tests on all curves and proving schemes supported by gnark. See available TestingOption.
// Deprecated: use CheckCircuit instead
func (assert *Assert) ProverFailed(circuit frontend.Circuit, invalidAssignment frontend.Circuit, opts ...TestingOption) {
	// copy the options
	newOpts := make([]TestingOption, len(opts), len(opts)+2)
	copy(newOpts, opts)
	newOpts = append(newOpts, WithInvalidAssignment(invalidAssignment))

	assert.CheckCircuit(circuit, newOpts...)
}

// Deprecated: use CheckCircuit instead
func (assert *Assert) SolvingSucceeded(circuit frontend.Circuit, validWitness frontend.Circuit, opts ...TestingOption) {

	// copy the options
	newOpts := make([]TestingOption, len(opts), len(opts)+1)
	copy(newOpts, opts)
	newOpts = append(newOpts, WithValidAssignment(validWitness))

	assert.CheckCircuit(circuit, newOpts...)
}

// Deprecated: use CheckCircuit instead
func (assert *Assert) SolvingFailed(circuit frontend.Circuit, invalidWitness frontend.Circuit, opts ...TestingOption) {
	// copy the options
	newOpts := make([]TestingOption, len(opts), len(opts)+1)
	copy(newOpts, opts)
	newOpts = append(newOpts, WithInvalidAssignment(invalidWitness))

	assert.CheckCircuit(circuit, newOpts...)
}

func lazySchema(circuit frontend.Circuit) func() *schema.Schema {
	return func() *schema.Schema {
		// we only parse the schema if we need to display the witness in json.
		s, err := schema.New(circuit, tVariable)
		if err != nil {
			panic("couldn't parse schema from circuit: " + err.Error())
		}
		return s
	}
}

// Fuzz fuzzes the given circuit by instantiating "randomized" witnesses and cross checking
// execution result between constraint system solver and big.Int test execution engine
//
// note: this is experimental and will be more tightly integrated with go1.18 built-in fuzzing
func (assert *Assert) Fuzz(circuit frontend.Circuit, fuzzCount int, opts ...TestingOption) {
	opt := assert.options(opts...)

	// first we clone the circuit
	// then we parse the frontend.Variable and set them to a random value  or from our interesting pool
	// (% of allocations to be tuned)
	w := shallowClone(circuit)

	fillers := []filler{randomFiller, binaryFiller, seedFiller}

	for _, curve := range opt.curves {
		for _, b := range opt.backends {
			curve := curve
			b := b
			assert.Run(func(assert *Assert) {
				// this puts the compiled circuit in the cache
				// we do this here in case our fuzzWitness method mutates some references in the circuit
				// (like []frontend.Variable) before cleaning up
				_, err := assert.compile(circuit, curve, b, opt.compileOpts)
				assert.NoError(err)
				valid := 0
				// "fuzz" with zeros
				valid += assert.fuzzer(zeroFiller, circuit, w, b, curve, &opt)

				for i := 0; i < fuzzCount; i++ {
					for _, f := range fillers {
						valid += assert.fuzzer(f, circuit, w, b, curve, &opt)
					}
				}

			}, curve.String(), b.String())

		}
	}
}

func (assert *Assert) fuzzer(fuzzer filler, circuit, w frontend.Circuit, b backend.ID, curve ecc.ID, opt *testingConfig) int {
	// fuzz a witness
	fuzzer(w, curve)

	errVars := IsSolved(circuit, w, curve.ScalarField())
	errConsts := IsSolved(circuit, w, curve.ScalarField(), SetAllVariablesAsConstants())

	if (errVars == nil) != (errConsts == nil) {
		w, err := frontend.NewWitness(w, curve.ScalarField())
		if err != nil {
			panic(err)
		}
		s, err := frontend.NewSchema(circuit)
		if err != nil {
			panic(err)
		}
		bb, err := w.ToJSON(s)
		if err != nil {
			panic(err)
		}

		assert.Log("errVars", errVars)
		assert.Log("errConsts", errConsts)
		assert.Log("fuzzer witness", string(bb))
		assert.FailNow("solving circuit with values as constants vs non-constants mismatched result")
	}

	if errVars == nil && errConsts == nil {
		// valid witness
		assert.solvingSucceeded(circuit, w, b, curve, opt)
		return 1
	}

	// invalid witness
	assert.solvingFailed(circuit, w, b, curve, opt)
	return 0
}

func (assert *Assert) solvingSucceeded(circuit frontend.Circuit, validAssignment frontend.Circuit, b backend.ID, curve ecc.ID, opt *testingConfig) {
	// parse assignment
	w := assert.parseAssignment(circuit, validAssignment, curve, opt.checkSerialization)

	checkError := func(err error) { assert.noError(err, &w) }

	// 1- compile the circuit
	ccs, err := assert.compile(circuit, curve, b, opt.compileOpts)
	checkError(err)

	// must not error with big int test engine
	err = IsSolved(circuit, validAssignment, curve.ScalarField())
	checkError(err)

	err = ccs.IsSolved(w.full, opt.solverOpts...)
	checkError(err)

}

func (assert *Assert) solvingFailed(circuit frontend.Circuit, invalidAssignment frontend.Circuit, b backend.ID, curve ecc.ID, opt *testingConfig) {
	// parse assignment
	w := assert.parseAssignment(circuit, invalidAssignment, curve, opt.checkSerialization)

	checkError := func(err error) { assert.noError(err, &w) }
	mustError := func(err error) { assert.error(err, &w) }

	// 1- compile the circuit
	ccs, err := assert.compile(circuit, curve, b, opt.compileOpts)
	checkError(err)

	// must error with big int test engine
	err = IsSolved(circuit, invalidAssignment, curve.ScalarField())
	mustError(err)

	err = ccs.IsSolved(w.full, opt.solverOpts...)
	mustError(err)

}

// compile the given circuit for given curve and backend, if not already present in cache
func (assert *Assert) compile(circuit frontend.Circuit, curveID ecc.ID, backendID backend.ID, compileOpts []frontend.CompileOption) (constraint.ConstraintSystem, error) {
	var newBuilder frontend.NewBuilder

	switch backendID {
	case backend.GROTH16:
		newBuilder = r1cs.NewBuilder
	case backend.PLONK:
		newBuilder = scs.NewBuilder
	case backend.PLONKFRI:
		newBuilder = scs.NewBuilder
	default:
		panic("not implemented")
	}

	// else compile it and ensure it is deterministic
	ccs, err := frontend.Compile(curveID.ScalarField(), newBuilder, circuit, compileOpts...)
	if err != nil {
		return nil, err
	}

	_ccs, err := frontend.Compile(curveID.ScalarField(), newBuilder, circuit, compileOpts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCompilationNotDeterministic, err)
	}

	if !reflect.DeepEqual(ccs, _ccs) {
		return nil, ErrCompilationNotDeterministic
	}

	return ccs, nil
}

// error ensure the error is set, else fails the test
// add a witness to the error message if provided
func (assert *Assert) error(err error, w *_witness) {
	if err != nil {
		return
	}
	json := "<nil>"
	if w != nil {
		bjson, err := w.full.ToJSON(lazySchema(w.assignment)())
		if err != nil {
			json = err.Error()
		} else {
			json = string(bjson)
		}
	}

	e := fmt.Errorf("did not error (but should have)\nwitness:%s", json)
	assert.FailNow(e.Error())
}

// ensure the error is nil, else fails the test
// add a witness to the error message if provided
func (assert *Assert) noError(err error, w *_witness) {
	if err == nil {
		return
	}

	e := err

	if w != nil {
		var json string
		bjson, err := w.full.ToJSON(lazySchema(w.assignment)())
		if err != nil {
			json = err.Error()
		} else {
			json = string(bjson)
		}
		e = fmt.Errorf("%w\nwitness:%s", e, json)
	}

	assert.FailNow(e.Error())
}

func (assert *Assert) marshalWitness(w witness.Witness, curveID ecc.ID, publicOnly bool) {
	// serialize the vector to binary
	var err error
	if publicOnly {
		w, err = w.Public()
		assert.NoError(err)
	}
	data, err := w.MarshalBinary()
	assert.NoError(err)

	// re-read
	witness, err := witness.New(curveID.ScalarField())
	assert.NoError(err)
	err = witness.UnmarshalBinary(data)
	assert.NoError(err)

	witnessMatch := reflect.DeepEqual(w, witness)

	assert.True(witnessMatch, "round trip marshaling failed")
}

func (assert *Assert) marshalWitnessJSON(w witness.Witness, s *schema.Schema, curveID ecc.ID, publicOnly bool) {
	var err error
	if publicOnly {
		w, err = w.Public()
		assert.NoError(err)
	}

	// serialize the vector to binary
	data, err := w.ToJSON(s)
	assert.NoError(err)

	// re-read
	witness, err := witness.New(curveID.ScalarField())
	assert.NoError(err)
	err = witness.FromJSON(s, data)
	assert.NoError(err)

	witnessMatch := reflect.DeepEqual(w, witness)
	assert.True(witnessMatch, "round trip marshaling failed")
}

func (assert *Assert) roundTripCheck(from any, builder func() any, descs ...string) {
	if from == nil {
		assert.Log("skipping serialization round trip check, from is nil")
	}
	assert.Run(func(assert *Assert) {
		assert.t.Parallel()
		var buf bytes.Buffer

		check := func(written int64) {
			// if builder implements io.ReaderFrom
			if r, ok := builder().(io.ReaderFrom); ok {
				read, err := r.ReadFrom(bytes.NewReader(buf.Bytes()))
				assert.NoError(err)
				assert.True(reflect.DeepEqual(from, r), "reconstructed object don't match original (ReadFrom)")
				assert.Log("reconstruction with ReadFrom OK")
				assert.Equal(written, read, "bytes written / read don't match")
			}

			// if builder implements gnarkio.UnsafeReaderFrom
			if r, ok := builder().(gnarkio.UnsafeReaderFrom); ok {
				read, err := r.UnsafeReadFrom(bytes.NewReader(buf.Bytes()))
				assert.NoError(err)
				assert.True(reflect.DeepEqual(from, r), "reconstructed object don't match original (UnsafeReadFrom)")
				assert.Log("reconstruction with UnsafeReadFrom OK")
				assert.Equal(written, read, "bytes written / read don't match")
			}
		}

		// if from implements io.WriterTo
		if w, ok := from.(io.WriterTo); ok {
			written, err := w.WriteTo(&buf)
			assert.NoError(err)

			check(written)
		}

		buf.Reset()

		// if from implements gnarkio.WriterRawTo
		if w, ok := from.(gnarkio.WriterRawTo); ok {
			written, err := w.WriteRawTo(&buf)
			assert.NoError(err)

			check(written)
		}
	}, descs...)
}
