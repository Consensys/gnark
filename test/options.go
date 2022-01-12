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
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
)

type TestingOption func(*testingConfig) error

// testingConfig enables calls to assert.ProverSucceeded and assert.ProverFailed to run with various features
//
// In particular: chose the curve, chose the backend and execute serialization tests on the witness
//
// Default values to all supported curves, backends and execute serialization tests = true
type testingConfig struct {
	backends             []backend.ID
	curves               []ecc.ID
	witnessSerialization bool
	proverOpts           []backend.ProverOption
	compileOpts          []frontend.CompileOption
}

// WithBackends enables calls to assert.ProverSucceeded and assert.ProverFailed to run on specific backends only
//
// (defaults to all gnark supported backends)
func WithBackends(b backend.ID, backends ...backend.ID) TestingOption {
	return func(opt *testingConfig) error {
		opt.backends = []backend.ID{b}
		opt.backends = append(opt.backends, backends...)
		return nil
	}
}

// WithCurves enables calls to assert.ProverSucceeded and assert.ProverFailed to run on specific curves only
//
// (defaults to all gnark supported curves)
func WithCurves(c ecc.ID, curves ...ecc.ID) TestingOption {
	return func(opt *testingConfig) error {
		opt.curves = []ecc.ID{c}
		opt.curves = append(opt.curves, curves...)
		return nil
	}
}

// NoSerialization enables calls to assert.ProverSucceeded and assert.ProverFailed to skip witness serialization tests
func NoSerialization() TestingOption {
	return func(opt *testingConfig) error {
		opt.witnessSerialization = false
		return nil
	}
}

// WithProverOpts enables calls to assert.ProverSucceeded and assert.ProverFailed to forward backend.Prover option
// to backend.Prove and backend.ReadAndProve calls
func WithProverOpts(proverOpts ...backend.ProverOption) TestingOption {
	return func(opt *testingConfig) error {
		opt.proverOpts = proverOpts
		return nil
	}
}

// WithCompileOpts enables calls to assert.ProverSucceeded and assert.ProverFailed to forward compiler.Compile option
// to compiler.Compile calls
func WithCompileOpts(compileOpts ...frontend.CompileOption) TestingOption {
	return func(opt *testingConfig) error {
		opt.compileOpts = compileOpts
		return nil
	}
}
