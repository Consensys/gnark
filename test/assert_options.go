package test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

// TestingOption defines option for altering the behavior of Assert methods.
// See the descriptions of functions returning instances of this type for
// particular options.
type TestingOption func(*testingConfig) error

type testingConfig struct {
	Profile
	solverOpts  []solver.Option
	proverOpts  []backend.ProverOption
	compileOpts []frontend.CompileOption

	validAssignments   []frontend.Circuit
	invalidAssignments []frontend.Circuit
}

// default options
func (assert *Assert) options(opts ...TestingOption) testingConfig {
	var opt testingConfig

	// apply user provided options.
	for _, option := range opts {
		err := option(&opt)
		assert.NoError(err, "parsing TestingOption")
	}

	// default options
	if opt.Backends == nil {
		// TODO @gbotrel note that we don't test PLONKFRI by default
		opt.Backends = []backend.ID{backend.GROTH16, backend.PLONK}
	}

	if len(opt.Curves) == 0 {
		if testing.Short() {
			opt.Curves = []ecc.ID{ecc.BN254}
		} else {
			opt.Curves = []ecc.ID{ecc.BN254, ecc.BLS12_381}
		}
	}

	return opt
}

// WithProfile is a testing option which simplify checking circuits
// with some presets. See Profile for more details.
func WithProfile(profile Profile) TestingOption {
	return func(opt *testingConfig) error {
		opt.Profile = profile
		return nil
	}
}

// WithDefaultProfile ...
// TODO @gbotrel comment.
func WithDefaultProfile() TestingOption {
	return func(opt *testingConfig) error {
		if fullProfile {
			opt.Profile = FullProfile
			return nil
		}
		if lightProfile {
			opt.Profile = ConstraintOnlyProfile
			return nil
		}
		if testing.Short() {
			opt.Profile = TestEngineOnly
		} else {
			opt.Profile = ConstraintOnlyProfile
		}
		// TODO @gbotrel could do some checks here to verify we don't override
		// previously set options.
		return nil
	}
}

// WithFullProver is a testing option which forces the use of the full prover
// (as opposed to running the solver on the constraint system without the proof system)
func WithFullProver() TestingOption {
	return func(opt *testingConfig) error {
		opt.FullProver = true
		return nil
	}
}

// WithValidAssignment is a testing option which adds a valid assignment
func WithValidAssignment(validAssignment frontend.Circuit) TestingOption {
	return func(opt *testingConfig) error {
		opt.validAssignments = append(opt.validAssignments, validAssignment)
		return nil
	}
}

// WithInvalidAssignment is a testing option which adds an invalid assignment
func WithInvalidAssignment(invalidAssignment frontend.Circuit) TestingOption {
	return func(opt *testingConfig) error {
		opt.invalidAssignments = append(opt.invalidAssignments, invalidAssignment)
		return nil
	}
}

// WithBackends is testing option which restricts the backends the assertions are
// run. When not given, runs on all implemented backends.
func WithBackends(b backend.ID, backends ...backend.ID) TestingOption {
	return func(opt *testingConfig) error {
		opt.Backends = []backend.ID{b}
		opt.Backends = append(opt.Backends, backends...)
		return nil
	}
}

// WithCurves is a testing option which restricts the curves the assertions are
// run. When not given, runs on all implemented curves.
func WithCurves(c ecc.ID, curves ...ecc.ID) TestingOption {
	return func(opt *testingConfig) error {
		opt.Curves = []ecc.ID{c}
		opt.Curves = append(opt.Curves, curves...)
		return nil
	}
}

// NoSerialization is a testing option which disables witness serialization tests
// in assertions.
func NoSerialization() TestingOption {
	return func(opt *testingConfig) error {
		opt.WitnessSerialization = false
		return nil
	}
}

// NoFuzzing is a testing option which disables fuzzing tests in assertions.
func NoFuzzing() TestingOption {
	return func(opt *testingConfig) error {
		opt.Fuzzing = false
		return nil
	}
}

// WithProverOpts is a testing option which uses the given proverOpts when
// calling backend.Prover, backend.ReadAndProve and backend.IsSolved methods in
// assertions.
func WithProverOpts(proverOpts ...backend.ProverOption) TestingOption {
	return func(opt *testingConfig) error {
		opt.proverOpts = proverOpts
		return nil
	}
}

// WithSolverOpts is a testing option which uses the given solverOpts when
// calling constraint system solver.
func WithSolverOpts(solverOpts ...solver.Option) TestingOption {
	return func(opt *testingConfig) error {
		opt.proverOpts = append(opt.proverOpts, backend.WithSolverOptions(solverOpts...))
		opt.solverOpts = solverOpts
		return nil
	}
}

// WithCompileOpts is a testing option which uses the given compileOpts when
// calling frontend.Compile in assertions.
func WithCompileOpts(compileOpts ...frontend.CompileOption) TestingOption {
	return func(opt *testingConfig) error {
		opt.compileOpts = compileOpts
		return nil
	}
}

// WithSolidity is a testing option which enables solidity tests in assertions.
// If the build tag "solccheck" is not set, this option is ignored.
// When the tag is set; this requires gnark-solidity-checker to be installed, which in turns
// requires solc and abigen to be reachable in the PATH.
//
// See https://github.com/ConsenSys/gnark-solidity-checker for more details.
func WithSolidity() TestingOption {
	return func(opt *testingConfig) error {
		opt.Solidity = true && solcCheck
		return nil
	}
}
