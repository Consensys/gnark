package frontend

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/internal/backend/compiled"
)

// Compile will generate a ConstraintSystem from the given circuit
//
// 1. it will first allocate the user inputs (see type Tag for more info)
// example:
// 		type MyCircuit struct {
// 			Y frontend.Variable `gnark:"exponent,public"`
// 		}
// in that case, Compile() will allocate one public variable with id "exponent"
//
// 2. it then calls circuit.Define(curveID, R1CS) to build the internal constraint system
// from the declarative code
//
// 3. finally, it converts that to a ConstraintSystem.
// 		if zkpID == backend.GROTH16	--> R1CS
//		if zkpID == backend.PLONK 	--> SparseR1CS
//
// initialCapacity is an optional parameter that reserves memory in slices
// it should be set to the estimated number of constraints in the circuit, if known.
func Compile(curveID ecc.ID, zkpID backend.ID, circuit Circuit, opts ...func(opt *CompileOption) error) (compiled.ConstraintSystem, error) {
	// setup option
	opt := CompileOption{}
	for _, o := range opts {
		if err := o(&opt); err != nil {
			return nil, fmt.Errorf("apply option: %w", err)
		}
	}
	backendsM.RLock()
	f, ok := backends[zkpID]
	backendsM.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no frontend registered for backend '%s'", zkpID)
	}
	systemsM.RLock()
	compiler, ok := systems[f]
	systemsM.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no compiler registered for frontend '%s'", f)
	}
	ccs, err := compiler(curveID, circuit)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	return ccs, nil
}

// CompileOption enables to set optional argument to call of frontend.Compile()
type CompileOption struct {
	capacity                  int
	ignoreUnconstrainedInputs bool
}

// WithOutput is a Compile option that specifies the estimated capacity needed for internal variables and constraints
func WithCapacity(capacity int) func(opt *CompileOption) error {
	return func(opt *CompileOption) error {
		opt.capacity = capacity
		return nil
	}
}

// IgnoreUnconstrainedInputs when set, the Compile function doesn't check for unconstrained inputs
func IgnoreUnconstrainedInputs(opt *CompileOption) error {
	opt.ignoreUnconstrainedInputs = true
	return nil
}
