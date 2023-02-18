package gadgets_test

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/gadgets"
	"github.com/consensys/gnark/test"
)

type muxCircuit struct {
	SEL                frontend.Variable
	I0, I1, I2, I3, I4 frontend.Variable
	OUT                frontend.Variable
}

func (c *muxCircuit) Define(api frontend.API) error {

	out := gadgets.Mux(api, c.SEL, c.I0, c.I1, c.I2, c.I3, c.I4)

	api.AssertIsEqual(out, c.OUT)

	return nil
}

// The output of this circuit is ignored and the only way its proof can fail is by providing invalid inputs.
type ignoredOutputMuxCircuit struct {
	SEL        frontend.Variable
	I0, I1, I2 frontend.Variable
}

func (c *ignoredOutputMuxCircuit) Define(api frontend.API) error {
	// We ignore the output
	_ = gadgets.Mux(api, c.SEL, c.I0, c.I1, c.I2)

	return nil
}

func TestMux(t *testing.T) {
	assert := test.NewAssert(t)

	assert.ProverSucceeded(&muxCircuit{}, &muxCircuit{SEL: 2, I0: 10, I1: 11, I2: 12, I3: 13, I4: 14, OUT: 12})

	assert.ProverSucceeded(&muxCircuit{}, &muxCircuit{SEL: 0, I0: 10, I1: 11, I2: 12, I3: 13, I4: 14, OUT: 10})

	assert.ProverSucceeded(&muxCircuit{}, &muxCircuit{SEL: 4, I0: 20, I1: 21, I2: 22, I3: 23, I4: 24, OUT: 24})

	// Failures
	assert.ProverFailed(&muxCircuit{}, &muxCircuit{SEL: 5, I0: 20, I1: 21, I2: 22, I3: 23, I4: 24, OUT: 24})

	assert.ProverFailed(&muxCircuit{}, &muxCircuit{SEL: 0, I0: 20, I1: 21, I2: 22, I3: 23, I4: 24, OUT: 21})

	// Ignoring the circuit's output:
	assert.ProverSucceeded(&ignoredOutputMuxCircuit{}, &ignoredOutputMuxCircuit{SEL: 0, I0: 0, I1: 1, I2: 2})

	assert.ProverSucceeded(&ignoredOutputMuxCircuit{}, &ignoredOutputMuxCircuit{SEL: 2, I0: 0, I1: 1, I2: 2})

	// Failures
	assert.ProverFailed(&ignoredOutputMuxCircuit{}, &ignoredOutputMuxCircuit{SEL: 3, I0: 0, I1: 1, I2: 2})

	assert.ProverFailed(&ignoredOutputMuxCircuit{}, &ignoredOutputMuxCircuit{SEL: -1, I0: 0, I1: 1, I2: 2})
}

// Lookup table tests:
type lookupCircuit struct {
	SEL            frontend.Variable
	K0, K1, K2, K3 frontend.Variable
	V0, V1, V2, V3 frontend.Variable
	OUT            frontend.Variable
}

func (c *lookupCircuit) Define(api frontend.API) error {

	out := gadgets.Lookup(api, c.SEL,
		[]frontend.Variable{c.K0, c.K1, c.K2, c.K3},
		[]frontend.Variable{c.V0, c.V1, c.V2, c.V3})

	api.AssertIsEqual(out, c.OUT)

	return nil
}

type ignoredOutputLookupCircuit struct {
	SEL    frontend.Variable
	K0, K1 frontend.Variable
	V0, V1 frontend.Variable
}

func (c *ignoredOutputLookupCircuit) Define(api frontend.API) error {

	_ = gadgets.Lookup(api, c.SEL,
		[]frontend.Variable{c.K0, c.K1},
		[]frontend.Variable{c.V0, c.V1})

	return nil
}

func TestLookup(t *testing.T) {
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&lookupCircuit{},
		&lookupCircuit{
			SEL: 100,
			K0:  100, K1: 111, K2: 222, K3: 333,
			V0: 0, V1: 1, V2: 2, V3: 3,
			OUT: 0,
		})

	assert.ProverSucceeded(&lookupCircuit{},
		&lookupCircuit{
			SEL: 222,
			K0:  100, K1: 111, K2: 222, K3: 333,
			V0: 0, V1: 1, V2: 2, V3: 3,
			OUT: 2,
		})

	assert.ProverSucceeded(&lookupCircuit{},
		&lookupCircuit{
			SEL: 333,
			K0:  100, K1: 111, K2: 222, K3: 333,
			V0: 0, V1: 1, V2: 2, V3: 3,
			OUT: 3,
		})

	// Duplicated key, success:
	assert.ProverSucceeded(&lookupCircuit{},
		&lookupCircuit{
			SEL: 333,
			K0:  222, K1: 222, K2: 222, K3: 333,
			V0: 0, V1: 1, V2: 2, V3: 3,
			OUT: 3,
		})

	// Duplicated key, UNDEFINED behavior: (with our hint implementation it fails)
	assert.ProverFailed(&lookupCircuit{},
		&lookupCircuit{
			SEL: 333,
			K0:  100, K1: 111, K2: 333, K3: 333,
			V0: 0, V1: 1, V2: 2, V3: 3,
			OUT: 3,
		})

	assert.ProverFailed(&lookupCircuit{},
		&lookupCircuit{
			SEL: 77,
			K0:  100, K1: 111, K2: 222, K3: 333,
			V0: 0, V1: 1, V2: 2, V3: 3,
			OUT: 3,
		})

	assert.ProverFailed(&lookupCircuit{},
		&lookupCircuit{
			SEL: 111,
			K0:  100, K1: 111, K2: 222, K3: 333,
			V0: 0, V1: 1, V2: 2, V3: 3,
			OUT: 2,
		})

	// Ignoring the circuit's output:
	assert.ProverSucceeded(&ignoredOutputLookupCircuit{},
		&ignoredOutputLookupCircuit{SEL: 5,
			K0: 5, K1: 7,
			V0: 10, V1: 11,
		})

	assert.ProverFailed(&ignoredOutputLookupCircuit{},
		&ignoredOutputLookupCircuit{SEL: 5,
			K0: 5, K1: 5,
			V0: 10, V1: 11,
		})

	assert.ProverFailed(&ignoredOutputLookupCircuit{},
		&ignoredOutputLookupCircuit{SEL: 6,
			K0: 5, K1: 7,
			V0: 10, V1: 11,
		})

}

func Example() {
	// default options generate gnark.pprof in current dir
	// use pprof as usual (go tool pprof -http=:8080 gnark.pprof) to read the profile file
	// overlapping profiles are allowed (define profiles inside Define or subfunction to profile
	// part of the circuit only)
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &muxCircuit{})
	p.Stop()

	fmt.Println("Number of constraints:", p.NbConstraints())
	fmt.Println(p.Top())

	p = profile.Start()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &lookupCircuit{})
	p.Stop()

	fmt.Println("Number of constraints:", p.NbConstraints())
	fmt.Println(p.Top())
	// Output:
	// Number of constraints: 17
	// Showing nodes accounting for 17, 100% of 17 total
	//       flat  flat%   sum%        cum   cum%
	//          7 41.18% 41.18%          7 41.18%  r1cs.(*builder).AssertIsEqual frontend/cs/r1cs/api_assertions.go:37
	//          5 29.41% 70.59%         10 58.82%  gadgets.generateSelector std/gadgets/multiplexer.go:58
	//          5 29.41%   100%          5 29.41%  gadgets.generateSelector std/gadgets/multiplexer.go:65
	//          0     0%   100%         16 94.12%  gadgets.Mux std/gadgets/multiplexer.go:36
	//          0     0%   100%          1  5.88%  gadgets.generateSelector std/gadgets/multiplexer.go:69
	//          0     0%   100%         16 94.12%  gadgets_test.(*muxCircuit).Define std/gadgets/multiplexer_test.go:23
	//          0     0%   100%          1  5.88%  gadgets_test.(*muxCircuit).Define std/gadgets/multiplexer_test.go:25
	//
	// Number of constraints: 14
	// Showing nodes accounting for 14, 100% of 14 total
	//       flat  flat%   sum%        cum   cum%
	//          6 42.86% 42.86%          6 42.86%  r1cs.(*builder).AssertIsEqual frontend/cs/r1cs/api_assertions.go:37
	//          4 28.57% 71.43%          8 57.14%  gadgets.generateSelector std/gadgets/multiplexer.go:61
	//          4 28.57%   100%          4 28.57%  gadgets.generateSelector std/gadgets/multiplexer.go:65
	//          0     0%   100%         13 92.86%  gadgets.Lookup std/gadgets/multiplexer.go:28
	//          0     0%   100%          1  7.14%  gadgets.generateSelector std/gadgets/multiplexer.go:69
	//          0     0%   100%         13 92.86%  gadgets_test.(*lookupCircuit).Define std/gadgets/multiplexer_test.go:78
	//          0     0%   100%          1  7.14%  gadgets_test.(*lookupCircuit).Define std/gadgets/multiplexer_test.go:82
}
