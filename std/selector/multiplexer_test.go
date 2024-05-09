package selector_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/selector"
	"github.com/consensys/gnark/test"
)

type muxCircuit struct {
	SEL                frontend.Variable
	I0, I1, I2, I3, I4 frontend.Variable
	OUT                frontend.Variable
}

func (c *muxCircuit) Define(api frontend.API) error {

	out := selector.Mux(api, c.SEL, c.I0, c.I1, c.I2, c.I3, c.I4)

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
	_ = selector.Mux(api, c.SEL, c.I0, c.I1, c.I2)

	return nil
}

type mux2to1Circuit struct {
	SEL    frontend.Variable
	I0, I1 frontend.Variable
	OUT    frontend.Variable
}

func (c *mux2to1Circuit) Define(api frontend.API) error {
	// We ignore the output
	out := selector.Mux(api, c.SEL, c.I0, c.I1)
	api.AssertIsEqual(out, c.OUT)
	return nil
}

type mux4to1Circuit struct {
	SEL frontend.Variable
	In  [4]frontend.Variable
	OUT frontend.Variable
}

func (c *mux4to1Circuit) Define(api frontend.API) error {
	out := selector.Mux(api, c.SEL, c.In[:]...)
	api.AssertIsEqual(out, c.OUT)
	return nil
}

func TestMux(t *testing.T) {
	assert := test.NewAssert(t)

	assert.CheckCircuit(&muxCircuit{},
		test.WithValidAssignment(&muxCircuit{SEL: 2, I0: 10, I1: 11, I2: 12, I3: 13, I4: 14, OUT: 12}),
		test.WithValidAssignment(&muxCircuit{SEL: 0, I0: 10, I1: 11, I2: 12, I3: 13, I4: 14, OUT: 10}),
		test.WithValidAssignment(&muxCircuit{SEL: 4, I0: 20, I1: 21, I2: 22, I3: 23, I4: 24, OUT: 24}),
		test.WithInvalidAssignment(&muxCircuit{SEL: 5, I0: 20, I1: 21, I2: 22, I3: 23, I4: 24, OUT: 24}),
		test.WithInvalidAssignment(&muxCircuit{SEL: 0, I0: 20, I1: 21, I2: 22, I3: 23, I4: 24, OUT: 21}),
	)

	assert.CheckCircuit(&ignoredOutputMuxCircuit{},
		test.WithValidAssignment(&ignoredOutputMuxCircuit{SEL: 0, I0: 0, I1: 1, I2: 2}),
		test.WithValidAssignment(&ignoredOutputMuxCircuit{SEL: 2, I0: 0, I1: 1, I2: 2}),
		test.WithInvalidAssignment(&ignoredOutputMuxCircuit{SEL: 3, I0: 0, I1: 1, I2: 2}),
		test.WithInvalidAssignment(&ignoredOutputMuxCircuit{SEL: -1, I0: 0, I1: 1, I2: 2}),
	)

	assert.CheckCircuit(&mux2to1Circuit{},
		test.WithValidAssignment(&mux2to1Circuit{SEL: 1, I0: 10, I1: 20, OUT: 20}),
		test.WithValidAssignment(&mux2to1Circuit{SEL: 0, I0: 10, I1: 20, OUT: 10}),
		test.WithInvalidAssignment(&mux2to1Circuit{SEL: 2, I0: 10, I1: 20, OUT: 20}),
	)

	assert.CheckCircuit(&mux4to1Circuit{},
		test.WithValidAssignment(&mux4to1Circuit{
			SEL: 3,
			In:  [4]frontend.Variable{11, 22, 33, 44},
			OUT: 44,
		}),
		test.WithValidAssignment(&mux4to1Circuit{
			SEL: 1,
			In:  [4]frontend.Variable{11, 22, 33, 44},
			OUT: 22,
		}),
		test.WithValidAssignment(&mux4to1Circuit{
			SEL: 0,
			In:  [4]frontend.Variable{11, 22, 33, 44},
			OUT: 11,
		}),
		test.WithInvalidAssignment(&mux4to1Circuit{
			SEL: 4,
			In:  [4]frontend.Variable{11, 22, 33, 44},
			OUT: 44,
		}),
	)

	cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &mux4to1Circuit{})
	// (4 - 1) + (2 + 1) + 1 == 7
	assert.Equal(7, cs.GetNbConstraints())
}

// Map tests:
type mapCircuit struct {
	SEL            frontend.Variable
	K0, K1, K2, K3 frontend.Variable
	V0, V1, V2, V3 frontend.Variable
	OUT            frontend.Variable
}

func (c *mapCircuit) Define(api frontend.API) error {

	out := selector.Map(api, c.SEL,
		[]frontend.Variable{c.K0, c.K1, c.K2, c.K3},
		[]frontend.Variable{c.V0, c.V1, c.V2, c.V3})

	api.AssertIsEqual(out, c.OUT)

	return nil
}

type ignoredOutputMapCircuit struct {
	SEL    frontend.Variable
	K0, K1 frontend.Variable
	V0, V1 frontend.Variable
}

func (c *ignoredOutputMapCircuit) Define(api frontend.API) error {

	_ = selector.Map(api, c.SEL,
		[]frontend.Variable{c.K0, c.K1},
		[]frontend.Variable{c.V0, c.V1})

	return nil
}

func TestMap(t *testing.T) {
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&mapCircuit{},
		&mapCircuit{
			SEL: 100,
			K0:  100, K1: 111, K2: 222, K3: 333,
			V0: 0, V1: 1, V2: 2, V3: 3,
			OUT: 0,
		})

	assert.ProverSucceeded(&mapCircuit{},
		&mapCircuit{
			SEL: 222,
			K0:  100, K1: 111, K2: 222, K3: 333,
			V0: 0, V1: 1, V2: 2, V3: 3,
			OUT: 2,
		})

	assert.ProverSucceeded(&mapCircuit{},
		&mapCircuit{
			SEL: 333,
			K0:  100, K1: 111, K2: 222, K3: 333,
			V0: 0, V1: 1, V2: 2, V3: 3,
			OUT: 3,
		})

	// Duplicated key, success:
	assert.ProverSucceeded(&mapCircuit{},
		&mapCircuit{
			SEL: 333,
			K0:  222, K1: 222, K2: 222, K3: 333,
			V0: 0, V1: 1, V2: 2, V3: 3,
			OUT: 3,
		})

	// Duplicated key, UNDEFINED behavior: (with our hint implementation it fails)
	assert.ProverFailed(&mapCircuit{},
		&mapCircuit{
			SEL: 333,
			K0:  100, K1: 111, K2: 333, K3: 333,
			V0: 0, V1: 1, V2: 2, V3: 3,
			OUT: 3,
		})

	assert.ProverFailed(&mapCircuit{},
		&mapCircuit{
			SEL: 77,
			K0:  100, K1: 111, K2: 222, K3: 333,
			V0: 0, V1: 1, V2: 2, V3: 3,
			OUT: 3,
		})

	assert.ProverFailed(&mapCircuit{},
		&mapCircuit{
			SEL: 111,
			K0:  100, K1: 111, K2: 222, K3: 333,
			V0: 0, V1: 1, V2: 2, V3: 3,
			OUT: 2,
		})

	// Ignoring the circuit's output:
	assert.ProverSucceeded(&ignoredOutputMapCircuit{},
		&ignoredOutputMapCircuit{SEL: 5,
			K0: 5, K1: 7,
			V0: 10, V1: 11,
		})

	assert.ProverFailed(&ignoredOutputMapCircuit{},
		&ignoredOutputMapCircuit{SEL: 5,
			K0: 5, K1: 5,
			V0: 10, V1: 11,
		})

	assert.ProverFailed(&ignoredOutputMapCircuit{},
		&ignoredOutputMapCircuit{SEL: 6,
			K0: 5, K1: 7,
			V0: 10, V1: 11,
		})

}
