package selector

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

// having this test file in package selector so that we can have mux3
func mux3(api frontend.API, sel frontend.Variable, inputs ...frontend.Variable) frontend.Variable {
	return dotProduct(api, inputs, Decoder(api, len(inputs), sel))
}

type muxCircuit struct {
	Sel      frontend.Variable
	Input    []frontend.Variable
	Expected frontend.Variable

	Length int
}

func (c *muxCircuit) Define(api frontend.API) error {
	if len(c.Input) != c.Length {
		panic("invalid length")
	}
	s := MuxCapped(api, c.Sel, c.Input...)
	api.AssertIsEqual(s, c.Expected)
	return nil
}

func TestMux100(t *testing.T) {
	for i := 0; i < 100; i++ {
		testMux(t, 100, i)
	}
}

func testMux(t *testing.T, len int, sel int) {
	assert := test.NewAssert(t)
	circuit := &muxCircuit{
		Length: len,
		Input:  make([]frontend.Variable, len),
	}

	inputs := make([]frontend.Variable, len)
	for i := 0; i < len; i++ {
		inputs[i] = frontend.Variable(i)
	}

	assert.CheckCircuit(circuit,
		test.WithValidAssignment(&muxCircuit{
			Sel:      sel,
			Input:    inputs,
			Expected: sel,
		}),
		test.WithInvalidAssignment(&muxCircuit{
			Sel:      3000,
			Input:    inputs,
			Expected: sel,
		}),
	)
}

type largeCircuit2 struct {
	Sel      frontend.Variable
	Input    []frontend.Variable
	Expected frontend.Variable

	Length int
}

func (c *largeCircuit2) Define(api frontend.API) error {
	if len(c.Input) != c.Length {
		panic("invalid length")
	}
	s := Mux(api, c.Sel, c.Input...)
	api.AssertIsEqual(s, c.Expected)
	return nil
}

type largeCircuit3 struct {
	Sel      frontend.Variable
	Input    []frontend.Variable
	Expected frontend.Variable

	Length int
}

func (c *largeCircuit3) Define(api frontend.API) error {
	if len(c.Input) != c.Length {
		panic("invalid length")
	}
	s := mux3(api, c.Sel, c.Input...)
	api.AssertIsEqual(s, c.Expected)
	return nil
}

func TestBenchMux(t *testing.T) {
	for i := 2; i < 900; i++ {
		a, b, c := testBenchMux(t, i)
		if a > b || a > c {
			t.Logf("warning: %v, %v, %v, %v\n", i, a, b, c)
		}
		t.Logf("%v, %v, %v, %v\n", i, a, b, c)
	}
}

func TestBenchMux2(t *testing.T) {
	for i := 1; i < 20; i++ {
		a, b, c := testBenchMux(t, 1<<i)
		if a != b || a >= c {
			t.Fatal(1<<i, a, b, c)
		}
		t.Logf("%v, %v, %v, %v\n", 1<<i, a, b, c)
	}
}

func TestBenchMux3(t *testing.T) {
	a, b, c := testBenchMux(t, 0b111111111111111111111)
	t.Logf("%v, %v, %v\n", a, b, c)
}

func testBenchMux(t *testing.T, len int) (int, int, int) {
	assert := test.NewAssert(t)
	circuit := &muxCircuit{
		Length: len,
		Input:  make([]frontend.Variable, len),
	}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	assert.NoError(err)

	circuit2 := &largeCircuit2{
		Length: len,
		Input:  make([]frontend.Variable, len),
	}

	cs2, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit2)
	assert.NoError(err)

	circuit3 := &largeCircuit3{
		Length: len,
		Input:  make([]frontend.Variable, len),
	}

	cs3, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit3)
	assert.NoError(err)

	return cs.GetNbConstraints(), cs2.GetNbConstraints(), cs3.GetNbConstraints()
}
