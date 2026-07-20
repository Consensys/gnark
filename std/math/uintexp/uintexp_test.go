package uintexp

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/smallfields/tinyfield"
	"github.com/consensys/gnark/test"
)

// supportedCurves are the big curves whose scalar field has 2-adicity >= 16.
// BLS24-315 (2-adicity 2) and BW6-633 (11) do not support the encoding.
func supportedCurves() test.TestingOption {
	return test.WithCurves(ecc.BN254, ecc.BLS12_377, ecc.BLS12_381)
}

type roundtripCircuit[W Width] struct {
	In       frontend.Variable
	Expected frontend.Variable
}

func (c *roundtripCircuit[W]) Define(api frontend.API) error {
	f, err := New[W](api)
	if err != nil {
		return err
	}
	api.AssertIsEqual(f.Value(f.ValueOf(c.In)), c.Expected)
	return nil
}

func TestRoundTrip(t *testing.T) {
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		assert.CheckCircuit(&roundtripCircuit[U8]{},
			test.WithValidAssignment(&roundtripCircuit[U8]{In: 0, Expected: 0}),
			test.WithValidAssignment(&roundtripCircuit[U8]{In: 1, Expected: 1}),
			test.WithValidAssignment(&roundtripCircuit[U8]{In: 255, Expected: 255}),
			test.WithInvalidAssignment(&roundtripCircuit[U8]{In: 256, Expected: 0}),
			test.WithInvalidAssignment(&roundtripCircuit[U8]{In: 3, Expected: 4}),
			supportedCurves(), test.WithSmallfieldCheck(),
		)
	}, "u8")
	assert.Run(func(assert *test.Assert) {
		assert.CheckCircuit(&roundtripCircuit[U16]{},
			test.WithValidAssignment(&roundtripCircuit[U16]{In: 0, Expected: 0}),
			test.WithValidAssignment(&roundtripCircuit[U16]{In: 65535, Expected: 65535}),
			test.WithInvalidAssignment(&roundtripCircuit[U16]{In: 65536, Expected: 0}),
			supportedCurves(), test.WithSmallfieldCheck(),
		)
	}, "u16")
}

type addCircuit[W Width] struct {
	In       []frontend.Variable
	Expected frontend.Variable
}

func (c *addCircuit[W]) Define(api frontend.API) error {
	f, err := New[W](api)
	if err != nil {
		return err
	}
	us := make([]Uint[W], len(c.In))
	for i := range c.In {
		us[i] = f.ValueOf(c.In[i])
	}
	api.AssertIsEqual(f.Value(f.Add(us...)), c.Expected)
	return nil
}

func TestAdd(t *testing.T) {
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		assert.CheckCircuit(&addCircuit[U8]{In: make([]frontend.Variable, 2)},
			test.WithValidAssignment(&addCircuit[U8]{In: []frontend.Variable{255, 2}, Expected: 1}),
			test.WithValidAssignment(&addCircuit[U8]{In: []frontend.Variable{100, 27}, Expected: 127}),
			test.WithInvalidAssignment(&addCircuit[U8]{In: []frontend.Variable{255, 2}, Expected: 257}),
			supportedCurves(), test.WithSmallfieldCheck(),
		)
	}, "u8-wrap")
	assert.Run(func(assert *test.Assert) {
		assert.CheckCircuit(&addCircuit[U16]{In: make([]frontend.Variable, 4)},
			test.WithValidAssignment(&addCircuit[U16]{In: []frontend.Variable{65535, 2, 3, 4}, Expected: 8}),
			test.WithValidAssignment(&addCircuit[U16]{In: []frontend.Variable{1, 2, 3, 4}, Expected: 10}),
			test.WithInvalidAssignment(&addCircuit[U16]{In: []frontend.Variable{65535, 2, 3, 4}, Expected: 65544}),
			supportedCurves(), test.WithSmallfieldCheck(),
		)
	}, "u16-four-inputs")
}

type addConstantCircuit[W Width] struct {
	In       frontend.Variable
	C        uint64
	Expected frontend.Variable
}

func (c *addConstantCircuit[W]) Define(api frontend.API) error {
	f, err := New[W](api)
	if err != nil {
		return err
	}
	api.AssertIsEqual(f.Value(f.AddConstant(f.ValueOf(c.In), c.C)), c.Expected)
	return nil
}

func TestAddConstant(t *testing.T) {
	assert := test.NewAssert(t)
	for _, tc := range []struct {
		c        uint64
		in, want int
	}{
		{c: 2, in: 255, want: 1},  // wraps
		{c: 0, in: 42, want: 42},  // identity
		{c: 300, in: 0, want: 44}, // constant reduced mod 2^8
		{c: 256, in: 7, want: 7},  // constant reduced to 0
	} {
		assert.Run(func(assert *test.Assert) {
			assert.CheckCircuit(&addConstantCircuit[U8]{C: tc.c},
				test.WithValidAssignment(&addConstantCircuit[U8]{In: tc.in, C: tc.c, Expected: tc.want}),
				supportedCurves(), test.WithSmallfieldCheck(),
			)
		}, fmt.Sprintf("u8+%d", tc.c))
	}
}

type negSubCircuit[W Width] struct {
	A, B           frontend.Variable
	ExpNeg, ExpSub frontend.Variable
}

func (c *negSubCircuit[W]) Define(api frontend.API) error {
	f, err := New[W](api)
	if err != nil {
		return err
	}
	a := f.ValueOf(c.A)
	b := f.ValueOf(c.B)
	api.AssertIsEqual(f.Value(f.Neg(a)), c.ExpNeg)
	api.AssertIsEqual(f.Value(f.Sub(a, b)), c.ExpSub)
	return nil
}

func TestNegSub(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&negSubCircuit[U8]{},
		test.WithValidAssignment(&negSubCircuit[U8]{A: 0, B: 0, ExpNeg: 0, ExpSub: 0}),
		test.WithValidAssignment(&negSubCircuit[U8]{A: 2, B: 3, ExpNeg: 254, ExpSub: 255}),
		test.WithValidAssignment(&negSubCircuit[U8]{A: 200, B: 100, ExpNeg: 56, ExpSub: 100}),
		test.WithInvalidAssignment(&negSubCircuit[U8]{A: 2, B: 3, ExpNeg: 254, ExpSub: 1}),
		supportedCurves(), test.WithSmallfieldCheck(),
	)
	assert.CheckCircuit(&negSubCircuit[U16]{},
		test.WithValidAssignment(&negSubCircuit[U16]{A: 2, B: 3, ExpNeg: 65534, ExpSub: 65535}),
		supportedCurves(), test.WithSmallfieldCheck(),
	)
}

type lshCircuit[W Width] struct {
	In       frontend.Variable
	C        int
	Expected frontend.Variable
}

func (c *lshCircuit[W]) Define(api frontend.API) error {
	f, err := New[W](api)
	if err != nil {
		return err
	}
	api.AssertIsEqual(f.Value(f.Lsh(f.ValueOf(c.In), c.C)), c.Expected)
	return nil
}

func TestLsh(t *testing.T) {
	assert := test.NewAssert(t)
	for _, tc := range []struct {
		c        int
		in, want int
	}{
		{c: 0, in: 3, want: 3},
		{c: 1, in: 3, want: 6},
		{c: 3, in: 3, want: 24},
		{c: 7, in: 3, want: 0x80}, // (3<<7) mod 256
		{c: 8, in: 3, want: 0},    // shifted out
		{c: 9, in: 255, want: 0},  // beyond the width
	} {
		assert.Run(func(assert *test.Assert) {
			assert.CheckCircuit(&lshCircuit[U8]{C: tc.c},
				test.WithValidAssignment(&lshCircuit[U8]{In: tc.in, C: tc.c, Expected: tc.want}),
				supportedCurves(), test.WithSmallfieldCheck(),
			)
		}, fmt.Sprintf("u8<<%d", tc.c))
	}
	assert.CheckCircuit(&lshCircuit[U16]{C: 15},
		test.WithValidAssignment(&lshCircuit[U16]{In: 3, C: 15, Expected: 0x8000}),
		supportedCurves(), test.WithSmallfieldCheck(),
	)
}

type selectIsZeroCircuit[W Width] struct {
	Sel, A, B frontend.Variable
	ExpSel    frontend.Variable
	AIsZero   frontend.Variable
}

func (c *selectIsZeroCircuit[W]) Define(api frontend.API) error {
	f, err := New[W](api)
	if err != nil {
		return err
	}
	a := f.ValueOf(c.A)
	b := f.ValueOf(c.B)
	api.AssertIsEqual(f.Value(f.Select(c.Sel, a, b)), c.ExpSel)
	api.AssertIsEqual(f.IsZero(a), c.AIsZero)
	return nil
}

func TestSelectIsZero(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&selectIsZeroCircuit[U8]{},
		test.WithValidAssignment(&selectIsZeroCircuit[U8]{Sel: 1, A: 5, B: 7, ExpSel: 5, AIsZero: 0}),
		test.WithValidAssignment(&selectIsZeroCircuit[U8]{Sel: 0, A: 0, B: 7, ExpSel: 7, AIsZero: 1}),
		test.WithInvalidAssignment(&selectIsZeroCircuit[U8]{Sel: 1, A: 5, B: 7, ExpSel: 7, AIsZero: 0}),
		supportedCurves(), test.WithSmallfieldCheck(),
	)
}

type assertEqCircuit[W Width] struct {
	A, B frontend.Variable
}

func (c *assertEqCircuit[W]) Define(api frontend.API) error {
	f, err := New[W](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(f.ValueOf(c.A), f.ValueOf(c.B))
	return nil
}

func TestAssertIsEqual(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&assertEqCircuit[U16]{},
		test.WithValidAssignment(&assertEqCircuit[U16]{A: 12345, B: 12345}),
		test.WithInvalidAssignment(&assertEqCircuit[U16]{A: 12345, B: 12346}),
		supportedCurves(), test.WithSmallfieldCheck(),
	)
}

// rawWitnessCircuit takes an encoded value directly as witness: the gadget
// must constrain it to be a well-formed encoding (subgroup membership).
type rawWitnessCircuit[W Width] struct {
	In       Uint[W]
	Expected frontend.Variable
}

func (c *rawWitnessCircuit[W]) Define(api frontend.API) error {
	f, err := New[W](api)
	if err != nil {
		return err
	}
	api.AssertIsEqual(f.Value(c.In), c.Expected)
	return nil
}

func TestRawWitnessSoundness(t *testing.T) {
	assert := test.NewAssert(t)
	for _, q := range []*big.Int{koalabear.Modulus(), ecc.BN254.ScalarField()} {
		q := q
		assert.Run(func(assert *test.Assert) {
			// valid: honest encoding of 5
			enc, err := Encode[U8](q, 5)
			assert.NoError(err)
			assert.NoError(test.IsSolved(&rawWitnessCircuit[U8]{}, &rawWitnessCircuit[U8]{In: enc, Expected: 5}, q))

			// invalid: an element of order 2^9 -- its square is in the
			// subgroup but it is not: must fail
			w9, err := omega(q, 9)
			assert.NoError(err)
			assert.Error(test.IsSolved(&rawWitnessCircuit[U8]{}, &rawWitnessCircuit[U8]{In: Uint[U8]{V: w9}, Expected: 5}, q))

			// invalid: zero is not in the multiplicative group
			assert.Error(test.IsSolved(&rawWitnessCircuit[U8]{}, &rawWitnessCircuit[U8]{In: Uint[U8]{V: 0}, Expected: 0}, q))

			// invalid: the plain (unencoded) integer
			assert.Error(test.IsSolved(&rawWitnessCircuit[U8]{}, &rawWitnessCircuit[U8]{In: Uint[U8]{V: 5}, Expected: 5}, q))
		}, q.String()[:8])
	}
}

// TestSolveBabyBear exercises the full compile+solve path over BabyBear with
// both builders.
func TestSolveBabyBear(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &addCircuit[U16]{In: make([]frontend.Variable, 2)}
	witness := &addCircuit[U16]{In: []frontend.Variable{65535, 3}, Expected: 2}
	assert.NoError(test.IsSolved(circuit, witness, babybear.Modulus()))

	w, err := frontend.NewWitness(witness, babybear.Modulus())
	assert.NoError(err)

	ccsR1CS, err := frontend.CompileU32(babybear.Modulus(), r1cs.NewBuilder, circuit)
	assert.NoError(err)
	assert.NoError(ccsR1CS.IsSolved(w))

	ccsSCS, err := frontend.CompileU32(babybear.Modulus(), scs.NewBuilder, circuit)
	assert.NoError(err)
	assert.NoError(ccsSCS.IsSolved(w))
}

// TestTinyFieldUnsupported checks that compilation over a field with
// insufficient 2-adicity surfaces the error from New.
func TestTinyFieldUnsupported(t *testing.T) {
	assert := test.NewAssert(t)
	_, err := frontend.CompileU32(tinyfield.Modulus(), r1cs.NewBuilder, &roundtripCircuit[U8]{})
	assert.Error(err)
}

type cachingCircuit struct {
	In frontend.Variable
}

func (c *cachingCircuit) Define(api frontend.API) error {
	f1, err := New[U8](api)
	if err != nil {
		return err
	}
	f2, err := New[U8](api)
	if err != nil {
		return err
	}
	if f1 != f2 {
		return fmt.Errorf("New[U8] is not cached")
	}
	f3, err := New[U16](api)
	if err != nil {
		return err
	}
	if f3.k != 16 || f1.k != 8 {
		return fmt.Errorf("cached instances mixed up across widths")
	}
	api.AssertIsEqual(f1.Value(f1.ValueOf(c.In)), c.In)
	return nil
}

func TestGadgetCaching(t *testing.T) {
	assert := test.NewAssert(t)
	_, err := frontend.CompileU32(koalabear.Modulus(), r1cs.NewBuilder, &cachingCircuit{})
	assert.NoError(err)
}
