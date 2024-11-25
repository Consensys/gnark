package smallfields_test

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/kvstore"
	"github.com/consensys/gnark/internal/smallfields/tinyfield"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/sha3"

	babybearcs "github.com/consensys/gnark/constraint/babybear"
	bls12377cs "github.com/consensys/gnark/constraint/bls12-377"
	"github.com/consensys/gnark/constraint/solver"
)

type NativeCircuit struct {
	A frontend.Variable `gnark:",public"`
	B frontend.Variable `gnark:",secret"`
}

func (circuit *NativeCircuit) Define(api frontend.API) error {
	res := api.Mul(circuit.A, circuit.A)
	api.AssertIsEqual(res, circuit.B)
	return nil
}

var testCases = []struct {
	name            string
	modulus         *big.Int
	supportsCompile bool
}{
	{"tinyfield", tinyfield.Modulus(), true},
	{"babybear", babybear.Modulus(), true},
	{"koalabear", koalabear.Modulus(), true},
}

func TestNativeCircuitTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	for _, tc := range testCases {
		assert.Run(func(assert *test.Assert) {
			err := test.IsSolved(&NativeCircuit{}, &NativeCircuit{A: 2, B: 4}, tc.modulus)
			assert.NoError(err)
		}, tc.name)
	}
}

func TestNativeCircuitCompileAndSolve(t *testing.T) {
	assert := test.NewAssert(t)
	for _, tc := range testCases {
		if !tc.supportsCompile {
			continue
		}
		assert.Run(func(assert *test.Assert) {
			ccs, err := frontend.CompileU32(tc.modulus, r1cs.NewBuilder, &NativeCircuit{})
			assert.NoError(err)
			assignment := &NativeCircuit{A: 2, B: 4}
			wit, err := frontend.NewWitness(assignment, tc.modulus)
			assert.NoError(err)
			solution, err := ccs.Solve(wit)
			assert.NoError(err)
			_ = solution

		}, fmt.Sprintf("ccs=r1cs/field=%s", tc.name))
		assert.Run(func(assert *test.Assert) {
			ccs, err := frontend.CompileU32(tc.modulus, scs.NewBuilder, &NativeCircuit{})
			assert.NoError(err)
			assignment := &NativeCircuit{A: 2, B: 4}
			wit, err := frontend.NewWitness(assignment, tc.modulus)
			assert.NoError(err)
			solution, err := ccs.Solve(wit)
			assert.NoError(err)
			_ = solution
		}, fmt.Sprintf("ccs=scs/field=%s", tc.name))
	}
}

type EmulatedCircuit[T emulated.FieldParams] struct {
	A emulated.Element[T] `gnark:",public"`
	B emulated.Element[T] `gnark:",secret"`
}

func (c *EmulatedCircuit[T]) Define(api frontend.API) error {
	f, err := emulated.NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Mul(&c.A, &c.A)
	f.AssertIsEqual(res, &c.B)
	return nil
}

func TestEmulatedCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	a, err := rand.Int(rand.Reader, emparams.BN254Fp{}.Modulus())
	assert.NoError(err)
	b := new(big.Int).Mul(a, a)
	b.Mod(b, emparams.BN254Fp{}.Modulus())

	err = test.IsSolved(&EmulatedCircuit[emparams.BN254Fp]{}, &EmulatedCircuit[emparams.BN254Fp]{A: emulated.ValueOf[emparams.BN254Fp](a), B: emulated.ValueOf[emparams.BN254Fp](b)}, ecc.BN254.ScalarField())
	assert.NoError(err)

	err = test.IsSolved(&EmulatedCircuit[emparams.BN254Fp]{}, &EmulatedCircuit[emparams.BN254Fp]{A: emulated.ValueOf[emparams.BN254Fp](a), B: emulated.ValueOf[emparams.BN254Fp](b)}, babybear.Modulus())
	assert.NoError(err)
}

func TestCompileEmulatedCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	f := babybear.Modulus()

	assignment := &EmulatedCircuit[emparams.BN254Fp]{A: emulated.ValueOf[emparams.BN254Fp](2), B: emulated.ValueOf[emparams.BN254Fp](4)}

	ccs, err := frontend.CompileU32(f, newWrappedBuilder(scs.NewBuilder), &EmulatedCircuit[emparams.BN254Fp]{})
	assert.NoError(err)

	w, err := frontend.NewWitness(assignment, f)
	assert.NoError(err)

	res, err := ccs.Solve(w)
	assert.NoError(err)

	tres, ok := res.(*babybearcs.SparseR1CSSolution)
	assert.True(ok)
	_ = tres

	ccs2, err := frontend.CompileU32(f, newWrappedBuilder(r1cs.NewBuilder), &EmulatedCircuit[emparams.BN254Fp]{})
	assert.NoError(err)

	res2, err := ccs2.Solve(w)
	assert.NoError(err)

	tres2, ok := res2.(*babybearcs.R1CSSolution)
	assert.True(ok)

	_ = tres2
}

type PairCircuit struct {
	InG1 sw_bn254.G1Affine
	InG2 sw_bn254.G2Affine
	Res  sw_bn254.GTEl
}

func (c *PairCircuit) Define(api frontend.API) error {
	pairing, err := sw_bn254.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	pairing.AssertIsOnG1(&c.InG1)
	pairing.AssertIsOnG2(&c.InG2)
	res, err := pairing.Pair([]*sw_bn254.G1Affine{&c.InG1}, []*sw_bn254.G2Affine{&c.InG2})
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	pairing.AssertIsEqual(res, &c.Res)
	return nil
}

func TestPairTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	p, q := randomG1G2Affines()
	res, err := bn254.Pair([]bn254.G1Affine{p}, []bn254.G2Affine{q})
	assert.NoError(err)
	witness := PairCircuit{
		InG1: sw_bn254.NewG1Affine(p),
		InG2: sw_bn254.NewG2Affine(q),
		Res:  sw_bn254.NewGTEl(res),
	}
	err = test.IsSolved(&PairCircuit{}, &witness, babybear.Modulus())
	assert.NoError(err)

	ccs, err := frontend.CompileU32(babybear.Modulus(), newWrappedBuilder(scs.NewBuilder), &PairCircuit{})
	assert.NoError(err)

	w, err := frontend.NewWitness(&witness, babybear.Modulus())
	assert.NoError(err)

	sol, err := ccs.Solve(w)
	assert.NoError(err)

	tres, ok := sol.(*babybearcs.SparseR1CSSolution)
	assert.True(ok)
	_ = tres

	ccs2, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &PairCircuit{})
	assert.NoError(err)
	// we define it again as the field is different
	witness = PairCircuit{
		InG1: sw_bn254.NewG1Affine(p),
		InG2: sw_bn254.NewG2Affine(q),
		Res:  sw_bn254.NewGTEl(res),
	}
	w2, err := frontend.NewWitness(&witness, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
	sol2, err := ccs2.Solve(w2)
	assert.NoError(err)
	tres2, ok := sol2.(*bls12377cs.SparseR1CSSolution)
	assert.True(ok)
	_ = tres2
}

func randomG1G2Affines() (bn254.G1Affine, bn254.G2Affine) {
	_, _, G1AffGen, G2AffGen := bn254.Generators()
	mod := bn254.ID.ScalarField()
	s1, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	s2, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	var p bn254.G1Affine
	p.ScalarMultiplication(&G1AffGen, s1)
	var q bn254.G2Affine
	q.ScalarMultiplication(&G2AffGen, s2)
	return p, q
}

type wrappedBuilder struct {
	requiredBuilderInterface
}

type requiredBuilderInterface interface {
	frontend.Builder[constraint.U32]
	kvstore.Store
}

func newWrappedBuilder(newBuilder frontend.NewBuilderU32) frontend.NewBuilderU32 {
	return func(field *big.Int, config frontend.CompileConfig) (frontend.Builder[constraint.U32], error) {
		b, err := newBuilder(field, config)
		if err != nil {
			return nil, err
		}
		bb, ok := b.(requiredBuilderInterface)
		if !ok {
			return nil, fmt.Errorf("builder does not implement required interface")
		}
		return &wrappedBuilder{bb}, nil
	}
}

func (w *wrappedBuilder) WideCommit(width int, toCommit ...frontend.Variable) (commitment []frontend.Variable, err error) {
	res, err := w.NewHint(wideCommitHint, width, toCommit...)
	return res, err
}

func (w *wrappedBuilder) Compiler() frontend.Compiler {
	return w
}

func wideCommitHint(m *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	nb := (m.BitLen() + 7) / 8
	buf := make([]byte, nb)
	hasher := sha3.NewCShake128(nil, []byte("gnark test engine"))
	for _, in := range inputs {
		bs := in.FillBytes(buf)
		hasher.Write(bs)
	}
	for i := range len(outputs) {
		hasher.Read(buf)
		outputs[i].SetBytes(buf)
		outputs[i].Mod(outputs[i], m)
	}
	return nil
}

func init() {
	solver.RegisterHint(wideCommitHint)
}
