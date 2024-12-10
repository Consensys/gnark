package smallfields

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/field/goldilocks"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/smallfields/babybear"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"

	babybearcs "github.com/consensys/gnark/constraint/babybear"
	bls12377cs "github.com/consensys/gnark/constraint/bls12-377"
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

type EmulatedCircuit[T emulated.FieldParams] struct {
	A emulated.Element[T] `gnark:",public"`
	B emulated.Element[T] `gnark:",secret"`
}

func (circuit *EmulatedCircuit[T]) Define(api frontend.API) error {
	f, err := emulated.NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Mul(&circuit.A, &circuit.A)
	f.AssertIsEqual(res, &circuit.B)
	return nil
}

func TestNativeCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	err := test.IsSolved(&NativeCircuit{}, &NativeCircuit{A: 2, B: 4}, goldilocks.Modulus())
	assert.NoError(err)
}

type smallBN struct {
	emparams.BN254Fp
}

func (smallBN) BitsPerLimb() uint {
	return 10
}

func (smallBN) NbLimbs() uint {
	return 26
}

func TestEmulatedCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	a, err := rand.Int(rand.Reader, emparams.BN254Fp{}.Modulus())
	assert.NoError(err)
	b := new(big.Int).Mul(a, a)
	b.Mod(b, emparams.BN254Fp{}.Modulus())

	err = test.IsSolved(&EmulatedCircuit[emparams.BN254Fp]{}, &EmulatedCircuit[emparams.BN254Fp]{A: emulated.ValueOf[emparams.BN254Fp](a), B: emulated.ValueOf[emparams.BN254Fp](b)}, ecc.BN254.ScalarField())
	assert.NoError(err)

	err = test.IsSolved(&EmulatedCircuit[emparams.BN254Fp]{}, &EmulatedCircuit[emparams.BN254Fp]{A: emulated.ValueOf[emparams.BN254Fp](a), B: emulated.ValueOf[emparams.BN254Fp](b)}, goldilocks.Modulus())
	assert.NoError(err)

	err = test.IsSolved(&EmulatedCircuit[smallBN]{}, &EmulatedCircuit[smallBN]{A: emulated.ValueOf[smallBN](a), B: emulated.ValueOf[smallBN](b)}, goldilocks.Modulus())
	assert.NoError(err)

	err = test.IsSolved(&EmulatedCircuit[emparams.BN254Fp]{}, &EmulatedCircuit[emparams.BN254Fp]{A: emulated.ValueOf[emparams.BN254Fp](a), B: emulated.ValueOf[emparams.BN254Fp](b)}, babybear.Modulus())
	assert.NoError(err)

	err = test.IsSolved(&EmulatedCircuit[smallBN]{}, &EmulatedCircuit[smallBN]{A: emulated.ValueOf[smallBN](a), B: emulated.ValueOf[smallBN](b)}, babybear.Modulus())
	assert.NoError(err)
}

func TestCompileEmulatedCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	f := babybear.Modulus()

	circuit := &EmulatedCircuit[smallBN]{}
	assignment := &EmulatedCircuit[smallBN]{A: emulated.ValueOf[smallBN](2), B: emulated.ValueOf[smallBN](4)}

	ccs, err := frontend.Compile(f, scs.NewBuilder, circuit)
	assert.NoError(err)

	w, err := frontend.NewWitness(assignment, f)
	assert.NoError(err)

	res, err := ccs.Solve(w)
	assert.NoError(err)

	tres, ok := res.(*babybearcs.SparseR1CSSolution)
	assert.True(ok)

	fmt.Println(tres.L.String())
	fmt.Println(tres.R.String())
	fmt.Println(tres.O.String())

	ccs2, err := frontend.Compile(f, r1cs.NewBuilder, circuit)
	assert.NoError(err)

	res2, err := ccs2.Solve(w)
	assert.NoError(err)

	tres2, ok := res2.(*babybearcs.R1CSSolution)
	assert.True(ok)

	fmt.Println(tres2.W.String())
	fmt.Println(tres2.A.String())
	fmt.Println(tres2.B.String())
	fmt.Println(tres2.C.String())
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

	// ccs, err := frontend.Compile(babybear.Modulus(), scs.NewBuilder, &PairCircuit{})
	// assert.NoError(err)
	// _ = ccs

	// w, err := frontend.NewWitness(&witness, babybear.Modulus())
	// assert.NoError(err)

	// sol, err := ccs.Solve(w)
	// assert.NoError(err)

	// tres, ok := sol.(*babybearcs.SparseR1CSSolution)
	// assert.True(ok)
	// fmt.Println(tres.L.Len())

	ccs2, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &PairCircuit{})
	_ = ccs2
	assert.NoError(err)
	w2, err := frontend.NewWitness(&witness, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
	sol2, err := ccs2.Solve(w2)
	assert.NoError(err)
	tres, ok := sol2.(*bls12377cs.SparseR1CSSolution)
	assert.True(ok)
	fmt.Println(tres.L.Len())
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
