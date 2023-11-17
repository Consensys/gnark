package sw_bn254

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

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

type FinalExponentiationCircuit struct {
	InGt GTEl
	Res  GTEl
}

func (c *FinalExponentiationCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	res1 := pairing.FinalExponentiation(&c.InGt)
	pairing.AssertIsEqual(res1, &c.Res)
	res2 := pairing.FinalExponentiationUnsafe(&c.InGt)
	pairing.AssertIsEqual(res2, &c.Res)
	return nil
}

func TestFinalExponentiationTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	var gt bn254.GT
	gt.SetRandom()
	res := bn254.FinalExponentiation(&gt)
	witness := FinalExponentiationCircuit{
		InGt: NewGTEl(gt),
		Res:  NewGTEl(res),
	}
	err := test.IsSolved(&FinalExponentiationCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type PairCircuit struct {
	InG1 G1Affine
	InG2 G2Affine
	Res  GTEl
}

func (c *PairCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	pairing.AssertIsOnG1(&c.InG1)
	pairing.AssertIsOnG2(&c.InG2)
	res, err := pairing.Pair([]*G1Affine{&c.InG1}, []*G2Affine{&c.InG2})
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
		InG1: NewG1Affine(p),
		InG2: NewG2Affine(q),
		Res:  NewGTEl(res),
	}
	err = test.IsSolved(&PairCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type MultiPairCircuit struct {
	InG1 G1Affine
	InG2 G2Affine
	Res  GTEl
	n    int
}

func (c *MultiPairCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	pairing.AssertIsOnG1(&c.InG1)
	pairing.AssertIsOnG2(&c.InG2)
	P, Q := []*G1Affine{}, []*G2Affine{}
	for i := 0; i < c.n; i++ {
		P = append(P, &c.InG1)
		Q = append(Q, &c.InG2)
	}
	res, err := pairing.Pair(P, Q)
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	pairing.AssertIsEqual(res, &c.Res)
	return nil
}

func TestMultiPairTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	p1, q1 := randomG1G2Affines()
	p := make([]bn254.G1Affine, 4)
	q := make([]bn254.G2Affine, 4)
	for i := 0; i < 4; i++ {
		p[i] = p1
		q[i] = q1
	}

	for i := 2; i < 4; i++ {
		res, err := bn254.Pair(p[:i], q[:i])
		assert.NoError(err)
		witness := MultiPairCircuit{
			InG1: NewG1Affine(p1),
			InG2: NewG2Affine(q1),
			Res:  NewGTEl(res),
		}
		err = test.IsSolved(&MultiPairCircuit{n: i}, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
}

type PairingCheckCircuit struct {
	In1G1 G1Affine
	In2G1 G1Affine
	In1G2 G2Affine
	In2G2 G2Affine
}

func (c *PairingCheckCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	err = pairing.PairingCheck([]*G1Affine{&c.In1G1, &c.In1G1, &c.In2G1, &c.In2G1}, []*G2Affine{&c.In1G2, &c.In2G2, &c.In1G2, &c.In2G2})
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	return nil
}

func TestPairingCheckTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	p1, q1 := randomG1G2Affines()
	_, q2 := randomG1G2Affines()
	var p2 bn254.G1Affine
	p2.Neg(&p1)
	witness := PairingCheckCircuit{
		In1G1: NewG1Affine(p1),
		In1G2: NewG2Affine(q1),
		In2G1: NewG1Affine(p2),
		In2G2: NewG2Affine(q2),
	}
	err := test.IsSolved(&PairingCheckCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type FinalExponentiationSafeCircuit struct {
	P1, P2 G1Affine
	Q1, Q2 G2Affine
}

func (c *FinalExponentiationSafeCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return err
	}
	res, err := pairing.MillerLoop([]*G1Affine{&c.P1, &c.P2}, []*G2Affine{&c.Q1, &c.Q2})
	if err != nil {
		return err
	}
	res2 := pairing.FinalExponentiation(res)
	one := pairing.Ext12.One()
	pairing.AssertIsEqual(one, res2)
	return nil
}

func TestFinalExponentiationSafeCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, p1, q1 := bn254.Generators()
	var p2 bn254.G1Affine
	var q2 bn254.G2Affine
	p2.Neg(&p1)
	q2.Set(&q1)
	err := test.IsSolved(&FinalExponentiationSafeCircuit{}, &FinalExponentiationSafeCircuit{
		P1: NewG1Affine(p1),
		P2: NewG1Affine(p2),
		Q1: NewG2Affine(q1),
		Q2: NewG2Affine(q2),
	}, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type GroupMembershipCircuit struct {
	InG1 G1Affine
	InG2 G2Affine
}

func (c *GroupMembershipCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	pairing.AssertIsOnG1(&c.InG1)
	pairing.AssertIsOnG2(&c.InG2)
	return nil
}

func TestGroupMembershipSolve(t *testing.T) {
	assert := test.NewAssert(t)
	p, q := randomG1G2Affines()
	witness := GroupMembershipCircuit{
		InG1: NewG1Affine(p),
		InG2: NewG2Affine(q),
	}
	err := test.IsSolved(&GroupMembershipCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// ----------------------------
//	  Fixed-argument pairing
// ----------------------------
//
// The second argument Q is the fixed canonical generator of G2.
//
// Q.X.A0 = 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
// Q.X.A1 = 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2
// Q.Y.A0 = 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
// Q.Y.A1 = 0x90689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b

type PairFixedCircuit struct {
	InG1 G1Affine
	Res  GTEl
}

func (c *PairFixedCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	res, err := pairing.PairFixedQ(&c.InG1)
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	pairing.AssertIsEqual(res, &c.Res)
	return nil
}

func TestPairFixedTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	p, _ := randomG1G2Affines()
	_, _, _, G2AffGen := bn254.Generators()
	res, err := bn254.Pair([]bn254.G1Affine{p}, []bn254.G2Affine{G2AffGen})
	assert.NoError(err)
	witness := PairFixedCircuit{
		InG1: NewG1Affine(p),
		Res:  NewGTEl(res),
	}
	err = test.IsSolved(&PairFixedCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type DoublePairFixedCircuit struct {
	In1G1 G1Affine
	In2G1 G1Affine
	In1G2 G2Affine
	Res   GTEl
}

func (c *DoublePairFixedCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	res, err := pairing.DoublePairFixedQ(&c.In1G1, &c.In2G1, &c.In1G2)
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	pairing.AssertIsEqual(res, &c.Res)
	return nil
}

func TestDoublePairFixedTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	p, q := randomG1G2Affines()
	_, _, _, G2AffGen := bn254.Generators()
	res, err := bn254.Pair([]bn254.G1Affine{p, p}, []bn254.G2Affine{q, G2AffGen})
	assert.NoError(err)
	witness := DoublePairFixedCircuit{
		In1G1: NewG1Affine(p),
		In2G1: NewG1Affine(p),
		In1G2: NewG2Affine(q),
		Res:   NewGTEl(res),
	}
	err = test.IsSolved(&DoublePairFixedCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// bench
func BenchmarkPairing(b *testing.B) {

	p1, q1 := randomG1G2Affines()
	_, q2 := randomG1G2Affines()
	var p2 bn254.G1Affine
	p2.Neg(&p1)
	witness := PairingCheckCircuit{
		In1G1: NewG1Affine(p1),
		In1G2: NewG2Affine(q1),
		In2G1: NewG1Affine(p2),
		In2G2: NewG2Affine(q2),
	}
	w, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatal(err)
	}
	var ccs constraint.ConstraintSystem
	b.Run("compile scs", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if ccs, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &PairingCheckCircuit{}); err != nil {
				b.Fatal(err)
			}
		}
	})
	var buf bytes.Buffer
	_, err = ccs.WriteTo(&buf)
	if err != nil {
		b.Fatal(err)
	}
	b.Logf("scs size: %d (bytes), nb constraints %d, nbInstructions: %d", buf.Len(), ccs.GetNbConstraints(), ccs.GetNbInstructions())
	b.Run("solve scs", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := ccs.Solve(w); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("compile r1cs", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if ccs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &PairingCheckCircuit{}); err != nil {
				b.Fatal(err)
			}
		}
	})
	buf.Reset()
	_, err = ccs.WriteTo(&buf)
	if err != nil {
		b.Fatal(err)
	}
	b.Logf("r1cs size: %d (bytes), nb constraints %d, nbInstructions: %d", buf.Len(), ccs.GetNbConstraints(), ccs.GetNbInstructions())

	b.Run("solve r1cs", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := ccs.Solve(w); err != nil {
				b.Fatal(err)
			}
		}
	})
}
