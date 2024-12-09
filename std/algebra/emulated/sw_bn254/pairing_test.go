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

type FinalExponentiationIsOne struct {
	InGt GTEl
}

func (c *FinalExponentiationIsOne) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	pairing.AssertFinalExponentiationIsOne(&c.InGt)
	return nil
}

func TestFinalExponentiationIsOneTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	// e(a,2b) * e(-2a,b) == 1
	p1, q1 := randomG1G2Affines()
	var p2 bn254.G1Affine
	p2.Double(&p1).Neg(&p2)
	var q2 bn254.G2Affine
	q2.Set(&q1)
	q1.Double(&q1)
	ml, err := bn254.MillerLoop(
		[]bn254.G1Affine{p1, p2},
		[]bn254.G2Affine{q1, q2},
	)
	witness := FinalExponentiationIsOne{
		InGt: NewGTEl(ml),
	}
	err = test.IsSolved(&FinalExponentiationIsOne{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
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
	err = pairing.PairingCheck([]*G1Affine{&c.In1G1, &c.In2G1}, []*G2Affine{&c.In1G2, &c.In2G2})
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	return nil
}

func TestPairingCheckTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	// e(a,2b) * e(-2a,b) == 1
	p1, q1 := randomG1G2Affines()
	var p2 bn254.G1Affine
	p2.Double(&p1).Neg(&p2)
	var q2 bn254.G2Affine
	q2.Set(&q1)
	q1.Double(&q1)
	witness := PairingCheckCircuit{
		In1G1: NewG1Affine(p1),
		In1G2: NewG2Affine(q1),
		In2G1: NewG1Affine(p2),
		In2G2: NewG2Affine(q2),
	}
	err := test.IsSolved(&PairingCheckCircuit{}, &witness, ecc.BN254.ScalarField())
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

type IsOnTwistCircuit struct {
	Q        G2Affine
	Expected frontend.Variable
}

func (c *IsOnTwistCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	res := pairing.IsOnTwist(&c.Q)
	api.AssertIsEqual(res, c.Expected)
	return nil
}

func TestIsOnTwistSolve(t *testing.T) {
	assert := test.NewAssert(t)
	// test for a point not on the twist
	var Q bn254.G2Affine
	_, err := Q.X.A0.SetString("0x119606e6d3ea97cea4eff54433f5c7dbc026b8d0670ddfbe6441e31225028d31")
	assert.NoError(err)
	_, err = Q.X.A1.SetString("0x1d3df5be6084324da6333a6ad1367091ca9fbceb70179ec484543a58b8cb5d63")
	assert.NoError(err)
	_, err = Q.Y.A0.SetString("0x1b9a36ea373fe2c5b713557042ce6deb2907d34e12be595f9bbe84c144de86ef")
	assert.NoError(err)
	_, err = Q.Y.A1.SetString("0x49fe60975e8c78b7b31a6ed16a338ac8b28cf6a065cfd2ca47e9402882518ba0")
	assert.NoError(err)
	assert.False(Q.IsOnCurve())
	witness := IsOnTwistCircuit{
		Q:        NewG2Affine(Q),
		Expected: 0,
	}
	err = test.IsSolved(&IsOnTwistCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
	// test for a point on the twist
	_, Q = randomG1G2Affines()
	assert.True(Q.IsOnCurve())
	witness = IsOnTwistCircuit{
		Q:        NewG2Affine(Q),
		Expected: 1,
	}
	err = test.IsSolved(&IsOnTwistCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type IsOnG2Circuit struct {
	Q        G2Affine
	Expected frontend.Variable
}

func (c *IsOnG2Circuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	res := pairing.IsOnG2(&c.Q)
	api.AssertIsEqual(res, c.Expected)
	return nil
}

func TestIsOnG2Solve(t *testing.T) {
	assert := test.NewAssert(t)
	// test for a point not on the curve
	var Q bn254.G2Affine
	_, err := Q.X.A0.SetString("0x119606e6d3ea97cea4eff54433f5c7dbc026b8d0670ddfbe6441e31225028d31")
	assert.NoError(err)
	_, err = Q.X.A1.SetString("0x1d3df5be6084324da6333a6ad1367091ca9fbceb70179ec484543a58b8cb5d63")
	assert.NoError(err)
	_, err = Q.Y.A0.SetString("0x1b9a36ea373fe2c5b713557042ce6deb2907d34e12be595f9bbe84c144de86ef")
	assert.NoError(err)
	_, err = Q.Y.A1.SetString("0x49fe60975e8c78b7b31a6ed16a338ac8b28cf6a065cfd2ca47e9402882518ba0")
	assert.NoError(err)
	assert.False(Q.IsOnCurve())
	witness := IsOnG2Circuit{
		Q:        NewG2Affine(Q),
		Expected: 0,
	}
	err = test.IsSolved(&IsOnG2Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
	// test for a point on curve not in G2
	_, err = Q.X.A0.SetString("0x07192b9fd0e2a32e3e1caa8e59462b757326d48f641924e6a1d00d66478913eb")
	assert.NoError(err)
	_, err = Q.X.A1.SetString("0x15ce93f1b1c4946dd6cfbb3d287d9c9a1cdedb264bda7aada0844416d8a47a63")
	assert.NoError(err)
	_, err = Q.Y.A0.SetString("0x0fa65a9b48ba018361ed081e3b9e958451de5d9e8ae0bd251833ebb4b2fafc96")
	assert.NoError(err)
	_, err = Q.Y.A1.SetString("0x06e1f5e20f68f6dfa8a91a3bea048df66d9eaf56cc7f11215401f7e05027e0c6")
	assert.NoError(err)
	assert.True(Q.IsOnCurve())
	assert.False(Q.IsInSubGroup())
	witness = IsOnG2Circuit{
		Q:        NewG2Affine(Q),
		Expected: 0,
	}
	err = test.IsSolved(&IsOnG2Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
	// test for a point in G2
	_, Q = randomG1G2Affines()
	assert.True(Q.IsOnCurve())
	assert.True(Q.IsInSubGroup())
	witness = IsOnG2Circuit{
		Q:        NewG2Affine(Q),
		Expected: 1,
	}
	err = test.IsSolved(&IsOnG2Circuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// bench
func BenchmarkPairing(b *testing.B) {
	// e(a,2b) * e(-2a,b) == 1
	p1, q1 := randomG1G2Affines()
	var p2 bn254.G1Affine
	p2.Double(&p1).Neg(&p2)
	var q2 bn254.G2Affine
	q2.Set(&q1)
	q1.Double(&q1)
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
