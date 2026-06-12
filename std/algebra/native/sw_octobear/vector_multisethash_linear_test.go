package sw_octobear

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/octobear"
	nativemsh "github.com/consensys/gnark-crypto/ecc/octobear/multiset-hash"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/widecommitter"
	"github.com/consensys/gnark/std/algebra/native/maptocurve_octobear"
	"github.com/consensys/gnark/test"
)

// linearHashCircuit verifies LinearAccumulator over a small batch of inserts.
type linearHashCircuit struct {
	Msgs   [4]frontend.Variable
	Digest [maptocurve_octobear.LinearN]G1Affine
}

func (c *linearHashCircuit) Define(api frontend.API) error {
	curve, err := NewCurve(api)
	if err != nil {
		return err
	}
	digest, err := curve.HashLinear(c.Msgs[:])
	if err != nil {
		return err
	}
	for i := range digest {
		digest[i].X.AssertIsEqual(api, c.Digest[i].X)
		digest[i].Y.AssertIsEqual(api, c.Digest[i].Y)
	}
	return nil
}

// linearSingleInsertCircuit measures the per-Insert constraint cost.
type linearSingleInsertCircuit struct {
	Msg    frontend.Variable
	Digest [maptocurve_octobear.LinearN]G1Affine
}

func (c *linearSingleInsertCircuit) Define(api frontend.API) error {
	curve, err := NewCurve(api)
	if err != nil {
		return err
	}
	digest, err := curve.HashLinear([]frontend.Variable{c.Msg})
	if err != nil {
		return err
	}
	for i := range digest {
		digest[i].X.AssertIsEqual(api, c.Digest[i].X)
		digest[i].Y.AssertIsEqual(api, c.Digest[i].Y)
	}
	return nil
}

// shiftedLinearDigest matches the per-coordinate offset added by the in-circuit
// LinearAccumulator (each coordinate starts at the generator G). The native
// HashLinear returns un-shifted sums starting at infinity, so we add G to each
// coordinate to bring them in sync with what the circuit accumulator computes.
func shiftedLinearDigest(d [maptocurve_octobear.LinearN]octobear.G1Affine) [maptocurve_octobear.LinearN]octobear.G1Affine {
	_, offset := octobear.Generators()
	var out [maptocurve_octobear.LinearN]octobear.G1Affine
	for i := range d {
		var jd, jo octobear.G1Jac
		jd.FromAffine(&d[i])
		jo.FromAffine(&offset)
		jd.AddAssign(&jo)
		out[i].FromJacobian(&jd)
	}
	return out
}

func newLinearWitnessDigest(d [maptocurve_octobear.LinearN]octobear.G1Affine) [maptocurve_octobear.LinearN]G1Affine {
	var out [maptocurve_octobear.LinearN]G1Affine
	for i := range d {
		out[i] = NewG1Affine(d[i])
	}
	return out
}

func TestLinearHash(t *testing.T) {
	assert := test.NewAssert(t)
	msgs := []uint32{7, 19, 7, 1024}
	d, err := nativemsh.HashLinear(msgs)
	assert.NoError(err)
	shifted := shiftedLinearDigest(d)
	witness := &linearHashCircuit{
		Msgs:   [4]frontend.Variable{msgs[0], msgs[1], msgs[2], msgs[3]},
		Digest: newLinearWitnessDigest(shifted),
	}
	invalid := *witness
	invalid.Digest[0].X.C0.B0.A0 = 42
	assert.CheckCircuit(&linearHashCircuit{}, test.WithValidAssignment(witness), test.WithInvalidAssignment(&invalid), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}

func TestLinearHashHomomorphic(t *testing.T) {
	// Hash(A ∪ B) == Hash(A) + Hash(B) componentwise. We can't run this purely
	// in the native code (since the circuit accumulator shifts by G per
	// coordinate, the linearity has to be tested at the un-shifted native
	// level). Just verify the native side here; the in-circuit additivity is
	// guaranteed by Insert calling AddAssign per coordinate.
	a := []uint32{3, 41, 197}
	b := []uint32{2, 99, 65535, 7}
	full, err := nativemsh.HashLinear(append(append([]uint32{}, a...), b...))
	if err != nil {
		t.Fatal(err)
	}
	dA, err := nativemsh.HashLinear(a)
	if err != nil {
		t.Fatal(err)
	}
	dB, err := nativemsh.HashLinear(b)
	if err != nil {
		t.Fatal(err)
	}
	for i := range full {
		var sum octobear.G1Affine
		sum.Add(&dA[i], &dB[i])
		if !sum.Equal(&full[i]) {
			t.Fatalf("native HashLinear is not additive at coord %d", i)
		}
	}
}

func BenchmarkLinearMultisetHashCircuitSolve(b *testing.B) {
	msg := uint32(7)
	d, err := nativemsh.HashLinear([]uint32{msg})
	if err != nil {
		b.Fatal(err)
	}
	shifted := shiftedLinearDigest(d)
	w := &linearSingleInsertCircuit{
		Msg:    msg,
		Digest: newLinearWitnessDigest(shifted),
	}
	witness, err := frontend.NewWitness(w, koalabear.Modulus())
	if err != nil {
		b.Fatal(err)
	}

	b.Run("scs", func(b *testing.B) {
		var c linearSingleInsertCircuit
		ccs, err := frontend.CompileGeneric[constraint.U32](koalabear.Modulus(), widecommitter.From(scs.NewBuilder), &c)
		if err != nil {
			b.Fatal(err)
		}
		b.Log("scs nbConstraints", ccs.GetNbConstraints())
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ccs.IsSolved(witness); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("r1cs", func(b *testing.B) {
		var c linearSingleInsertCircuit
		ccs, err := frontend.CompileGeneric[constraint.U32](koalabear.Modulus(), widecommitter.From(r1cs.NewBuilder), &c, frontend.WithCompressThreshold(10))
		if err != nil {
			b.Fatal(err)
		}
		b.Log("r1cs nbConstraints", ccs.GetNbConstraints())
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ccs.IsSolved(witness); err != nil {
				b.Fatal(err)
			}
		}
	})
}
