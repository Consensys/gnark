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

// poseidon2HashCircuit verifies Poseidon2Accumulator over a small batch.
type poseidon2HashCircuit struct {
	MsgsLow  [4]frontend.Variable
	MsgsHigh [4]frontend.Variable
	Digest   [maptocurve_octobear.PqN]G1Affine
}

func (c *poseidon2HashCircuit) Define(api frontend.API) error {
	curve, err := NewCurve(api)
	if err != nil {
		return err
	}
	digest, err := curve.HashPoseidon2(c.MsgsLow[:], c.MsgsHigh[:])
	if err != nil {
		return err
	}
	for i := range digest {
		digest[i].X.AssertIsEqual(api, c.Digest[i].X)
		digest[i].Y.AssertIsEqual(api, c.Digest[i].Y)
	}
	return nil
}

type poseidon2SingleInsertCircuit struct {
	MsgLow  frontend.Variable
	MsgHigh frontend.Variable
	Digest  [maptocurve_octobear.PqN]G1Affine
}

func (c *poseidon2SingleInsertCircuit) Define(api frontend.API) error {
	curve, err := NewCurve(api)
	if err != nil {
		return err
	}
	digest, err := curve.HashPoseidon2([]frontend.Variable{c.MsgLow}, []frontend.Variable{c.MsgHigh})
	if err != nil {
		return err
	}
	for i := range digest {
		digest[i].X.AssertIsEqual(api, c.Digest[i].X)
		digest[i].Y.AssertIsEqual(api, c.Digest[i].Y)
	}
	return nil
}

func shiftedPoseidon2Digest(d [maptocurve_octobear.PqN]octobear.G1Affine) [maptocurve_octobear.PqN]octobear.G1Affine {
	_, offset := octobear.Generators()
	var out [maptocurve_octobear.PqN]octobear.G1Affine
	for i := range d {
		var jd, jo octobear.G1Jac
		jd.FromAffine(&d[i])
		jo.FromAffine(&offset)
		jd.AddAssign(&jo)
		out[i].FromJacobian(&jd)
	}
	return out
}

func newPoseidon2WitnessDigest(d [maptocurve_octobear.PqN]octobear.G1Affine) [maptocurve_octobear.PqN]G1Affine {
	var out [maptocurve_octobear.PqN]G1Affine
	for i := range d {
		out[i] = NewG1Affine(d[i])
	}
	return out
}

func splitMsg(msg uint64) (low, high uint32) {
	return uint32(msg & 0xFFFFFFFF), uint32(msg >> 32)
}

func TestPoseidon2Hash(t *testing.T) {
	assert := test.NewAssert(t)
	msgs := []uint64{7, 19, 7, 1024}
	d, err := nativemsh.HashPoseidon2(msgs)
	assert.NoError(err)
	shifted := shiftedPoseidon2Digest(d)

	var w poseidon2HashCircuit
	for i, m := range msgs {
		low, high := splitMsg(m)
		w.MsgsLow[i] = low
		w.MsgsHigh[i] = high
	}
	w.Digest = newPoseidon2WitnessDigest(shifted)

	invalid := w
	invalid.Digest[0].X.C0.B0.A0 = 42

	assert.CheckCircuit(&poseidon2HashCircuit{},
		test.WithValidAssignment(&w),
		test.WithInvalidAssignment(&invalid),
		test.WithoutCurveChecks(),
		test.WithSmallfieldCheck())
}

func TestPoseidon2HashHomomorphic(t *testing.T) {
	a := []uint64{3, 41, 197}
	b := []uint64{2, 99, 65535, 7}
	full, err := nativemsh.HashPoseidon2(append(append([]uint64{}, a...), b...))
	if err != nil {
		t.Fatal(err)
	}
	dA, err := nativemsh.HashPoseidon2(a)
	if err != nil {
		t.Fatal(err)
	}
	dB, err := nativemsh.HashPoseidon2(b)
	if err != nil {
		t.Fatal(err)
	}
	for i := range full {
		var sum octobear.G1Affine
		sum.Add(&dA[i], &dB[i])
		if !sum.Equal(&full[i]) {
			t.Fatalf("native HashPoseidon2 is not additive at coord %d", i)
		}
	}
}

func BenchmarkPoseidon2MultisetHashCircuitSolve(b *testing.B) {
	msg := uint64(7)
	d, err := nativemsh.HashPoseidon2([]uint64{msg})
	if err != nil {
		b.Fatal(err)
	}
	shifted := shiftedPoseidon2Digest(d)
	low, high := splitMsg(msg)
	w := &poseidon2SingleInsertCircuit{
		MsgLow:  low,
		MsgHigh: high,
		Digest:  newPoseidon2WitnessDigest(shifted),
	}
	witness, err := frontend.NewWitness(w, koalabear.Modulus())
	if err != nil {
		b.Fatal(err)
	}

	b.Run("scs", func(b *testing.B) {
		var c poseidon2SingleInsertCircuit
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
		var c poseidon2SingleInsertCircuit
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
