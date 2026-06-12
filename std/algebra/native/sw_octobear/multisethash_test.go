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
	"github.com/consensys/gnark/test"
)

// multisetHashCircuit is the 1-point octobear multiset-hash verification circuit.
type multisetHashCircuit struct {
	Msgs   [4]frontend.Variable
	Digest G1Affine
}

type multisetHashSingleInsertCircuit struct {
	Msg    frontend.Variable
	Digest G1Affine
}

func (c *multisetHashCircuit) Define(api frontend.API) error {
	curve, err := NewCurve(api)
	if err != nil {
		return err
	}
	digest, err := curve.Hash(c.Msgs[:])
	if err != nil {
		return err
	}
	digest.X.AssertIsEqual(api, c.Digest.X)
	digest.Y.AssertIsEqual(api, c.Digest.Y)
	return nil
}

func (c *multisetHashSingleInsertCircuit) Define(api frontend.API) error {
	curve, err := NewCurve(api)
	if err != nil {
		return err
	}
	digest, err := curve.Hash([]frontend.Variable{c.Msg})
	if err != nil {
		return err
	}
	digest.X.AssertIsEqual(api, c.Digest.X)
	digest.Y.AssertIsEqual(api, c.Digest.Y)
	return nil
}

func TestHash(t *testing.T) {
	assert := test.NewAssert(t)
	msgs := []uint16{7, 19, 7, 1024}
	d, err := nativemsh.Hash(msgs)
	assert.NoError(err)
	shifted := shiftedDigest(d)
	witness := &multisetHashCircuit{
		Msgs:   [4]frontend.Variable{msgs[0], msgs[1], msgs[2], msgs[3]},
		Digest: NewG1Affine(shifted),
	}
	invalid := *witness
	invalid.Digest.X.C0.B0.A0 = 42
	assert.CheckCircuit(&multisetHashCircuit{}, test.WithValidAssignment(witness), test.WithInvalidAssignment(&invalid), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}

func TestHashInvalidDigest(t *testing.T) {
	assert := test.NewAssert(t)
	msgs := []uint16{1, 2, 3, 4}
	d, err := nativemsh.Hash(msgs)
	assert.NoError(err)
	shifted := shiftedDigest(d)
	valid := &multisetHashCircuit{
		Msgs:   [4]frontend.Variable{msgs[0], msgs[1], msgs[2], msgs[3]},
		Digest: NewG1Affine(shifted),
	}
	invalid := *valid
	invalid.Digest.Y.C1.B1.A1 = 17
	assert.CheckCircuit(&multisetHashCircuit{}, test.WithValidAssignment(valid), test.WithInvalidAssignment(&invalid), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}

func BenchmarkMultisetHashCircuitSolve(b *testing.B) {
	msg := uint16(7)
	d, err := nativemsh.Hash([]uint16{msg})
	if err != nil {
		b.Fatal(err)
	}
	shifted := shiftedDigest(d)
	w := &multisetHashSingleInsertCircuit{
		Msg:    msg,
		Digest: NewG1Affine(shifted),
	}
	witness, err := frontend.NewWitness(w, koalabear.Modulus())
	if err != nil {
		b.Fatal(err)
	}

	b.Run("scs", func(b *testing.B) {
		var c multisetHashSingleInsertCircuit
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
		var c multisetHashSingleInsertCircuit
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

func shiftedDigest(d octobear.G1Affine) octobear.G1Affine {
	_, offset := octobear.Generators()
	var jd, jo octobear.G1Jac
	jd.FromAffine(&d)
	jo.FromAffine(&offset)
	jd.AddAssign(&jo)
	var shifted octobear.G1Affine
	shifted.FromJacobian(&jd)
	return shifted
}
