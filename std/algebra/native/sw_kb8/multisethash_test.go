package sw_kb8

import (
	"testing"

	nativemsh "github.com/consensys/gnark-crypto/ecc/kb8/multiset-hash"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/widecommitter"
	"github.com/consensys/gnark/test"
)

// multisetHashCircuit is the 1-point kb8 multiset-hash verification circuit.
type multisetHashCircuit struct {
	Msgs   [4]frontend.Variable
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

func TestHash(t *testing.T) {
	assert := test.NewAssert(t)
	msgs := []uint16{7, 19, 7, 1024}
	d, err := nativemsh.Hash(msgs)
	assert.NoError(err)
	witness := &multisetHashCircuit{
		Msgs:   [4]frontend.Variable{msgs[0], msgs[1], msgs[2], msgs[3]},
		Digest: NewG1Affine(d),
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
	valid := &multisetHashCircuit{
		Msgs:   [4]frontend.Variable{msgs[0], msgs[1], msgs[2], msgs[3]},
		Digest: NewG1Affine(d),
	}
	invalid := *valid
	invalid.Digest.Y.C1.B1.A1 = 17
	assert.CheckCircuit(&multisetHashCircuit{}, test.WithValidAssignment(valid), test.WithInvalidAssignment(&invalid), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}

func BenchmarkMultisetHashCircuitSolve(b *testing.B) {
	msgs := []uint16{7, 19, 7, 1024}
	d, err := nativemsh.Hash(msgs)
	if err != nil {
		b.Fatal(err)
	}
	w := &multisetHashCircuit{
		Msgs:   [4]frontend.Variable{msgs[0], msgs[1], msgs[2], msgs[3]},
		Digest: NewG1Affine(d),
	}
	witness, err := frontend.NewWitness(w, koalabear.Modulus())
	if err != nil {
		b.Fatal(err)
	}

	b.Run("scs", func(b *testing.B) {
		var c multisetHashCircuit
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
		var c multisetHashCircuit
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
