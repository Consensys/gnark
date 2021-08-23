package frontend

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
)

const benchSize = 1 << 20

func BenchmarkCompileReferenceGroth16(b *testing.B) {
	var c benchCircuit

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Compile(ecc.BN254, backend.GROTH16, &c, benchSize)
	}
}

func BenchmarkCompileReferencePlonk(b *testing.B) {
	var c benchCircuit

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Compile(ecc.BN254, backend.PLONK, &c, benchSize)
	}
}

// benchCircuit is a simple circuit that checks X*X*X*X*X... == Y
type benchCircuit struct {
	X Variable
	Y Variable `gnark:",public"`
}

func (circuit *benchCircuit) Define(curveID ecc.ID, cs *ConstraintSystem) error {
	for i := 0; i < benchSize; i++ {
		circuit.X = cs.Mul(circuit.X, circuit.X)
	}
	cs.AssertIsEqual(circuit.X, circuit.Y)
	return nil
}
