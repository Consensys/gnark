package frontend

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/internal/backend/compiled"
)

type splitCircuit struct {
	A [2]Variable
	B Variable
}

func (circuit *splitCircuit) Define(curveID ecc.ID, cs *ConstraintSystem) error {

	u := cs.Mul(circuit.A[0], -2)
	v := cs.Add(u, circuit.A[1])
	cs.AssertIsEqual(v, circuit.B)
	cs.Mul(v, circuit.A[0])
	return nil
}

func TestSplit(t *testing.T) {

	var circuit splitCircuit

	cs, err := buildCS(ecc.BN254, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	scs := sparseR1CS{
		ConstraintSystem: &cs,
		ccs: compiled.SparseR1CS{
			CS: compiled.CS{
				NbInternalVariables: len(cs.internal.variables),
				NbPublicVariables:   len(cs.public.variables) - 1, // the ONE_WIRE is discarded in PlonK
				NbSecretVariables:   len(cs.secret.variables),
				DebugInfo:           make([]compiled.LogEntry, len(cs.debugInfo)),
				Logs:                make([]compiled.LogEntry, len(cs.logs)),
				MDebug:              make(map[int]int),
				MHints:              make(map[int]compiled.Hint),
			},
			Constraints: make([]compiled.SparseR1C, 0, len(cs.constraints)),
		},
		solvedVariables:      make([]bool, len(cs.internal.variables), len(cs.internal.variables)*2),
		scsInternalVariables: len(cs.internal.variables),
		currentR1CDebugID:    -1,
		record:               make(map[string]compiled.Term),
		h:                    sha256.New(),
	}

	for i := 0; i < len(scs.constraints); i++ {

		// sort.Sort(scs.constraints[i].L)
		// sort.Sort(scs.constraints[i].R)
		// sort.Sort(scs.constraints[i].O)

		fmt.Printf("%s\n", scs.constraints[i].String(scs.coeffs))

		scs.splitBis(scs.constraints[i].L)

		scs.splitBis(scs.constraints[i].R)

		scs.splitBis(scs.constraints[i].O)
		for k := range scs.record {
			fmt.Printf("%x\n", k)
		}
		fmt.Println("---")

	}

	for k := range scs.record {
		fmt.Printf("%x\n", k)
	}
	fmt.Println("---")

}

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
