package zkpschemes

const Groth16Tests = `


{{ template "header" . }}

package groth16

import (
	{{ template "import_curve" . }}
	{{ template "import_backend" . }}
	"path/filepath"
	"runtime/debug"
	"testing"
	"strings"


	"github.com/consensys/gnark/internal/utils/encoding/gob"
	constants "github.com/consensys/gnark/backend"

	{{if ne .Curve "GENERIC"}}
	"reflect"
	"github.com/stretchr/testify/require"
	{{end}}
)


func TestCircuits(t *testing.T) {
	assert := NewAssert(t)
	{{if eq .Curve "GENERIC"}}
		matches, err := filepath.Glob("./testdata/" + strings.ToLower(curve.ID.String()) + "/*.r1cs")
	{{else}}
		matches, err := filepath.Glob("../../../../backend/groth16/testdata/" + strings.ToLower(curve.ID.String()) + "/*.r1cs")
	{{end}}
	
	if err != nil {
		t.Fatal(err) 
	}

	if len(matches) == 0 {
		t.Fatal("couldn't find test circuits for", curve.ID.String())
	}
	for _, name := range matches {
		name = name[:len(name)-5]
		t.Log(curve.ID.String(), " -- ", filepath.Base(name))

		good := backend.NewAssignment()
		if err := good.ReadFile(name + ".good"); err != nil {
			t.Fatal(err)
		}
		bad := backend.NewAssignment()
		if err := bad.ReadFile(name + ".bad"); err != nil {
			t.Fatal(err)
		}
		var r1cs backend.R1CS

		if err := gob.Read(name+".r1cs", &r1cs, curve.ID); err != nil {
			t.Fatal(err)
		}
		assert.NotSolved(&r1cs, bad)
		assert.Solved(&r1cs, good, nil)
	}
}

func TestParsePublicInput(t *testing.T) {

	expectedNames := [2]string{"data", "ONE_WIRE"}

	inputOneWire := backend.NewAssignment()
	inputOneWire.Assign(constants.Public, "ONE_WIRE", 3)
	if _, err := parsePublicInput(expectedNames[:], inputOneWire); err == nil {
		t.Fatal("expected ErrMissingAssigment error")
	}

	inputPrivate := backend.NewAssignment()
	inputPrivate.Assign(constants.Secret, "data", 3)
	if _, err := parsePublicInput(expectedNames[:], inputPrivate); err == nil {
		t.Fatal("expected ErrMissingAssigment error")
	}

	missingInput := backend.NewAssignment()
	if _, err := parsePublicInput(expectedNames[:], missingInput); err == nil {
		t.Fatal("expected ErrMissingAssigment")
	}

	correctInput := backend.NewAssignment()
	correctInput.Assign(constants.Public, "data", 3)
	got, err := parsePublicInput(expectedNames[:], correctInput)
	if err != nil {
		t.Fatal(err)
	}

	expected := make([]fr.Element, 2)
	expected[0].SetUint64(3).FromMont()
	expected[1].SetUint64(1).FromMont()
	if len(got) != len(expected) {
		t.Fatal("Unexpected length for assignment")
	}
	for i := 0; i < len(got); i++ {
		if !got[i].Equal(&expected[i]) {
			t.Fatal("error public assignment")
		}
	}

}

//--------------------//
//     benches		  //
//--------------------//

func referenceCircuit() (backend.R1CS, backend.Assignments, backend.Assignments) {
	{{if eq .Curve "GENERIC"}}
		name := "./testdata/" + strings.ToLower(curve.ID.String()) + "/reference_large"
	{{else}}
		name := "../../../../backend/groth16/testdata/" + strings.ToLower(curve.ID.String()) + "/reference_large"
	{{end}}
	
	good := backend.NewAssignment()
	if err := good.ReadFile(name + ".good"); err != nil {
		panic(err)
	}
	bad := backend.NewAssignment()
	if err := bad.ReadFile(name + ".bad"); err != nil {
		panic(err)
	}
	var r1cs backend.R1CS

	if err := gob.Read(name+".r1cs", &r1cs, curve.ID); err != nil {
		panic(err)
	}

	return r1cs, good, bad
}

// BenchmarkSetup is a helper to benchmark Setup on a given circuit
func BenchmarkSetup(b *testing.B) {
	r1cs, _, _ := referenceCircuit()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	var pk ProvingKey
	var vk VerifyingKey
	b.ResetTimer()

	b.Run("setup", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Setup(&r1cs, &pk, &vk)
		}
	})
}

// BenchmarkProver is a helper to benchmark Prove on a given circuit
// it will run the Setup, reset the benchmark timer and benchmark the prover
func BenchmarkProver(b *testing.B) {
	r1cs, solution, _ := referenceCircuit()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	var pk ProvingKey
	var vk VerifyingKey
	Setup(&r1cs, &pk, &vk)

	b.ResetTimer()
	b.Run("prover", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = Prove(&r1cs, &pk, solution)
		}
	})
}

// BenchmarkVerifier is a helper to benchmark Verify on a given circuit
// it will run the Setup, the Prover and reset the benchmark timer and benchmark the verifier
// the provided solution will be filtered to keep only public inputs
func BenchmarkVerifier(b *testing.B) {
	r1cs, solution, _ := referenceCircuit()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	var pk ProvingKey
	var vk VerifyingKey
	Setup(&r1cs, &pk, &vk)
	proof, err := Prove(&r1cs, &pk, solution)
	if err != nil {
		panic(err)
	}

	solution = solution.DiscardSecrets()
	b.ResetTimer()
	b.Run("verifier", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = Verify(proof, &vk, solution)
		}
	})
}


{{if ne .Curve "GENERIC"}}
// assert helpers
{{ template "groth16_assert" . }}
{{end}}

`
