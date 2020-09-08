package zkpschemes

// Groth16Tests ...
const Groth16Tests = `

import (
	{{ template "import_curve" . }}
	{{ template "import_backend" . }}
	"path/filepath"
	"runtime/debug"
	"testing"
	"strings"


	{{if eq .Curve "BLS377"}}
		{{toLower .Curve}}groth16 "github.com/consensys/gnark/internal/backend/bls377/groth16"
	{{else if eq .Curve "BLS381"}}
		{{toLower .Curve}}groth16 "github.com/consensys/gnark/internal/backend/bls381/groth16"
	{{else if eq .Curve "BN256"}}
		{{toLower .Curve}}groth16 "github.com/consensys/gnark/internal/backend/bn256/groth16"
	{{ else if eq .Curve "BW761"}}
		{{toLower .Curve}}groth16 "github.com/consensys/gnark/internal/backend/bw761/groth16"
	{{end}}

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/internal/backend/circuits"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"

	"reflect"
	"github.com/stretchr/testify/require"
)


func TestCircuits(t *testing.T) {
	for name, circuit := range circuits.Circuits {
		t.Run(name, func(t *testing.T) {
			assert := groth16.NewAssert(t)
			r1cs := circuit.R1CS.ToR1CS(curve.ID)
			assert.NotSolved(r1cs, circuit.Bad)
			assert.Solved(r1cs, circuit.Good, nil)
		})
	}
}

func TestParsePublicInput(t *testing.T) {

	expectedNames := [2]string{"data", backend.OneWire}

	inputOneWire := make(map[string]interface{})
	inputOneWire[ backend.OneWire ] = 3
	if _, err := {{toLower .Curve}}groth16.ParsePublicInput(expectedNames[:], inputOneWire); err == nil {
		t.Fatal("expected ErrMissingAssigment error")
	}

	missingInput := make(map[string]interface{})
	if _, err := {{toLower .Curve}}groth16.ParsePublicInput(expectedNames[:], missingInput); err == nil {
		t.Fatal("expected ErrMissingAssigment")
	}

	correctInput := make(map[string]interface{})
	correctInput[ "data" ] = 3
	got, err := {{toLower .Curve}}groth16.ParsePublicInput(expectedNames[:], correctInput)
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

type refCircuit struct {
	nbConstraints int 
	X frontend.Variable
	Y frontend.Variable ` + "`" + "gnark:\",public\"" + "`" + `
}

func (circuit *refCircuit) Define(curveID gurvy.ID, cs *frontend.CS) error {
	for i := 0; i < circuit.nbConstraints; i++ {
		circuit.X = cs.Mul(circuit.X, circuit.X)
	}
	cs.MustBeEqual(circuit.X, circuit.Y)
	return nil 
}

func referenceCircuit() (r1cs.R1CS, map[string]interface{}) {
	const nbConstraints = 40000
	circuit := refCircuit{
		nbConstraints: nbConstraints,
	}
	r1cs, err := frontend.Compile(curve.ID, &circuit)
	if err != nil {
		panic(err)
	}
	
	good := make(map[string]interface{})
	good["X"] = 2

	// compute expected Y
	var expectedY fr.Element
	expectedY.SetUint64(2)

	for i := 0; i < nbConstraints; i++ {
		expectedY.Mul(&expectedY, &expectedY)
	}

	good["Y"] = expectedY

	return r1cs, good
}

func TestReferenceCircuit(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	assert := groth16.NewAssert(t)
	r1cs, solution := referenceCircuit()
	assert.Solved(r1cs, solution, nil)
}

// BenchmarkSetup is a helper to benchmark Setup on a given circuit
func BenchmarkSetup(b *testing.B) {
	r1cs, _ := referenceCircuit()
	
	var pk {{toLower .Curve}}groth16.ProvingKey
	var vk {{toLower .Curve}}groth16.VerifyingKey
	b.ResetTimer()

	b.Run("setup", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			{{toLower .Curve}}groth16.Setup(r1cs.(*{{toLower .Curve}}backend.R1CS), &pk, &vk)
		}
	})
}

// BenchmarkProver is a helper to benchmark Prove on a given circuit
// it will run the Setup, reset the benchmark timer and benchmark the prover
func BenchmarkProver(b *testing.B) {
	r1cs, solution := referenceCircuit()
	
	var pk {{toLower .Curve}}groth16.ProvingKey
	{{toLower .Curve}}groth16.DummySetup(r1cs.(*{{toLower .Curve}}backend.R1CS), &pk)

	b.ResetTimer()
	b.Run("prover", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = {{toLower .Curve}}groth16.Prove(r1cs.(*{{toLower .Curve}}backend.R1CS), &pk, solution)
		}
	})
}

// BenchmarkVerifier is a helper to benchmark Verify on a given circuit
// it will run the Setup, the Prover and reset the benchmark timer and benchmark the verifier
// the provided solution will be filtered to keep only public inputs
func BenchmarkVerifier(b *testing.B) {
	r1cs, solution := referenceCircuit()
	
	var pk {{toLower .Curve}}groth16.ProvingKey
	var vk {{toLower .Curve}}groth16.VerifyingKey
	{{toLower .Curve}}groth16.Setup(r1cs.(*{{toLower .Curve}}backend.R1CS), &pk, &vk)
	proof, err := {{toLower .Curve}}groth16.Prove(r1cs.(*{{toLower .Curve}}backend.R1CS), &pk, solution)
	if err != nil {
		panic(err)
	}

	b.ResetTimer()
	b.Run("verifier", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = {{toLower .Curve}}groth16.Verify(proof, &vk, solution)
		}
	})
}

`
