package poseidon2

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	frbls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/fr"
	poseidonbls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/fr/poseidon2"
	"github.com/stretchr/testify/require"

	frbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	poseidonbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/poseidon2"

	frbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	poseidonbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/poseidon2"

	frbw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/fr"
	poseidonbw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/fr/poseidon2"

	frbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	poseidonbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2"

	frbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	poseidonbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/poseidon2"

	frbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	poseidonbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

type Poseidon2Circuit struct {
	Input  []frontend.Variable
	Output []frontend.Variable `gnark:",public"`
	params circuitParams
}

type circuitParams struct {
	rf int
	rp int
	t  int
	id ecc.ID
}

func (c *Poseidon2Circuit) Define(api frontend.API) error {
	h, err := NewPoseidon2FromParameters(api, c.params.t, c.params.rf, c.params.rp)
	if err != nil {
		return fmt.Errorf("could not create poseidon2 hasher: %w", err)
	}
	if err := h.Permutation(c.Input); err != nil {
		return fmt.Errorf("could not apply permutation: %w", err)
	}
	for i := 0; i < len(c.Input); i++ {
		api.AssertIsEqual(c.Output[i], c.Input[i])
	}
	return nil
}

func TestPoseidon2(t *testing.T) {

	assert := test.NewAssert(t)

	params := make(map[ecc.ID]circuitParams)
	params[ecc.BN254] = circuitParams{rf: 8, rp: 56, t: 3, id: ecc.BN254}
	params[ecc.BLS12_381] = circuitParams{rf: 8, rp: 56, t: 3, id: ecc.BLS12_381}
	params[ecc.BLS12_377] = circuitParams{rf: 8, rp: 56, t: 2, id: ecc.BLS12_377}
	params[ecc.BW6_761] = circuitParams{rf: 8, rp: 56, t: 3, id: ecc.BW6_761}
	params[ecc.BW6_633] = circuitParams{rf: 8, rp: 56, t: 3, id: ecc.BW6_633}
	params[ecc.BLS24_315] = circuitParams{rf: 8, rp: 56, t: 3, id: ecc.BLS24_315}
	params[ecc.BLS24_317] = circuitParams{rf: 8, rp: 56, t: 3, id: ecc.BLS24_317}

	{
		var circuit, validWitness Poseidon2Circuit

		h := poseidonbn254.NewPermutation(
			params[ecc.BN254].t,
			params[ecc.BN254].rf,
			params[ecc.BN254].rp,
		)
		var in, out [3]frbn254.Element
		for i := 0; i < 3; i++ {
			in[i].SetRandom()
		}
		copy(out[:], in[:])
		err := h.Permutation(out[:])
		if err != nil {
			t.Fatal(err)
		}

		validWitness.Input = make([]frontend.Variable, 3)
		validWitness.Output = make([]frontend.Variable, 3)

		circuit.Input = make([]frontend.Variable, 3)
		circuit.Output = make([]frontend.Variable, 3)
		circuit.params = params[ecc.BN254]

		for i := 0; i < 3; i++ {
			validWitness.Input[i] = in[i].String()
			validWitness.Output[i] = out[i].String()
		}
		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithCurves(ecc.BN254))
	}
	{
		var circuit, validWitness Poseidon2Circuit

		h := poseidonbls12377.NewPermutation(
			params[ecc.BLS12_377].t,
			params[ecc.BLS12_377].rf,
			params[ecc.BLS12_377].rp,
		)
		var in, out [2]frbls12377.Element
		for i := 0; i < 2; i++ {
			in[i].SetRandom()
		}
		copy(out[:], in[:])
		err := h.Permutation(out[:])
		if err != nil {
			t.Fatal(err)
		}

		validWitness.Input = make([]frontend.Variable, 2)
		validWitness.Output = make([]frontend.Variable, 2)

		circuit.Input = make([]frontend.Variable, 2)
		circuit.Output = make([]frontend.Variable, 2)
		circuit.params = params[ecc.BLS12_377]

		for i := 0; i < 2; i++ {
			validWitness.Input[i] = in[i].String()
			validWitness.Output[i] = out[i].String()
		}
		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithCurves(ecc.BLS12_377))
	}
	{
		var circuit, validWitness Poseidon2Circuit

		h := poseidonbls12381.NewPermutation(
			params[ecc.BLS12_381].t,
			params[ecc.BLS12_381].rf,
			params[ecc.BLS12_381].rp,
		)
		var in, out [3]frbls12381.Element
		for i := 0; i < 3; i++ {
			in[i].SetRandom()
		}
		copy(out[:], in[:])
		err := h.Permutation(out[:])
		if err != nil {
			t.Fatal(err)
		}

		validWitness.Input = make([]frontend.Variable, 3)
		validWitness.Output = make([]frontend.Variable, 3)

		circuit.Input = make([]frontend.Variable, 3)
		circuit.Output = make([]frontend.Variable, 3)
		circuit.params = params[ecc.BLS12_381]

		for i := 0; i < 3; i++ {
			validWitness.Input[i] = in[i].String()
			validWitness.Output[i] = out[i].String()
		}
		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithCurves(ecc.BLS12_381))
	}
	{
		var circuit, validWitness Poseidon2Circuit

		h := poseidonbw6633.NewPermutation(
			params[ecc.BW6_633].t,
			params[ecc.BW6_633].rf,
			params[ecc.BW6_633].rp,
		)
		var in, out [3]frbw6633.Element
		for i := 0; i < 3; i++ {
			in[i].SetRandom()
		}
		copy(out[:], in[:])
		err := h.Permutation(out[:])
		if err != nil {
			t.Fatal(err)
		}

		validWitness.Input = make([]frontend.Variable, 3)
		validWitness.Output = make([]frontend.Variable, 3)

		circuit.Input = make([]frontend.Variable, 3)
		circuit.Output = make([]frontend.Variable, 3)
		circuit.params = params[ecc.BW6_633]

		for i := 0; i < 3; i++ {
			validWitness.Input[i] = in[i].String()
			validWitness.Output[i] = out[i].String()
		}
		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithCurves(ecc.BW6_633))
	}
	{
		var circuit, validWitness Poseidon2Circuit

		h := poseidonbw6633.NewPermutation(
			params[ecc.BW6_633].t,
			params[ecc.BW6_633].rf,
			params[ecc.BW6_633].rp,
		)
		var in, out [3]frbw6633.Element
		for i := 0; i < 3; i++ {
			in[i].SetRandom()
		}
		copy(out[:], in[:])
		err := h.Permutation(out[:])
		if err != nil {
			t.Fatal(err)
		}

		validWitness.Input = make([]frontend.Variable, 3)
		validWitness.Output = make([]frontend.Variable, 3)

		circuit.Input = make([]frontend.Variable, 3)
		circuit.Output = make([]frontend.Variable, 3)
		circuit.params = params[ecc.BW6_633]

		for i := 0; i < 3; i++ {
			validWitness.Input[i] = in[i].String()
			validWitness.Output[i] = out[i].String()
		}
		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithCurves(ecc.BW6_633))
	}
	{
		var circuit, validWitness Poseidon2Circuit

		h := poseidonbw6761.NewPermutation(
			params[ecc.BW6_761].t,
			params[ecc.BW6_761].rf,
			params[ecc.BW6_761].rp,
		)
		var in, out [3]frbw6761.Element
		for i := 0; i < 3; i++ {
			in[i].SetRandom()
		}
		copy(out[:], in[:])
		err := h.Permutation(out[:])
		if err != nil {
			t.Fatal(err)
		}

		validWitness.Input = make([]frontend.Variable, 3)
		validWitness.Output = make([]frontend.Variable, 3)

		circuit.Input = make([]frontend.Variable, 3)
		circuit.Output = make([]frontend.Variable, 3)
		circuit.params = params[ecc.BW6_761]

		for i := 0; i < 3; i++ {
			validWitness.Input[i] = in[i].String()
			validWitness.Output[i] = out[i].String()
		}
		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithCurves(ecc.BW6_761))
	}
	{
		var circuit, validWitness Poseidon2Circuit

		h := poseidonbls24315.NewPermutation(
			params[ecc.BLS24_315].t,
			params[ecc.BLS24_315].rf,
			params[ecc.BLS24_315].rp,
		)
		var in, out [3]frbls24315.Element
		for i := 0; i < 3; i++ {
			in[i].SetRandom()
		}
		copy(out[:], in[:])
		err := h.Permutation(out[:])
		if err != nil {
			t.Fatal(err)
		}

		validWitness.Input = make([]frontend.Variable, 3)
		validWitness.Output = make([]frontend.Variable, 3)

		circuit.Input = make([]frontend.Variable, 3)
		circuit.Output = make([]frontend.Variable, 3)
		circuit.params = params[ecc.BLS24_315]

		for i := 0; i < 3; i++ {
			validWitness.Input[i] = in[i].String()
			validWitness.Output[i] = out[i].String()
		}
		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithCurves(ecc.BLS24_315))
	}
	{
		var circuit, validWitness Poseidon2Circuit

		h := poseidonbls24317.NewPermutation(
			params[ecc.BLS24_317].t,
			params[ecc.BLS24_317].rf,
			params[ecc.BLS24_317].rp,
		)
		var in, out [3]frbls24317.Element
		for i := 0; i < 3; i++ {
			in[i].SetRandom()
		}
		copy(out[:], in[:])
		err := h.Permutation(out[:])
		if err != nil {
			t.Fatal(err)
		}

		validWitness.Input = make([]frontend.Variable, 3)
		validWitness.Output = make([]frontend.Variable, 3)

		circuit.Input = make([]frontend.Variable, 3)
		circuit.Output = make([]frontend.Variable, 3)
		circuit.params = params[ecc.BLS24_317]

		for i := 0; i < 3; i++ {
			validWitness.Input[i] = in[i].String()
			validWitness.Output[i] = out[i].String()
		}
		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithCurves(ecc.BLS24_317))
	}

}

// Poseidon2DefaultParamsCircuit is a test circuit using default parameters
type Poseidon2DefaultParamsCircuit struct {
	Input  []frontend.Variable
	Output []frontend.Variable `gnark:",public"`
}

func (c *Poseidon2DefaultParamsCircuit) Define(api frontend.API) error {
	h, err := NewPoseidon2(api)
	if err != nil {
		return fmt.Errorf("could not create poseidon2 hasher: %w", err)
	}
	if err := h.Permutation(c.Input); err != nil {
		return fmt.Errorf("could not apply permutation: %w", err)
	}
	for i := 0; i < len(c.Input); i++ {
		api.AssertIsEqual(c.Output[i], c.Input[i])
	}
	return nil
}

// TestPoseidon2_DefaultParams_BLS12377 tests the poseidon2 permutation with default parameters
// using the BLS12-377 curve. It verifies that the circuit produces the same output
// as the gnark-crypto reference implementation.
func TestPoseidon2_DefaultParams_BLS12377(t *testing.T) {
	assert := test.NewAssert(t)

	// Get default parameters to know the width
	params, err := GetDefaultParameters(ecc.BLS12_377)
	require.NoError(t, err)

	width := params.Width

	// Create gnark-crypto permutation with default parameters
	h := poseidonbls12377.NewDefaultPermutation()

	// Generate random input
	in := make([]frbls12377.Element, width)
	out := make([]frbls12377.Element, width)
	for i := 0; i < width; i++ {
		in[i].SetRandom()
		out[i].Set(&in[i])
	}

	// Compute expected output using gnark-crypto
	err = h.Permutation(out)
	require.NoError(t, err)

	// Set up circuit and witness
	var circuit, validWitness Poseidon2DefaultParamsCircuit
	circuit.Input = make([]frontend.Variable, width)
	circuit.Output = make([]frontend.Variable, width)
	validWitness.Input = make([]frontend.Variable, width)
	validWitness.Output = make([]frontend.Variable, width)

	for i := 0; i < width; i++ {
		validWitness.Input[i] = in[i].String()
		validWitness.Output[i] = out[i].String()
	}

	// Test the circuit
	assert.CheckCircuit(&circuit,
		test.WithValidAssignment(&validWitness),
		test.WithCurves(ecc.BLS12_377))
}

// BenchmarkPoseidon2_BLS12377 benchmarks the poseidon2 permutation circuit
// and reports the number of PLONK constraints.
func BenchmarkPoseidon2_BLS12377(b *testing.B) {
	// Get default parameters to know the width
	params, err := GetDefaultParameters(ecc.BLS12_377)
	if err != nil {
		b.Fatal(err)
	}

	width := params.Width

	// Set up circuit
	var circuit Poseidon2DefaultParamsCircuit
	circuit.Input = make([]frontend.Variable, width)
	circuit.Output = make([]frontend.Variable, width)

	// Compile the circuit using SCS builder (PLONK)
	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		b.Fatal(err)
	}

	// Report constraint count as a metric
	b.ReportMetric(float64(ccs.GetNbConstraints()), "constraints")
	b.ReportMetric(float64(ccs.GetNbSecretVariables()), "secret_vars")
	b.ReportMetric(float64(ccs.GetNbInternalVariables()), "internal_vars")

	// Log constraint info
	b.Logf("Poseidon2 BLS12-377 (width=%d, rf=%d, rp=%d): %d constraints",
		params.Width, params.NbFullRounds, params.NbPartialRounds, ccs.GetNbConstraints())

	// Benchmark the compilation
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &circuit)
	}
}
