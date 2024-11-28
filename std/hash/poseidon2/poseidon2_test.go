package poseidon

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	frbls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/fr"
	poseidonbls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/fr/poseidon2"

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
	"github.com/consensys/gnark/test"
)

type Poseidon2Circuit struct {
	Input  []frontend.Variable
	Output []frontend.Variable `gnark:",public"`
	params circuitParams
}

type circuitParams struct {
	seed string
	rf   int
	rp   int
	t    int
	d    int
	id   ecc.ID
}

func (c *Poseidon2Circuit) Define(api frontend.API) error {
	h := NewHash(c.params.t, c.params.d, c.params.rf, c.params.rp, c.params.seed, c.params.id)
	h.Permutation(api, c.Input)
	for i := 0; i < len(c.Input); i++ {
		api.AssertIsEqual(c.Output[i], c.Input[i])
	}
	return nil
}

func TestPoseidon2(t *testing.T) {

	assert := test.NewAssert(t)

	params := make(map[ecc.ID]circuitParams)
	params[ecc.BN254] = circuitParams{seed: "seed", rf: 8, rp: 56, t: 3, d: 5, id: ecc.BN254}
	params[ecc.BLS12_381] = circuitParams{seed: "seed", rf: 8, rp: 56, t: 3, d: 5, id: ecc.BLS12_381}
	params[ecc.BLS12_377] = circuitParams{seed: "seed", rf: 8, rp: 56, t: 3, d: 17, id: ecc.BLS12_377}
	params[ecc.BW6_761] = circuitParams{seed: "seed", rf: 8, rp: 56, t: 3, d: 5, id: ecc.BW6_761}
	params[ecc.BW6_633] = circuitParams{seed: "seed", rf: 8, rp: 56, t: 3, d: 5, id: ecc.BW6_633}
	params[ecc.BLS24_315] = circuitParams{seed: "seed", rf: 8, rp: 56, t: 3, d: 5, id: ecc.BLS24_315}
	params[ecc.BLS24_317] = circuitParams{seed: "seed", rf: 8, rp: 56, t: 3, d: 7, id: ecc.BLS24_317}

	{
		var circuit, validWitness Poseidon2Circuit

		h := poseidonbn254.NewHash(
			params[ecc.BN254].t,
			params[ecc.BN254].rf,
			params[ecc.BN254].rp,
			"seed")
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

		h := poseidonbls12377.NewHash(
			params[ecc.BLS12_377].t,
			params[ecc.BLS12_377].rf,
			params[ecc.BLS12_377].rp,
			"seed")
		var in, out [3]frbls12377.Element
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
		circuit.params = params[ecc.BLS12_377]

		for i := 0; i < 3; i++ {
			validWitness.Input[i] = in[i].String()
			validWitness.Output[i] = out[i].String()
		}
		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithCurves(ecc.BLS12_377))
	}
	{
		var circuit, validWitness Poseidon2Circuit

		h := poseidonbls12381.NewHash(
			params[ecc.BLS12_381].t,
			params[ecc.BLS12_381].rf,
			params[ecc.BLS12_381].rp,
			"seed")
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

		h := poseidonbw6633.NewHash(
			params[ecc.BW6_633].t,
			params[ecc.BW6_633].rf,
			params[ecc.BW6_633].rp,
			"seed")
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

		h := poseidonbw6633.NewHash(
			params[ecc.BW6_633].t,
			params[ecc.BW6_633].rf,
			params[ecc.BW6_633].rp,
			"seed")
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

		h := poseidonbw6761.NewHash(
			params[ecc.BW6_761].t,
			params[ecc.BW6_761].rf,
			params[ecc.BW6_761].rp,
			"seed")
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

		h := poseidonbls24315.NewHash(
			params[ecc.BLS24_315].t,
			params[ecc.BLS24_315].rf,
			params[ecc.BLS24_315].rp,
			"seed")
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

		h := poseidonbls24317.NewHash(
			params[ecc.BLS24_317].t,
			params[ecc.BLS24_317].rf,
			params[ecc.BLS24_317].rp,
			"seed")
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
