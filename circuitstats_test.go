package gnark

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
)

type circuitStats struct {
	nbConstraints, internal, secret, public int
}

var mStats map[string][backend.PLONK + 1][ecc.BW6_633 + 1]circuitStats

func checkStats(t *testing.T, circuitName string, nbConstraints, internal, secret, public int, curve ecc.ID, backendID backend.ID) {
	// fmt.Printf("{\ncircuit:=mStats[\"%s\"]\ncircuit[backend.%s][ecc.%s] = circuitStats{%d, %d, %d, %d};mStats[\"%s\"]=circuit;\n}\n",
	// 	circuitName, strings.ToUpper(backendID.String()), strings.ToUpper(curve.String()), nbConstraints, internal, secret, public, circuitName)
	// return
	if referenceStats, ok := mStats[circuitName]; !ok {
		t.Log("warning: no stats for circuit", circuitName)
	} else {
		ref := referenceStats[backendID][curve]
		if ref.nbConstraints != nbConstraints {
			t.Errorf("expected %d nbConstraints (reference), got %d. %s, %s, %s", ref.nbConstraints, nbConstraints, circuitName, backendID.String(), curve.String())
		}
		if ref.internal != internal {
			t.Errorf("expected %d internal (reference), got %d. %s, %s, %s", ref.internal, internal, circuitName, backendID.String(), curve.String())
		}
		if ref.secret != secret {
			t.Errorf("expected %d secret (reference), got %d. %s, %s, %s", ref.secret, secret, circuitName, backendID.String(), curve.String())
		}
		if ref.public != public {
			t.Errorf("expected %d public (reference), got %d. %s, %s, %s", ref.public, public, circuitName, backendID.String(), curve.String())
		}
	}
}

func init() {
	mStats = make(map[string][backend.PLONK + 1][ecc.BW6_633 + 1]circuitStats)
	{
		circuit := mStats["frombinary"]
		circuit[backend.GROTH16][ecc.BN254] = circuitStats{5, 0, 4, 2}
		mStats["frombinary"] = circuit
	}
	{
		circuit := mStats["frombinary"]
		circuit[backend.PLONK][ecc.BN254] = circuitStats{8, 3, 4, 1}
		mStats["frombinary"] = circuit
	}
	{
		circuit := mStats["frombinary"]
		circuit[backend.GROTH16][ecc.BLS12_377] = circuitStats{5, 0, 4, 2}
		mStats["frombinary"] = circuit
	}
	{
		circuit := mStats["frombinary"]
		circuit[backend.PLONK][ecc.BLS12_377] = circuitStats{8, 3, 4, 1}
		mStats["frombinary"] = circuit
	}
	{
		circuit := mStats["frombinary"]
		circuit[backend.GROTH16][ecc.BLS12_381] = circuitStats{5, 0, 4, 2}
		mStats["frombinary"] = circuit
	}
	{
		circuit := mStats["frombinary"]
		circuit[backend.PLONK][ecc.BLS12_381] = circuitStats{8, 3, 4, 1}
		mStats["frombinary"] = circuit
	}
	{
		circuit := mStats["frombinary"]
		circuit[backend.GROTH16][ecc.BW6_761] = circuitStats{5, 0, 4, 2}
		mStats["frombinary"] = circuit
	}
	{
		circuit := mStats["frombinary"]
		circuit[backend.PLONK][ecc.BW6_761] = circuitStats{8, 3, 4, 1}
		mStats["frombinary"] = circuit
	}
	{
		circuit := mStats["frombinary"]
		circuit[backend.GROTH16][ecc.BLS24_315] = circuitStats{5, 0, 4, 2}
		mStats["frombinary"] = circuit
	}
	{
		circuit := mStats["frombinary"]
		circuit[backend.PLONK][ecc.BLS24_315] = circuitStats{8, 3, 4, 1}
		mStats["frombinary"] = circuit
	}
	{
		circuit := mStats["neg"]
		circuit[backend.GROTH16][ecc.BN254] = circuitStats{2, 1, 1, 2}
		mStats["neg"] = circuit
	}
	{
		circuit := mStats["neg"]
		circuit[backend.PLONK][ecc.BN254] = circuitStats{3, 2, 1, 1}
		mStats["neg"] = circuit
	}
	{
		circuit := mStats["neg"]
		circuit[backend.GROTH16][ecc.BLS12_377] = circuitStats{2, 1, 1, 2}
		mStats["neg"] = circuit
	}
	{
		circuit := mStats["neg"]
		circuit[backend.PLONK][ecc.BLS12_377] = circuitStats{3, 2, 1, 1}
		mStats["neg"] = circuit
	}
	{
		circuit := mStats["neg"]
		circuit[backend.GROTH16][ecc.BLS12_381] = circuitStats{2, 1, 1, 2}
		mStats["neg"] = circuit
	}
	{
		circuit := mStats["neg"]
		circuit[backend.PLONK][ecc.BLS12_381] = circuitStats{3, 2, 1, 1}
		mStats["neg"] = circuit
	}
	{
		circuit := mStats["neg"]
		circuit[backend.GROTH16][ecc.BW6_761] = circuitStats{2, 1, 1, 2}
		mStats["neg"] = circuit
	}
	{
		circuit := mStats["neg"]
		circuit[backend.PLONK][ecc.BW6_761] = circuitStats{3, 2, 1, 1}
		mStats["neg"] = circuit
	}
	{
		circuit := mStats["neg"]
		circuit[backend.GROTH16][ecc.BLS24_315] = circuitStats{2, 1, 1, 2}
		mStats["neg"] = circuit
	}
	{
		circuit := mStats["neg"]
		circuit[backend.PLONK][ecc.BLS24_315] = circuitStats{3, 2, 1, 1}
		mStats["neg"] = circuit
	}
	{
		circuit := mStats["noComputationCircuit"]
		circuit[backend.GROTH16][ecc.BN254] = circuitStats{1, 0, 1, 2}
		mStats["noComputationCircuit"] = circuit
	}
	{
		circuit := mStats["noComputationCircuit"]
		circuit[backend.PLONK][ecc.BN254] = circuitStats{1, 0, 1, 1}
		mStats["noComputationCircuit"] = circuit
	}
	{
		circuit := mStats["noComputationCircuit"]
		circuit[backend.GROTH16][ecc.BLS12_377] = circuitStats{1, 0, 1, 2}
		mStats["noComputationCircuit"] = circuit
	}
	{
		circuit := mStats["noComputationCircuit"]
		circuit[backend.PLONK][ecc.BLS12_377] = circuitStats{1, 0, 1, 1}
		mStats["noComputationCircuit"] = circuit
	}
	{
		circuit := mStats["noComputationCircuit"]
		circuit[backend.GROTH16][ecc.BLS12_381] = circuitStats{1, 0, 1, 2}
		mStats["noComputationCircuit"] = circuit
	}
	{
		circuit := mStats["noComputationCircuit"]
		circuit[backend.PLONK][ecc.BLS12_381] = circuitStats{1, 0, 1, 1}
		mStats["noComputationCircuit"] = circuit
	}
	{
		circuit := mStats["noComputationCircuit"]
		circuit[backend.GROTH16][ecc.BW6_761] = circuitStats{1, 0, 1, 2}
		mStats["noComputationCircuit"] = circuit
	}
	{
		circuit := mStats["noComputationCircuit"]
		circuit[backend.PLONK][ecc.BW6_761] = circuitStats{1, 0, 1, 1}
		mStats["noComputationCircuit"] = circuit
	}
	{
		circuit := mStats["noComputationCircuit"]
		circuit[backend.GROTH16][ecc.BLS24_315] = circuitStats{1, 0, 1, 2}
		mStats["noComputationCircuit"] = circuit
	}
	{
		circuit := mStats["noComputationCircuit"]
		circuit[backend.PLONK][ecc.BLS24_315] = circuitStats{1, 0, 1, 1}
		mStats["noComputationCircuit"] = circuit
	}
	{
		circuit := mStats["range"]
		circuit[backend.GROTH16][ecc.BN254] = circuitStats{3078, 2562, 1, 3}
		mStats["range"] = circuit
	}
	{
		circuit := mStats["range"]
		circuit[backend.PLONK][ecc.BN254] = circuitStats{6141, 5625, 1, 2}
		mStats["range"] = circuit
	}
	{
		circuit := mStats["range"]
		circuit[backend.GROTH16][ecc.BLS12_377] = circuitStats{3078, 2562, 1, 3}
		mStats["range"] = circuit
	}
	{
		circuit := mStats["range"]
		circuit[backend.PLONK][ecc.BLS12_377] = circuitStats{6141, 5625, 1, 2}
		mStats["range"] = circuit
	}
	{
		circuit := mStats["range"]
		circuit[backend.GROTH16][ecc.BLS12_381] = circuitStats{3078, 2562, 1, 3}
		mStats["range"] = circuit
	}
	{
		circuit := mStats["range"]
		circuit[backend.PLONK][ecc.BLS12_381] = circuitStats{6141, 5625, 1, 2}
		mStats["range"] = circuit
	}
	{
		circuit := mStats["range"]
		circuit[backend.GROTH16][ecc.BW6_761] = circuitStats{3078, 2562, 1, 3}
		mStats["range"] = circuit
	}
	{
		circuit := mStats["range"]
		circuit[backend.PLONK][ecc.BW6_761] = circuitStats{6141, 5625, 1, 2}
		mStats["range"] = circuit
	}
	{
		circuit := mStats["range"]
		circuit[backend.GROTH16][ecc.BLS24_315] = circuitStats{3078, 2562, 1, 3}
		mStats["range"] = circuit
	}
	{
		circuit := mStats["range"]
		circuit[backend.PLONK][ecc.BLS24_315] = circuitStats{6141, 5625, 1, 2}
		mStats["range"] = circuit
	}
	{
		circuit := mStats["xor11"]
		circuit[backend.GROTH16][ecc.BN254] = circuitStats{4, 1, 2, 2}
		mStats["xor11"] = circuit
	}
	{
		circuit := mStats["xor11"]
		circuit[backend.PLONK][ecc.BN254] = circuitStats{6, 3, 2, 1}
		mStats["xor11"] = circuit
	}
	{
		circuit := mStats["xor11"]
		circuit[backend.GROTH16][ecc.BLS12_377] = circuitStats{4, 1, 2, 2}
		mStats["xor11"] = circuit
	}
	{
		circuit := mStats["xor11"]
		circuit[backend.PLONK][ecc.BLS12_377] = circuitStats{6, 3, 2, 1}
		mStats["xor11"] = circuit
	}
	{
		circuit := mStats["xor11"]
		circuit[backend.GROTH16][ecc.BLS12_381] = circuitStats{4, 1, 2, 2}
		mStats["xor11"] = circuit
	}
	{
		circuit := mStats["xor11"]
		circuit[backend.PLONK][ecc.BLS12_381] = circuitStats{6, 3, 2, 1}
		mStats["xor11"] = circuit
	}
	{
		circuit := mStats["xor11"]
		circuit[backend.GROTH16][ecc.BW6_761] = circuitStats{4, 1, 2, 2}
		mStats["xor11"] = circuit
	}
	{
		circuit := mStats["xor11"]
		circuit[backend.PLONK][ecc.BW6_761] = circuitStats{6, 3, 2, 1}
		mStats["xor11"] = circuit
	}
	{
		circuit := mStats["xor11"]
		circuit[backend.GROTH16][ecc.BLS24_315] = circuitStats{4, 1, 2, 2}
		mStats["xor11"] = circuit
	}
	{
		circuit := mStats["xor11"]
		circuit[backend.PLONK][ecc.BLS24_315] = circuitStats{6, 3, 2, 1}
		mStats["xor11"] = circuit
	}
	{
		circuit := mStats["assert_different"]
		circuit[backend.GROTH16][ecc.BN254] = circuitStats{2, 2, 1, 2}
		mStats["assert_different"] = circuit
	}
	{
		circuit := mStats["assert_different"]
		circuit[backend.PLONK][ecc.BN254] = circuitStats{3, 3, 1, 1}
		mStats["assert_different"] = circuit
	}
	{
		circuit := mStats["assert_different"]
		circuit[backend.GROTH16][ecc.BLS12_377] = circuitStats{2, 2, 1, 2}
		mStats["assert_different"] = circuit
	}
	{
		circuit := mStats["assert_different"]
		circuit[backend.PLONK][ecc.BLS12_377] = circuitStats{3, 3, 1, 1}
		mStats["assert_different"] = circuit
	}
	{
		circuit := mStats["assert_different"]
		circuit[backend.GROTH16][ecc.BLS12_381] = circuitStats{2, 2, 1, 2}
		mStats["assert_different"] = circuit
	}
	{
		circuit := mStats["assert_different"]
		circuit[backend.PLONK][ecc.BLS12_381] = circuitStats{3, 3, 1, 1}
		mStats["assert_different"] = circuit
	}
	{
		circuit := mStats["assert_different"]
		circuit[backend.GROTH16][ecc.BW6_761] = circuitStats{2, 2, 1, 2}
		mStats["assert_different"] = circuit
	}
	{
		circuit := mStats["assert_different"]
		circuit[backend.PLONK][ecc.BW6_761] = circuitStats{3, 3, 1, 1}
		mStats["assert_different"] = circuit
	}
	{
		circuit := mStats["assert_different"]
		circuit[backend.GROTH16][ecc.BLS24_315] = circuitStats{2, 2, 1, 2}
		mStats["assert_different"] = circuit
	}
	{
		circuit := mStats["assert_different"]
		circuit[backend.PLONK][ecc.BLS24_315] = circuitStats{3, 3, 1, 1}
		mStats["assert_different"] = circuit
	}
	{
		circuit := mStats["div"]
		circuit[backend.GROTH16][ecc.BN254] = circuitStats{3, 2, 2, 2}
		mStats["div"] = circuit
	}
	{
		circuit := mStats["div"]
		circuit[backend.PLONK][ecc.BN254] = circuitStats{3, 2, 2, 1}
		mStats["div"] = circuit
	}
	{
		circuit := mStats["div"]
		circuit[backend.GROTH16][ecc.BLS12_377] = circuitStats{3, 2, 2, 2}
		mStats["div"] = circuit
	}
	{
		circuit := mStats["div"]
		circuit[backend.PLONK][ecc.BLS12_377] = circuitStats{3, 2, 2, 1}
		mStats["div"] = circuit
	}
	{
		circuit := mStats["div"]
		circuit[backend.GROTH16][ecc.BLS12_381] = circuitStats{3, 2, 2, 2}
		mStats["div"] = circuit
	}
	{
		circuit := mStats["div"]
		circuit[backend.PLONK][ecc.BLS12_381] = circuitStats{3, 2, 2, 1}
		mStats["div"] = circuit
	}
	{
		circuit := mStats["div"]
		circuit[backend.GROTH16][ecc.BW6_761] = circuitStats{3, 2, 2, 2}
		mStats["div"] = circuit
	}
	{
		circuit := mStats["div"]
		circuit[backend.PLONK][ecc.BW6_761] = circuitStats{3, 2, 2, 1}
		mStats["div"] = circuit
	}
	{
		circuit := mStats["div"]
		circuit[backend.GROTH16][ecc.BLS24_315] = circuitStats{3, 2, 2, 2}
		mStats["div"] = circuit
	}
	{
		circuit := mStats["div"]
		circuit[backend.PLONK][ecc.BLS24_315] = circuitStats{3, 2, 2, 1}
		mStats["div"] = circuit
	}
	{
		circuit := mStats["isZero"]
		circuit[backend.GROTH16][ecc.BN254] = circuitStats{8, 4, 2, 1}
		mStats["isZero"] = circuit
	}
	{
		circuit := mStats["isZero"]
		circuit[backend.PLONK][ecc.BN254] = circuitStats{10, 6, 2, 0}
		mStats["isZero"] = circuit
	}
	{
		circuit := mStats["isZero"]
		circuit[backend.GROTH16][ecc.BLS12_377] = circuitStats{8, 4, 2, 1}
		mStats["isZero"] = circuit
	}
	{
		circuit := mStats["isZero"]
		circuit[backend.PLONK][ecc.BLS12_377] = circuitStats{10, 6, 2, 0}
		mStats["isZero"] = circuit
	}
	{
		circuit := mStats["isZero"]
		circuit[backend.GROTH16][ecc.BLS12_381] = circuitStats{8, 4, 2, 1}
		mStats["isZero"] = circuit
	}
	{
		circuit := mStats["isZero"]
		circuit[backend.PLONK][ecc.BLS12_381] = circuitStats{10, 6, 2, 0}
		mStats["isZero"] = circuit
	}
	{
		circuit := mStats["isZero"]
		circuit[backend.GROTH16][ecc.BW6_761] = circuitStats{8, 4, 2, 1}
		mStats["isZero"] = circuit
	}
	{
		circuit := mStats["isZero"]
		circuit[backend.PLONK][ecc.BW6_761] = circuitStats{10, 6, 2, 0}
		mStats["isZero"] = circuit
	}
	{
		circuit := mStats["isZero"]
		circuit[backend.GROTH16][ecc.BLS24_315] = circuitStats{8, 4, 2, 1}
		mStats["isZero"] = circuit
	}
	{
		circuit := mStats["isZero"]
		circuit[backend.PLONK][ecc.BLS24_315] = circuitStats{10, 6, 2, 0}
		mStats["isZero"] = circuit
	}
	{
		circuit := mStats["OR"]
		circuit[backend.GROTH16][ecc.BN254] = circuitStats{16, 4, 12, 1}
		mStats["OR"] = circuit
	}
	{
		circuit := mStats["OR"]
		circuit[backend.PLONK][ecc.BN254] = circuitStats{20, 8, 12, 0}
		mStats["OR"] = circuit
	}
	{
		circuit := mStats["OR"]
		circuit[backend.GROTH16][ecc.BLS12_377] = circuitStats{16, 4, 12, 1}
		mStats["OR"] = circuit
	}
	{
		circuit := mStats["OR"]
		circuit[backend.PLONK][ecc.BLS12_377] = circuitStats{20, 8, 12, 0}
		mStats["OR"] = circuit
	}
	{
		circuit := mStats["OR"]
		circuit[backend.GROTH16][ecc.BLS12_381] = circuitStats{16, 4, 12, 1}
		mStats["OR"] = circuit
	}
	{
		circuit := mStats["OR"]
		circuit[backend.PLONK][ecc.BLS12_381] = circuitStats{20, 8, 12, 0}
		mStats["OR"] = circuit
	}
	{
		circuit := mStats["OR"]
		circuit[backend.GROTH16][ecc.BW6_761] = circuitStats{16, 4, 12, 1}
		mStats["OR"] = circuit
	}
	{
		circuit := mStats["OR"]
		circuit[backend.PLONK][ecc.BW6_761] = circuitStats{20, 8, 12, 0}
		mStats["OR"] = circuit
	}
	{
		circuit := mStats["OR"]
		circuit[backend.GROTH16][ecc.BLS24_315] = circuitStats{16, 4, 12, 1}
		mStats["OR"] = circuit
	}
	{
		circuit := mStats["OR"]
		circuit[backend.PLONK][ecc.BLS24_315] = circuitStats{20, 8, 12, 0}
		mStats["OR"] = circuit
	}
	{
		circuit := mStats["xor01"]
		circuit[backend.GROTH16][ecc.BN254] = circuitStats{4, 1, 2, 2}
		mStats["xor01"] = circuit
	}
	{
		circuit := mStats["xor01"]
		circuit[backend.PLONK][ecc.BN254] = circuitStats{6, 3, 2, 1}
		mStats["xor01"] = circuit
	}
	{
		circuit := mStats["xor01"]
		circuit[backend.GROTH16][ecc.BLS12_377] = circuitStats{4, 1, 2, 2}
		mStats["xor01"] = circuit
	}
	{
		circuit := mStats["xor01"]
		circuit[backend.PLONK][ecc.BLS12_377] = circuitStats{6, 3, 2, 1}
		mStats["xor01"] = circuit
	}
	{
		circuit := mStats["xor01"]
		circuit[backend.GROTH16][ecc.BLS12_381] = circuitStats{4, 1, 2, 2}
		mStats["xor01"] = circuit
	}
	{
		circuit := mStats["xor01"]
		circuit[backend.PLONK][ecc.BLS12_381] = circuitStats{6, 3, 2, 1}
		mStats["xor01"] = circuit
	}
	{
		circuit := mStats["xor01"]
		circuit[backend.GROTH16][ecc.BW6_761] = circuitStats{4, 1, 2, 2}
		mStats["xor01"] = circuit
	}
	{
		circuit := mStats["xor01"]
		circuit[backend.PLONK][ecc.BW6_761] = circuitStats{6, 3, 2, 1}
		mStats["xor01"] = circuit
	}
	{
		circuit := mStats["xor01"]
		circuit[backend.GROTH16][ecc.BLS24_315] = circuitStats{4, 1, 2, 2}
		mStats["xor01"] = circuit
	}
	{
		circuit := mStats["xor01"]
		circuit[backend.PLONK][ecc.BLS24_315] = circuitStats{6, 3, 2, 1}
		mStats["xor01"] = circuit
	}
	{
		circuit := mStats["xor10"]
		circuit[backend.GROTH16][ecc.BN254] = circuitStats{4, 1, 2, 2}
		mStats["xor10"] = circuit
	}
	{
		circuit := mStats["xor10"]
		circuit[backend.PLONK][ecc.BN254] = circuitStats{6, 3, 2, 1}
		mStats["xor10"] = circuit
	}
	{
		circuit := mStats["xor10"]
		circuit[backend.GROTH16][ecc.BLS12_377] = circuitStats{4, 1, 2, 2}
		mStats["xor10"] = circuit
	}
	{
		circuit := mStats["xor10"]
		circuit[backend.PLONK][ecc.BLS12_377] = circuitStats{6, 3, 2, 1}
		mStats["xor10"] = circuit
	}
	{
		circuit := mStats["xor10"]
		circuit[backend.GROTH16][ecc.BLS12_381] = circuitStats{4, 1, 2, 2}
		mStats["xor10"] = circuit
	}
	{
		circuit := mStats["xor10"]
		circuit[backend.PLONK][ecc.BLS12_381] = circuitStats{6, 3, 2, 1}
		mStats["xor10"] = circuit
	}
	{
		circuit := mStats["xor10"]
		circuit[backend.GROTH16][ecc.BW6_761] = circuitStats{4, 1, 2, 2}
		mStats["xor10"] = circuit
	}
	{
		circuit := mStats["xor10"]
		circuit[backend.PLONK][ecc.BW6_761] = circuitStats{6, 3, 2, 1}
		mStats["xor10"] = circuit
	}
	{
		circuit := mStats["xor10"]
		circuit[backend.GROTH16][ecc.BLS24_315] = circuitStats{4, 1, 2, 2}
		mStats["xor10"] = circuit
	}
	{
		circuit := mStats["xor10"]
		circuit[backend.PLONK][ecc.BLS24_315] = circuitStats{6, 3, 2, 1}
		mStats["xor10"] = circuit
	}
	{
		circuit := mStats["determinism"]
		circuit[backend.GROTH16][ecc.BN254] = circuitStats{2, 1, 5, 2}
		mStats["determinism"] = circuit
	}
	{
		circuit := mStats["determinism"]
		circuit[backend.PLONK][ecc.BN254] = circuitStats{10, 9, 5, 1}
		mStats["determinism"] = circuit
	}
	{
		circuit := mStats["determinism"]
		circuit[backend.GROTH16][ecc.BLS12_377] = circuitStats{2, 1, 5, 2}
		mStats["determinism"] = circuit
	}
	{
		circuit := mStats["determinism"]
		circuit[backend.PLONK][ecc.BLS12_377] = circuitStats{10, 9, 5, 1}
		mStats["determinism"] = circuit
	}
	{
		circuit := mStats["determinism"]
		circuit[backend.GROTH16][ecc.BLS12_381] = circuitStats{2, 1, 5, 2}
		mStats["determinism"] = circuit
	}
	{
		circuit := mStats["determinism"]
		circuit[backend.PLONK][ecc.BLS12_381] = circuitStats{10, 9, 5, 1}
		mStats["determinism"] = circuit
	}
	{
		circuit := mStats["determinism"]
		circuit[backend.GROTH16][ecc.BW6_761] = circuitStats{2, 1, 5, 2}
		mStats["determinism"] = circuit
	}
	{
		circuit := mStats["determinism"]
		circuit[backend.PLONK][ecc.BW6_761] = circuitStats{10, 9, 5, 1}
		mStats["determinism"] = circuit
	}
	{
		circuit := mStats["determinism"]
		circuit[backend.GROTH16][ecc.BLS24_315] = circuitStats{2, 1, 5, 2}
		mStats["determinism"] = circuit
	}
	{
		circuit := mStats["determinism"]
		circuit[backend.PLONK][ecc.BLS24_315] = circuitStats{10, 9, 5, 1}
		mStats["determinism"] = circuit
	}
	{
		circuit := mStats["inv"]
		circuit[backend.GROTH16][ecc.BN254] = circuitStats{4, 3, 3, 1}
		mStats["inv"] = circuit
	}
	{
		circuit := mStats["inv"]
		circuit[backend.PLONK][ecc.BN254] = circuitStats{4, 3, 3, 0}
		mStats["inv"] = circuit
	}
	{
		circuit := mStats["inv"]
		circuit[backend.GROTH16][ecc.BLS12_377] = circuitStats{4, 3, 3, 1}
		mStats["inv"] = circuit
	}
	{
		circuit := mStats["inv"]
		circuit[backend.PLONK][ecc.BLS12_377] = circuitStats{4, 3, 3, 0}
		mStats["inv"] = circuit
	}
	{
		circuit := mStats["inv"]
		circuit[backend.GROTH16][ecc.BLS12_381] = circuitStats{4, 3, 3, 1}
		mStats["inv"] = circuit
	}
	{
		circuit := mStats["inv"]
		circuit[backend.PLONK][ecc.BLS12_381] = circuitStats{4, 3, 3, 0}
		mStats["inv"] = circuit
	}
	{
		circuit := mStats["inv"]
		circuit[backend.GROTH16][ecc.BW6_761] = circuitStats{4, 3, 3, 1}
		mStats["inv"] = circuit
	}
	{
		circuit := mStats["inv"]
		circuit[backend.PLONK][ecc.BW6_761] = circuitStats{4, 3, 3, 0}
		mStats["inv"] = circuit
	}
	{
		circuit := mStats["inv"]
		circuit[backend.GROTH16][ecc.BLS24_315] = circuitStats{4, 3, 3, 1}
		mStats["inv"] = circuit
	}
	{
		circuit := mStats["inv"]
		circuit[backend.PLONK][ecc.BLS24_315] = circuitStats{4, 3, 3, 0}
		mStats["inv"] = circuit
	}
	{
		circuit := mStats["expo"]
		circuit[backend.GROTH16][ecc.BN254] = circuitStats{18, 16, 2, 2}
		mStats["expo"] = circuit
	}
	{
		circuit := mStats["expo"]
		circuit[backend.PLONK][ecc.BN254] = circuitStats{29, 27, 2, 1}
		mStats["expo"] = circuit
	}
	{
		circuit := mStats["expo"]
		circuit[backend.GROTH16][ecc.BLS12_377] = circuitStats{18, 16, 2, 2}
		mStats["expo"] = circuit
	}
	{
		circuit := mStats["expo"]
		circuit[backend.PLONK][ecc.BLS12_377] = circuitStats{29, 27, 2, 1}
		mStats["expo"] = circuit
	}
	{
		circuit := mStats["expo"]
		circuit[backend.GROTH16][ecc.BLS12_381] = circuitStats{18, 16, 2, 2}
		mStats["expo"] = circuit
	}
	{
		circuit := mStats["expo"]
		circuit[backend.PLONK][ecc.BLS12_381] = circuitStats{29, 27, 2, 1}
		mStats["expo"] = circuit
	}
	{
		circuit := mStats["expo"]
		circuit[backend.GROTH16][ecc.BW6_761] = circuitStats{18, 16, 2, 2}
		mStats["expo"] = circuit
	}
	{
		circuit := mStats["expo"]
		circuit[backend.PLONK][ecc.BW6_761] = circuitStats{29, 27, 2, 1}
		mStats["expo"] = circuit
	}
	{
		circuit := mStats["expo"]
		circuit[backend.GROTH16][ecc.BLS24_315] = circuitStats{18, 16, 2, 2}
		mStats["expo"] = circuit
	}
	{
		circuit := mStats["expo"]
		circuit[backend.PLONK][ecc.BLS24_315] = circuitStats{29, 27, 2, 1}
		mStats["expo"] = circuit
	}
	{
		circuit := mStats["range_constant"]
		circuit[backend.GROTH16][ecc.BN254] = circuitStats{1028, 520, 1, 2}
		mStats["range_constant"] = circuit
	}
	{
		circuit := mStats["range_constant"]
		circuit[backend.PLONK][ecc.BN254] = circuitStats{1549, 1041, 1, 1}
		mStats["range_constant"] = circuit
	}
	{
		circuit := mStats["range_constant"]
		circuit[backend.GROTH16][ecc.BLS12_377] = circuitStats{1028, 520, 1, 2}
		mStats["range_constant"] = circuit
	}
	{
		circuit := mStats["range_constant"]
		circuit[backend.PLONK][ecc.BLS12_377] = circuitStats{1549, 1041, 1, 1}
		mStats["range_constant"] = circuit
	}
	{
		circuit := mStats["range_constant"]
		circuit[backend.GROTH16][ecc.BLS12_381] = circuitStats{1028, 520, 1, 2}
		mStats["range_constant"] = circuit
	}
	{
		circuit := mStats["range_constant"]
		circuit[backend.PLONK][ecc.BLS12_381] = circuitStats{1549, 1041, 1, 1}
		mStats["range_constant"] = circuit
	}
	{
		circuit := mStats["range_constant"]
		circuit[backend.GROTH16][ecc.BW6_761] = circuitStats{1028, 520, 1, 2}
		mStats["range_constant"] = circuit
	}
	{
		circuit := mStats["range_constant"]
		circuit[backend.PLONK][ecc.BW6_761] = circuitStats{1549, 1041, 1, 1}
		mStats["range_constant"] = circuit
	}
	{
		circuit := mStats["range_constant"]
		circuit[backend.GROTH16][ecc.BLS24_315] = circuitStats{1028, 520, 1, 2}
		mStats["range_constant"] = circuit
	}
	{
		circuit := mStats["range_constant"]
		circuit[backend.PLONK][ecc.BLS24_315] = circuitStats{1549, 1041, 1, 1}
		mStats["range_constant"] = circuit
	}
	{
		circuit := mStats["xor00"]
		circuit[backend.GROTH16][ecc.BN254] = circuitStats{4, 1, 2, 2}
		mStats["xor00"] = circuit
	}
	{
		circuit := mStats["xor00"]
		circuit[backend.PLONK][ecc.BN254] = circuitStats{6, 3, 2, 1}
		mStats["xor00"] = circuit
	}
	{
		circuit := mStats["xor00"]
		circuit[backend.GROTH16][ecc.BLS12_377] = circuitStats{4, 1, 2, 2}
		mStats["xor00"] = circuit
	}
	{
		circuit := mStats["xor00"]
		circuit[backend.PLONK][ecc.BLS12_377] = circuitStats{6, 3, 2, 1}
		mStats["xor00"] = circuit
	}
	{
		circuit := mStats["xor00"]
		circuit[backend.GROTH16][ecc.BLS12_381] = circuitStats{4, 1, 2, 2}
		mStats["xor00"] = circuit
	}
	{
		circuit := mStats["xor00"]
		circuit[backend.PLONK][ecc.BLS12_381] = circuitStats{6, 3, 2, 1}
		mStats["xor00"] = circuit
	}
	{
		circuit := mStats["xor00"]
		circuit[backend.GROTH16][ecc.BW6_761] = circuitStats{4, 1, 2, 2}
		mStats["xor00"] = circuit
	}
	{
		circuit := mStats["xor00"]
		circuit[backend.PLONK][ecc.BW6_761] = circuitStats{6, 3, 2, 1}
		mStats["xor00"] = circuit
	}
	{
		circuit := mStats["xor00"]
		circuit[backend.GROTH16][ecc.BLS24_315] = circuitStats{4, 1, 2, 2}
		mStats["xor00"] = circuit
	}
	{
		circuit := mStats["xor00"]
		circuit[backend.PLONK][ecc.BLS24_315] = circuitStats{6, 3, 2, 1}
		mStats["xor00"] = circuit
	}
	{
		circuit := mStats["AND"]
		circuit[backend.GROTH16][ecc.BN254] = circuitStats{16, 4, 12, 1}
		mStats["AND"] = circuit
	}
	{
		circuit := mStats["AND"]
		circuit[backend.PLONK][ecc.BN254] = circuitStats{16, 4, 12, 0}
		mStats["AND"] = circuit
	}
	{
		circuit := mStats["AND"]
		circuit[backend.GROTH16][ecc.BLS12_377] = circuitStats{16, 4, 12, 1}
		mStats["AND"] = circuit
	}
	{
		circuit := mStats["AND"]
		circuit[backend.PLONK][ecc.BLS12_377] = circuitStats{16, 4, 12, 0}
		mStats["AND"] = circuit
	}
	{
		circuit := mStats["AND"]
		circuit[backend.GROTH16][ecc.BLS12_381] = circuitStats{16, 4, 12, 1}
		mStats["AND"] = circuit
	}
	{
		circuit := mStats["AND"]
		circuit[backend.PLONK][ecc.BLS12_381] = circuitStats{16, 4, 12, 0}
		mStats["AND"] = circuit
	}
	{
		circuit := mStats["AND"]
		circuit[backend.GROTH16][ecc.BW6_761] = circuitStats{16, 4, 12, 1}
		mStats["AND"] = circuit
	}
	{
		circuit := mStats["AND"]
		circuit[backend.PLONK][ecc.BW6_761] = circuitStats{16, 4, 12, 0}
		mStats["AND"] = circuit
	}
	{
		circuit := mStats["AND"]
		circuit[backend.GROTH16][ecc.BLS24_315] = circuitStats{16, 4, 12, 1}
		mStats["AND"] = circuit
	}
	{
		circuit := mStats["AND"]
		circuit[backend.PLONK][ecc.BLS24_315] = circuitStats{16, 4, 12, 0}
		mStats["AND"] = circuit
	}
	{
		circuit := mStats["assert_equal"]
		circuit[backend.GROTH16][ecc.BN254] = circuitStats{2, 0, 1, 2}
		mStats["assert_equal"] = circuit
	}
	{
		circuit := mStats["assert_equal"]
		circuit[backend.PLONK][ecc.BN254] = circuitStats{3, 1, 1, 1}
		mStats["assert_equal"] = circuit
	}
	{
		circuit := mStats["assert_equal"]
		circuit[backend.GROTH16][ecc.BLS12_377] = circuitStats{2, 0, 1, 2}
		mStats["assert_equal"] = circuit
	}
	{
		circuit := mStats["assert_equal"]
		circuit[backend.PLONK][ecc.BLS12_377] = circuitStats{3, 1, 1, 1}
		mStats["assert_equal"] = circuit
	}
	{
		circuit := mStats["assert_equal"]
		circuit[backend.GROTH16][ecc.BLS12_381] = circuitStats{2, 0, 1, 2}
		mStats["assert_equal"] = circuit
	}
	{
		circuit := mStats["assert_equal"]
		circuit[backend.PLONK][ecc.BLS12_381] = circuitStats{3, 1, 1, 1}
		mStats["assert_equal"] = circuit
	}
	{
		circuit := mStats["assert_equal"]
		circuit[backend.GROTH16][ecc.BW6_761] = circuitStats{2, 0, 1, 2}
		mStats["assert_equal"] = circuit
	}
	{
		circuit := mStats["assert_equal"]
		circuit[backend.PLONK][ecc.BW6_761] = circuitStats{3, 1, 1, 1}
		mStats["assert_equal"] = circuit
	}
	{
		circuit := mStats["assert_equal"]
		circuit[backend.GROTH16][ecc.BLS24_315] = circuitStats{2, 0, 1, 2}
		mStats["assert_equal"] = circuit
	}
	{
		circuit := mStats["assert_equal"]
		circuit[backend.PLONK][ecc.BLS24_315] = circuitStats{3, 1, 1, 1}
		mStats["assert_equal"] = circuit
	}
}
