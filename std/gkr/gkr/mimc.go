package gkr

import (
	"github.com/consensys/gnark/std/gkr/circuit"
	"github.com/consensys/gnark/std/gkr/hash"
)

// CreateMimcCircuit returns the GKR MIMC proving circuit
func CreateMimcCircuit() circuit.Circuit {
	nRounds := 91
	wiring := make([][]circuit.Wire, nRounds)

	for i := 0; i < nRounds-1; i++ {
		wiring[i] = []circuit.Wire{
			{L: 1, R: 0, O: 0, Gate: circuit.NewCipherGate(hash.Arks[i])},
			{L: 1, R: 0, O: 1, Gate: circuit.CopyGate{}},
		}
	}

	// And we don't copy the input in the last layer
	wiring[nRounds-1] = []circuit.Wire{
		{L: 1, R: 0, O: 0, Gate: circuit.NewCipherGate(hash.Arks[nRounds-1])},
	}

	return circuit.NewCircuit(wiring)
}

// CreateMimcCircuitBatch returns the GKR MIMC proving circuit
func CreateMimcCircuitBatch(batchSize int) []circuit.Circuit {
	nRounds := 91
	results := make([]circuit.Circuit, nRounds/batchSize)
	for i := range results {
		results[i] = CreateMimcCircuitBatchItem(i, batchSize)
	}
	return results
}

func CreateMimcCircuitBatchItem(batchIndex int, batchSize int) circuit.Circuit {
	wiring := make([][]circuit.Wire, batchSize)
	for i := batchIndex * batchSize; i < batchIndex*batchSize+batchSize-1; i++ {
		wiring[i-batchIndex*batchSize] = []circuit.Wire{
			{L: 1, R: 0, O: 0, Gate: circuit.NewCipherGate(hash.Arks[i])},
			{L: 1, R: 0, O: 1, Gate: circuit.CopyGate{}},
		}
	}
	// And we don't copy the input in the last layer
	wiring[batchSize-1] = []circuit.Wire{
		{L: 1, R: 0, O: 0, Gate: circuit.NewCipherGate(hash.Arks[batchIndex*batchSize+batchSize-1])},
	}
	return circuit.NewCircuit(wiring)
}
