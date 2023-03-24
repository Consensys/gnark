package gkr

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
)

func witnessGenerator(id ecc.ID, inputs [][]fr.Element, bN, batchSize, initialLength int) (results []fr.Element, startLength, endLength int) {
	nativeCircuits := CreateMimcCircuitBatch(batchSize)
	for i := range nativeCircuits {
		nativeCircuit := nativeCircuits[i]
		assignment := nativeCircuit.Assign(inputs, 1)
		outputs := assignment.Values[batchSize]
		prover := NewProver(nativeCircuit, assignment)
		proofg := prover.Prove(1)
		qInitialprime, _ := GetInitialQPrimeAndQAndInput(bN, 0, inputs[0])
		c := AllocateGKRMimcTestCircuitBatch(bN, i)
		c.Assign(proofg, inputs, outputs, qInitialprime)

		for i := range inputs {
			for j := range inputs[i] {
				// copy gate should stay with initial inputs
				// cipher gate needs to copy
				if j < len(inputs[i])/2 {
					inputs[i][j] = outputs[i][j]
				}
			}
		}

		w, err := frontend.NewWitness(&c, id.ScalarField())
		if err != nil {
			panic(err)
		}

		vectors := w.Vector().(fr.Vector)
		// first start len
		if startLength == 0 {
			startLength = initialLength - vectors.Len()*(7-i)
		}
		for j := initialLength - vectors.Len()*(7-i); j < initialLength-vectors.Len()*(6-i); j++ {
			results = append(results, vectors[j-initialLength+vectors.Len()*(7-i)])
		}
		endLength = initialLength - vectors.Len()*(6-i)
	}
	return results, startLength, endLength
}

func init() {
	cs.RegisterGKRWitnessGeneratorHandler(witnessGenerator)
}
