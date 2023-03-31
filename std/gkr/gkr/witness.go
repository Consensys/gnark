package gkr

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/gkr/circuit"
	"sync"
)

func witnessGenerator(id ecc.ID, inputs [][]fr.Element, bN, batchSize, initialLength int, initialHash *fr.Element) (results []fr.Element, startLength, endLength int) {
	nativeCircuits := CreateMimcCircuitBatch(batchSize)
	provers := make([]Prover, len(nativeCircuits))
	slices := make([]GkrCircuitSlice, len(nativeCircuits))
	assignments := make([]circuit.Assignment, len(nativeCircuits))
	sliceResults := make([][]fr.Element, len(nativeCircuits))

	for i := range nativeCircuits {
		nativeCircuit := nativeCircuits[i]
		assignment := nativeCircuit.Assign(inputs, 10)
		outputs := assignment.Values[batchSize]
		prover := NewProver(nativeCircuit, assignment, initialHash)
		c := AllocateGKRMimcTestCircuitBatch(bN, i)

		provers[i] = prover
		slices[i] = c
		assignments[i] = assignment

		for i := range inputs {
			for j := range inputs[i] {
				// copy gate should stay with initial inputs
				// cipher gate needs to copy
				if j < len(inputs[i])/2 {
					inputs[i][j] = outputs[i][j]
				}
			}
		}
	}

	wg := sync.WaitGroup{}
	for i := range nativeCircuits {
		wg.Add(1)
		go func(i int) {
			prover := provers[i]
			c := slices[i]
			assignment := assignments[i]
			challenges := make([]string, 0)
			for i := len(c.Proof.SumcheckProofs) - 1; i >= 0; i-- {
				for j := range c.Proof.SumcheckProofs[i].HPolys {
					challenges = append(challenges, fmt.Sprintf("layers.%d.hpolys.%d", i, j))
				}
				challenges = append(challenges, fmt.Sprintf("layers.%d.next", i-1))
			}
			proofg := prover.Prove(10, challenges...)
			c.Assign(proofg, assignment.Values[0], assignment.Values[batchSize])

			w, err := frontend.NewWitness(&c, id.ScalarField())
			if err != nil {
				panic(err)
			}

			vectors := w.Vector().(fr.Vector)
			// first start len
			if i == 0 {
				startLength = initialLength - vectors.Len()*7
			}
			sliceResults[i] = vectors
			wg.Done()
			//for j := initialLength - vectors.Len()*(7-i); j < initialLength-vectors.Len()*(6-i); j++ {
			//	results = append(results, vectors[j-initialLength+vectors.Len()*(7-i)])
			//}
			endLength = initialLength
		}(i)
	}
	wg.Wait()
	for i := range sliceResults {
		results = append(results, sliceResults[i]...)
	}
	return results, startLength, endLength
}

func init() {
	cs.RegisterGKRWitnessGeneratorHandler(witnessGenerator)
}
