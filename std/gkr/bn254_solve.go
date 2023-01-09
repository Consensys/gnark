package gkr

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/gkr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
	"math/big"
)

func bn254CreateAssignments(noPtr circuitDataNoPtr, assignmentVector []*big.Int) [][]fr.Element {
	circuit := noPtr.circuit
	nbInstances := noPtr.nbInstances()
	assignments := make([][]fr.Element, len(circuit))
	for wireI := range circuit {
		assignments[wireI] = make([]fr.Element, nbInstances)
		if circuit[wireI].isInput() {
			dependencies := circuit[wireI].dependencies
			dependencyI := 0
			for instanceI := range assignments[wireI] {
				if dependencyI < len(dependencies) && dependencies[dependencyI].inputInstance == instanceI {
					dependencyI++
				} else {
					assignments[wireI][instanceI].SetBigInt(assignmentVector[instanceI-dependencyI])
				}
			}
		}
	}
	return assignments
}

func bn254Solve(noPtr circuitDataNoPtr, typed bn254CircuitData, assignments [][]fr.Element) {

	inputs := make([]fr.Element, noPtr.maxNIns)
	for _, instanceI := range noPtr.sortedInstances {
		dependencyI := 0
		for wireI := range typed.circuit {
			dependencies := noPtr.circuit[wireI].dependencies
			if dependencyI < len(dependencies) && dependencies[dependencyI].inputInstance == instanceI {
				assignments[instanceI][wireI].Set(&assignments[dependencies[dependencyI].outputWire][dependencies[dependencyI].outputInstance])
				dependencyI++
			} else {
				// assemble the inputs
				inputIndexes := noPtr.circuit[wireI].inputs
				for i, inputI := range inputIndexes {
					inputs[i].Set(&assignments[inputI][instanceI])
				}
				gate := typed.circuit[wireI].Gate
				assignments[instanceI][wireI] = gate.Evaluate(inputs[:len(inputIndexes)]...)
			}
		}
	}
}

func toBn254MapAssignment(circuit gkr.Circuit, assignment [][]fr.Element) gkr.WireAssignment {
	res := make(gkr.WireAssignment, len(circuit))
	for i := range circuit {
		res[&circuit[i]] = assignment[i]
	}
	return res
}

func bn254SetOutputValues(circuit []wireNoPtr, assignments [][]fr.Element, outs []*big.Int) {
	outsI := 0
	for i := range circuit {
		if circuit[i].isOutput {
			for j := range assignments[i] {
				assignments[i][j].BigInt(outs[outsI])
			}
			outsI++
		}
	}
	// Check if outsI == len(outs)?
}

func bn254SolveHint(data circuitDataNoPtr, ins []*big.Int, outs []*big.Int) (bn254CircuitData, error) {

	res := bn254CircuitData{
		circuit:    convertCircuit(data.circuit),
		memoryPool: polynomial.NewPool(256, 1<<11), // TODO: Get clever with limits
	}

	assignments := bn254CreateAssignments(data, ins)
	bn254Solve(data, res, assignments)
	res.assignments = toBn254MapAssignment(res.circuit, assignments)
	bn254SetOutputValues(data.circuit, assignments, outs)

	return res, nil
}
