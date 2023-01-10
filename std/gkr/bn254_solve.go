package gkr

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/gkr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
	"golang.org/x/exp/slices"
	"math/big"
)

type bn254AssignmentNoPtr [][]fr.Element //bn254AssignmentNoPtr is indexed instance first, wire second

func bn254CreateAssignments(noPtr circuitDataNoPtr, assignmentVector []*big.Int) bn254AssignmentNoPtr {
	circuit := noPtr.circuit
	nbInstances := noPtr.nbInstances()

	/*offsets := make([]int, len(circuit)+1) // offsets shows where the assignments for each wire begin
	for i := range circuit {
		nbAssignments := 0
		if circuit[i].isInput() {
			nbAssignments = nbInstances - len(circuit[i].dependencies)
		}
		offsets[i+1] = offsets[i] + nbAssignments
	}*/
	dependenciesI := make([]int, len(circuit))
	assignments := make([][]fr.Element, nbInstances) // Many short arrays are probably less efficient than a few long arrays. A point against the current instance-first indexing

	for instanceI := 0; instanceI < nbInstances; instanceI++ {
		assignments[instanceI] = make([]fr.Element, len(circuit))
		for wireI := range circuit {
			if circuit[wireI].isInput() {
				dependencies := circuit[wireI].dependencies
				dependencyI := dependenciesI[wireI]
				if dependencyI < len(dependencies) && dependencies[dependencyI].inputInstance == instanceI {
					dependenciesI[wireI]++
				} else {
					assignments[instanceI][wireI].SetBigInt(assignmentVector[0])
					assignmentVector = assignmentVector[1:]
				}
			}
		}
	}
	return assignments
}

func bn254Solve(noPtr circuitDataNoPtr, typed bn254CircuitData, assignments bn254AssignmentNoPtr) {

	inputs := make([]fr.Element, noPtr.maxNIns)
	for _, instanceI := range noPtr.sortedInstances {
		for wireI := range typed.circuit {
			if noPtr.circuit[wireI].isInput() {
				dependencies := noPtr.circuit[wireI].dependencies
				dependencyI, dependent := slices.BinarySearchFunc(dependencies, inputDependency{inputInstance: instanceI},
					func(a, b inputDependency) int {
						if a.inputInstance > b.inputInstance {
							return 1
						} else if a.inputInstance == b.inputInstance {
							return 0
						}
						return -1
					})
				if dependent {
					assignments[instanceI][wireI].Set(&assignments[dependencies[dependencyI].outputInstance][dependencies[dependencyI].outputWire])
				}
			} else {
				// assemble the inputs
				inputIndexes := noPtr.circuit[wireI].inputs
				for i, inputI := range inputIndexes {
					inputs[i].Set(&assignments[instanceI][inputI])
				}
				gate := typed.circuit[wireI].Gate
				assignments[instanceI][wireI] = gate.Evaluate(inputs[:len(inputIndexes)]...)
			}
		}
	}
}

func toBn254MapAssignment(circuit gkr.Circuit, assignment bn254AssignmentNoPtr) gkr.WireAssignment {
	res := make(gkr.WireAssignment, len(circuit))
	for i := range circuit {
		res[&circuit[i]] = assignment[i]
	}
	return res
}

func bn254SetOutputValues(circuit []wireNoPtr, assignments bn254AssignmentNoPtr, outs []*big.Int) {
	outsI := 0
	for i := range circuit {
		if circuit[i].isOutput() {
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
		circuit:    bn254ConvertCircuit(data.circuit),
		memoryPool: polynomial.NewPool(256, 1<<11), // TODO: Get clever with limits
	}

	assignments := bn254CreateAssignments(data, ins)
	bn254Solve(data, res, assignments)
	res.assignments = toBn254MapAssignment(res.circuit, assignments)
	bn254SetOutputValues(data.circuit, assignments, outs)

	return res, nil
}
