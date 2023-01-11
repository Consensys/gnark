package gkr

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/gkr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
	"math/big"
)

// this module assumes that wire and instance indexes respect dependencies

type bn254AssignmentNoPtr [][]fr.Element //bn254AssignmentNoPtr is indexed wire first, instance second

// assumes assignmentVector is arranged wire first, instance second in order of solution
func bn254Solve(noPtr circuitDataNoPtr, typed bn254CircuitData, assignmentVector []*big.Int) bn254AssignmentNoPtr {
	circuit := noPtr.circuit
	nbInstances := circuit.nbInstances()
	offsets := circuit.assignmentOffsets()
	nbDepsResolved := make([]int, len(circuit))
	inputs := make([]fr.Element, noPtr.maxNIns)

	assignments := make(bn254AssignmentNoPtr, len(circuit))
	for i := range assignments {
		assignments[i] = make([]fr.Element, nbInstances)
	}

	for instanceI := 0; instanceI < nbInstances; instanceI++ {
		for wireI, wire := range circuit {
			if wire.isInput() {
				if nbDepsResolved[wireI] < len(wire.dependencies) && instanceI == wire.dependencies[nbDepsResolved[wireI]].inputInstance {
					dep := wire.dependencies[nbDepsResolved[wireI]]
					assignments[wireI][instanceI].Set(&assignments[dep.outputWire][dep.outputInstance])
					nbDepsResolved[wireI]++
				} else {
					assignments[wireI][instanceI].SetBigInt(assignmentVector[offsets[wireI]+instanceI-nbDepsResolved[wireI]])
				}
			} else {
				// assemble the inputs
				inputIndexes := noPtr.circuit[wireI].inputs
				for i, inputI := range inputIndexes {
					inputs[i].Set(&assignments[inputI][instanceI])
				}
				gate := typed.circuit[wireI].Gate
				assignments[wireI][instanceI] = gate.Evaluate(inputs[:len(inputIndexes)]...)
			}
		}
	}
	return assignments
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

	assignments := bn254Solve(data, res, ins)
	res.assignments = toBn254MapAssignment(res.circuit, assignments)
	bn254SetOutputValues(data.circuit, assignments, outs)

	return res, nil
}
