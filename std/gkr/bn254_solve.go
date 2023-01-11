package gkr

import (
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/gkr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/test_vector_utils"
	"github.com/consensys/gnark/std/utils/algo_utils"
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
		fmt.Println("instance", instanceI)
		for wireI, wire := range circuit {
			fmt.Print("\twire ", wireI, ": ")
			if wire.isInput() {
				fmt.Print("input.")
				if nbDepsResolved[wireI] < len(wire.dependencies) && instanceI == wire.dependencies[nbDepsResolved[wireI]].inputInstance {
					fmt.Print(" copying value from dependency")
					dep := wire.dependencies[nbDepsResolved[wireI]]
					assignments[wireI][instanceI].Set(&assignments[dep.outputWire][dep.outputInstance])
					nbDepsResolved[wireI]++
				} else {
					fmt.Print(" taking value from input")
					assignments[wireI][instanceI].SetBigInt(assignmentVector[offsets[wireI]+instanceI-nbDepsResolved[wireI]])
				}
			} else {
				fmt.Print("gated.")
				// assemble the inputs
				inputIndexes := noPtr.circuit[wireI].inputs
				for i, inputI := range inputIndexes {
					inputs[i].Set(&assignments[inputI][instanceI])
				}
				gate := typed.circuit[wireI].Gate
				assignments[wireI][instanceI] = gate.Evaluate(inputs[:len(inputIndexes)]...)
			}
			fmt.Println("\n\t\tresult: ", assignments[wireI][instanceI].Text(10))
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
				outsI++
			}
		}
	}
	// Check if outsI == len(outs)?
}

func bn254SolveHint(data circuitDataNoPtr, ins []*big.Int, outs []*big.Int) (bn254CircuitData, error) {

	res := bn254CircuitData{
		circuit:    bn254ConvertCircuit(data.circuit), // TODO: Take this out of here into the proving module
		memoryPool: polynomial.NewPool(256, 1<<11),    // TODO: Get clever with limits
	}

	assignments := bn254Solve(data, res, ins)
	res.assignments = toBn254MapAssignment(res.circuit, assignments)
	bn254SetOutputValues(data.circuit, assignments, outs)

	fmt.Println("assignment ", sliceSliceToString(assignments))
	fmt.Println("returning ", bigIntPtrSliceToString(outs))

	return res, nil
}

func bigIntPtrSliceToString(slice []*big.Int) []int64 {
	return algo_utils.Map(slice, func(e *big.Int) int64 {
		if !e.IsInt64() {
			panic("int too big")
		}
		return e.Int64()
	})
}

func sliceSliceToString(slice [][]fr.Element) string {
	printable := make([]interface{}, len(slice))
	for i, s := range slice {
		printable[i] = test_vector_utils.ElementSliceToInterfaceSlice(s)
	}
	res, err := json.Marshal(printable)
	if err != nil {
		panic(err.Error())
	}
	return string(res)
}

/*
func sliceToString(slice []fr.Element) string {
	printable := test_vector_utils.ElementSliceToInterfaceSlice(slice)
	res, err := json.Marshal(printable)
	if err != nil {
		panic(err.Error())
	}
	return string(res)
}
*/
