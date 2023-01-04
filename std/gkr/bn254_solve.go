package gkr

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/gkr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
	"math/big"
)

type solvingStatus byte

const (
	unsolved    solvingStatus = 0
	beingSolved               = 1
	solved                    = 2
)

type bn254Solver struct {
	assignment       [][]fr.Element //wire first, instance second
	assignmentVector []*big.Int
	d                *circuitData
	typed            *bn254CircuitData
	status           []solvingStatus
	offsets          []int // the index of an input wire's first given input in the AssignmentVector
}

// solve the i'th instance
func (s bn254Solver) solve(instance int) {
	if s.status[instance] == solved {
		return
	}
	if s.status[instance] == beingSolved {
		panic("circular dependency among instances")
	}
	//inputI := 0
	for j, J := range s.d.inputIndexes {
		offset := s.offsets[j] //[inputI]
		dependency := s.d.inputDependencies.get(j, instance)

		if dependency.OutputWireIndex == -1 { // no dependency
			s.assignment[J][instance].SetBigInt(s.assignmentVector[offset+instance])
			//inputI++
		} else {
			s.solve(dependency.OutputInstance)
			s.assignment[J][instance] = s.assignment[dependency.OutputWireIndex][dependency.OutputInstance]
		}
	}
	s.complete(instance) //TODO: This duplicates some of gkr.Complete
	s.status[instance] = solved
}

// complete computes the assignments of an instance given input assignments
func (s bn254Solver) complete(i int) {
	circuit := s.d.circuitInputsIndex
	ins := s.typed.memoryPool.Make(s.d.maxGateDegree) // TODO: Check
	for j := range circuit {
		n := len(circuit[j])
		for k := 0; k < n; k++ {
			ins[k] = s.assignment[circuit[j][k]][i]
		}

		s.assignment[j][i] = s.typed.circuit[j].Gate.Evaluate(ins[:n]...)
	}
	s.typed.memoryPool.Dump(ins)
}

func bn254Solve(circuitData *circuitData, typed *bn254CircuitData, assignmentVector []*big.Int) {
	solver := bn254Solver{
		assignment:       make([][]fr.Element, len(typed.circuit)),
		d:                circuitData,
		typed:            typed,
		status:           make([]solvingStatus, circuitData.nbInstances),
		offsets:          make([]int, len(typed.circuit)),
		assignmentVector: assignmentVector,
	}

	solver.offsets[0] = 0
	for j := 0; j+1 < len(typed.circuit); j++ {
		solver.offsets[j+1] = solver.offsets[j] + circuitData.nbInstances - circuitData.inputDependencies.nbDependencies(j)
	}

	for i := 0; i < circuitData.nbInstances; i++ {
		solver.solve(i)
	}

	typed.assignments = make(gkr.WireAssignment, len(typed.circuit))
	for i := range typed.circuit {
		typed.assignments[&typed.circuit[i]] = solver.assignment[i]
	}
}

func bn254SolveHint(data *circuitData, ins []*big.Int, outs []*big.Int) error {
	circuit := convertCircuit(data)
	typed := bn254CircuitData{
		memoryPool: polynomial.NewPool(256, 1<<11), // TODO: Get clever with limits
	}
	data.typed = typed

	bn254Solve(data, &typed, ins)

	outI := 0
	for i, w := range data.sorted {
		if w.IsOutput() {
			assignmentW := typed.assignments[&circuit[i]]
			for j := range assignmentW {
				assignmentW[outI].BigInt(outs[outI+j])
			}
			outI++
		}
	}

	return nil
}
