package gkr

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	curveGkr "github.com/consensys/gnark-crypto/ecc/bn254/fr/gkr"
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
	circuit          curveGkr.Circuit
	status           []solvingStatus
	offsets          []int // the index of an input wire's first given input in the AssignmentVector
	pool             polynomial.Pool
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
	s.complete(instance) //TODO: This duplicates some of curveGkr.Complete
	s.status[instance] = solved
}

// complete computes the assignments of an instance given input assignments
func (s bn254Solver) complete(i int) {
	circuit := s.d.circuitInputsIndex
	ins := s.pool.Make(s.d.maxGateDegree) // TODO: Check
	for j := range circuit {
		n := len(circuit[j])
		for k := 0; k < n; k++ {
			ins[k] = s.assignment[circuit[j][k]][i]
		}

		s.assignment[j][i] = s.circuit[j].Gate.Evaluate(ins[:n]...)
	}
	s.pool.Dump(ins)
}

func bn254Solve(circuitData *circuitData, circuit curveGkr.Circuit, assignmentVector []*big.Int) curveGkr.WireAssignment {
	solver := bn254Solver{
		assignment:       make([][]fr.Element, len(circuit)),
		d:                circuitData,
		circuit:          circuit,
		status:           make([]solvingStatus, circuitData.nbInstances),
		offsets:          make([]int, len(circuit)),
		assignmentVector: assignmentVector,
	}

	solver.offsets[0] = 0
	for j := 0; j+1 < len(circuit); j++ {
		solver.offsets[j+1] = solver.offsets[j] + circuitData.nbInstances - circuitData.inputDependencies.nbDependencies(j)
	}

	for i := 0; i < circuitData.nbInstances; i++ {
		solver.solve(i)
	}

	res := make(curveGkr.WireAssignment, len(circuit))
	for i := range circuit {
		res[&circuit[i]] = solver.assignment[i]
	}
	return res
}

func bn254SolveHint(data *circuitData, ins []*big.Int, outs []*big.Int) error {
	circuit := convertCircuit(data)
	assignments := bn254Solve(data, circuit, ins)

	outI := 0
	for i, w := range data.sorted {
		if w.IsOutput() {
			assignmentW := assignments[&circuit[i]]
			for j := range assignmentW {
				assignmentW[outI].BigInt(outs[outI+j])
			}
			outI++
		}
	}

	data.assignments = assignments

	return nil
}
