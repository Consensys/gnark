package bn254

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/gkr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
	genericGkr "github.com/consensys/gnark/std/gkr"
)

type solvingStatus byte

const (
	unsolved    solvingStatus = 0
	beingSolved               = 1
	solved                    = 2
)

type solver struct {
	assignment [][]fr.Element //wire first, instance second
	d          genericGkr.CircuitData
	circuit    gkr.Circuit
	status     []solvingStatus
	offsets    []int // per wire
	pool       polynomial.Pool
}

// solve the i'th instance
func (s solver) solve(i int) {
	if s.status[i] == solved {
		return
	}
	if s.status[i] == beingSolved {
		panic("circular dependency among instances")
	}
	inputI := 0
	for j, J := range s.d.InputIndexes {
		offset := s.offsets[inputI]
		dependencyWireIndex := s.d.InputDependencies[i][j].OutputWireIndex

		if dependencyWireIndex == -1 { // no dependency
			s.assignment[J][i].SetBigInt(s.d.AssignmentVector[offset+i])
			inputI++
		} else {
			dependencyInstance := s.d.InputDependencies[i][j].OutputInstance
			s.solve(dependencyInstance)
			s.assignment[J][i] = s.assignment[dependencyWireIndex][dependencyInstance]
		}
	}
	s.complete(i) //TODO: This duplicates some of gkr.Complete in gnark-crypto
	s.status[i] = solved
}

// complete computes the assignments of an instance given input assignments
func (s solver) complete(i int) {
	circuit := s.d.CircuitInputsIndex
	ins := s.pool.Make(s.d.MaxGateDegree)
	for j := range circuit {
		n := len(circuit[j])
		for k := 0; k < n; k++ {
			ins[k] = s.assignment[circuit[j][k]][i]
		}

		s.assignment[j][i] = s.circuit[j].Gate.Evaluate(ins[:n]...)
	}
	s.pool.Dump(ins)
}

func Solve(circuitData genericGkr.CircuitData, circuit gkr.Circuit) gkr.WireAssignment {
	solver := solver{
		assignment: make([][]fr.Element, len(circuit)),
		d:          circuitData,
		circuit:    circuit,
		status:     make([]solvingStatus, circuitData.NbInstances),
		offsets:    make([]int, len(circuit)),
	}

	solver.offsets[0] = 0
	for j := 0; j+1 < len(circuit); j++ {
		solver.offsets[j+1] = solver.offsets[j] + circuitData.NbInstances - circuitData.InputDependencies.NbDependencies(j)
	}

	for i := 0; i < circuitData.NbInstances; i++ {
		solver.solve(i)
	}

	res := make(gkr.WireAssignment, len(circuit))
	for i := range circuit {
		res[&circuit[i]] = solver.assignment[i]
	}
	return res
}
