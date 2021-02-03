// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pcs

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gurvy"
	"github.com/consensys/gurvy/bn256/fr"
)

// CS represents a Plonk like circuit
// WIP does not contain logs for the moment
type CS struct {

	// Variables
	NbInternalVariables int
	NbPublicVariables   int
	NbSecretVariables   int

	// Constraints
	Constraints []backend.PlonkConstraint // list of Plonk constraints that yield an output (for example v3 == v1 * v2, return v3)
	Assertions  []backend.PlonkConstraint // list of Plonk constraints that yield no output (for example ensuring v1 == v2)

	// Logs (e.g. variables that have been printed using cs.Println)
	Logs []backend.LogEntry

	// Coefficients in the constraints
	Coeffs []fr.Element // list of unique coefficients.
}

// GetNbConstraints returns the number of constraints
func (plonkcs *CS) GetNbConstraints() uint64 {
	res := uint64(len(plonkcs.Constraints))
	return res
}

// GetNbWires returns the number of wires (internal)
func (plonkcs *CS) GetNbWires() uint64 {
	res := uint64(plonkcs.NbInternalVariables)
	return res
}

// GetNbCoefficients return the number of unique coefficients needed in the R1CS
func (plonkcs *CS) GetNbCoefficients() int {
	res := len(plonkcs.Coeffs)
	return res
}

// GetCurveID returns curve ID as defined in gurvy (gurvy.BN256)
func (plonkcs *CS) GetCurveID() gurvy.ID {
	return gurvy.BN256
}

// find unsolved variable
func findUnsolvedVariable(c backend.PlonkConstraint, wireInstantiated []bool) int {
	lro := -1 // 0 if the variable to solve is L, 1 if it's R, 2 if it's O
	if c.L.CoeffID() != 0 && !wireInstantiated[c.L.VariableID()] {
		lro = 0
	}
	if lro == -1 {
		if c.M[0].CoeffID() != 0 && !wireInstantiated[c.M[0].VariableID()] {
			lro = 0 // M[0] corresponds to L by default
		}
	}
	if lro == -1 {
		if c.R.CoeffID() != 0 && !wireInstantiated[c.R.VariableID()] {
			lro = 1
		}
	}
	if lro == -1 {
		if c.M[1].CoeffID() != 0 && !wireInstantiated[c.M[1].VariableID()] {
			lro = 1 // M[0] corresponds to L by default
		}
	}
	if lro == -1 { // only O remains
		lro = 2
	}
	return lro
}

// computeTerm computes coef*variable
func (plonkcs *CS) computeTerm(t backend.Term, solution []fr.Element) fr.Element {
	var res fr.Element
	res.Mul(&plonkcs.Coeffs[t.CoeffID()], &solution[t.VariableID()])
	return res
}

// solveConstraint solves c with the help of the slices wireInstantiated
// and solution. Those are used to find which variable remains to be solved,
// and the way of solving it (binary or single value). Once the variable(s)
// is solved, solution and wireInstantiated are updated.
func (plonkcs *CS) solveConstraint(c backend.PlonkConstraint, wireInstantiated []bool, solution []fr.Element) {

	switch c.Solver {
	case backend.SingleOutput:

		lro := findUnsolvedVariable(c, wireInstantiated)
		if lro == 0 { // we solve for L: u1L+u2R+u3LR+u4O+k=0 => L(u1+u3R)+u2R+u4O+k = 0

			var u1, u2, u3, den, num, v1, v2 fr.Element
			u3.Mul(&plonkcs.Coeffs[c.M[0].CoeffID()], &plonkcs.Coeffs[c.M[1].CoeffID()])
			u1.Set(&plonkcs.Coeffs[c.L.CoeffID()])
			u2.Set(&plonkcs.Coeffs[c.R.CoeffID()])
			den.Mul(&u3, &solution[c.R.VariableID()]).Add(&den, &u1)

			v1 = plonkcs.computeTerm(c.R, solution)
			v2 = plonkcs.computeTerm(c.O, solution)
			num.Add(&v1, &v2).Add(&num, &plonkcs.Coeffs[c.K])

			solution[c.L.VariableID()].Div(&num, &den).Neg(&solution[c.L.VariableID()])
			wireInstantiated[c.L.VariableID()] = true

		} else if lro == 1 { // we solve for R: u1L+u2R+u3LR+u4O+k=0 => R(u2+u3L)+u1L+u4O+k = 0

			var u1, u2, u3, den, num, v1, v2 fr.Element
			u3.Mul(&plonkcs.Coeffs[c.M[0].VariableID()], &plonkcs.Coeffs[c.M[1].VariableID()])
			u1.Set(&plonkcs.Coeffs[c.L.CoeffID()])
			u2.Set(&plonkcs.Coeffs[c.R.CoeffID()])
			den.Mul(&u3, &solution[c.L.VariableID()]).Add(&den, &u2)

			v1 = plonkcs.computeTerm(c.L, solution)
			v2 = plonkcs.computeTerm(c.O, solution)
			num.Add(&v1, &v2).Add(&num, &plonkcs.Coeffs[c.K])

			solution[c.L.VariableID()].Div(&num, &den).Neg(&solution[c.L.VariableID()])
			wireInstantiated[c.L.VariableID()] = true

		} else { // O we solve for O
			l := plonkcs.computeTerm(c.L, solution)
			r := plonkcs.computeTerm(c.R, solution)
			m := plonkcs.computeTerm(c.M[0], solution)
			_m := plonkcs.computeTerm(c.M[1], solution)
			m.Mul(&m, &_m)
			m.Add(&m, &l).Add(&m, &r).Add(&m, &plonkcs.Coeffs[c.K])
			m.Div(&m, &plonkcs.Coeffs[c.O.CoeffID()])

			solution[c.O.VariableID()].Neg(&m)
			wireInstantiated[c.O.VariableID()] = true
		}

	case backend.BinaryDec:
		// 2*L + R = O, computed as a = c/2, b = c%2
		var bo, bl, br, two big.Int
		o := solution[c.O.VariableID()]
		o.ToBigIntRegular(&bo)
		two.SetInt64(2)
		br.Mod(&bo, &two)
		bl.Rsh(&bo, 1)
		solution[c.L.VariableID()].SetBigInt(&bl)
		solution[c.R.VariableID()].SetBigInt(&br)
		wireInstantiated[c.L.VariableID()] = true
		wireInstantiated[c.R.VariableID()] = true

	default:
		panic("unimplemented solving method")
	}

}

// IsSolved returns nil if given witness solves the R1CS and error otherwise
// this method wraps r1cs.Solve() and allocates r1cs.Solve() inputs
func (plonkcs *CS) IsSolved(witness []fr.Element) error {
	_, err := plonkcs.Solve(witness)
	return err
}

// checkConstraint verifies that the constraint holds
func (plonkcs *CS) checkConstraint(c backend.PlonkConstraint, solution []fr.Element) error {
	var res, a, b, zero fr.Element
	res = plonkcs.computeTerm(c.L, solution)
	a = plonkcs.computeTerm(c.R, solution)
	res.Add(&res, &a)
	a = plonkcs.computeTerm(c.M[0], solution)
	b = plonkcs.computeTerm(c.M[1], solution)
	a.Mul(&a, &b)
	res.Add(&res, &a)
	a = plonkcs.computeTerm(c.O, solution)
	res.Add(&res, &a)
	a = plonkcs.Coeffs[c.K]
	res.Add(&res, &a)
	if !res.Equal(&zero) {
		return fmt.Errorf("%w", backend.ErrUnsatisfiedConstraint)
	}
	return nil
}

// Solve sets all the wires.
// wireValues =  [intermediateVariables | secretInputs | publicInputs]
// witness: contains the input variables
// it returns the full slice of wires
func (plonkcs *CS) Solve(witness []fr.Element) (solution []fr.Element, err error) {

	expectedWitnessSize := int(plonkcs.NbPublicVariables + plonkcs.NbSecretVariables)
	if len(witness) != expectedWitnessSize {
		return nil, fmt.Errorf(
			"invalid witness size, got %d, expected %d = %d (public) + %d (secret)",
			len(witness),
			expectedWitnessSize,
			plonkcs.NbPublicVariables,
			plonkcs.NbSecretVariables,
		)
	}

	// set the slices holding the solution and monitoring which variables have been solved
	privateStartIndex := plonkcs.NbInternalVariables
	nbVariables := plonkcs.NbInternalVariables + plonkcs.NbSecretVariables + plonkcs.NbPublicVariables
	solution = make([]fr.Element, nbVariables)
	wireInstantiated := make([]bool, nbVariables)

	// solution = [intermediateVariables | secretInputs | publicInputs] -> we fill secretInputs | publicInputs
	copy(solution[privateStartIndex:], witness)
	for i := 0; i < len(witness); i++ {
		wireInstantiated[i+privateStartIndex] = true
	}

	// defer log printing once all wireValues are computed
	defer plonkcs.printLogs(solution, wireInstantiated)

	// loop through the constraints to solve the variables
	for i := 0; i < len(plonkcs.Constraints); i++ {
		plonkcs.solveConstraint(plonkcs.Constraints[i], wireInstantiated, solution)
		err = plonkcs.checkConstraint(plonkcs.Constraints[i], solution)
		if err != nil {
			return nil, err
		}
	}

	// loop through the assertions and check consistency
	for i := 0; i < len(plonkcs.Assertions); i++ {
		err = plonkcs.checkConstraint(plonkcs.Assertions[i], solution)
		if err != nil {
			return nil, err
		}
	}

	// for i := 0; i < plonkcs.NbInternalVariables; i++ {
	// 	fmt.Printf("solution[%d]: %s\n", i, solution[i].String())
	// }
	// for i := plonkcs.NbInternalVariables; i < plonkcs.NbInternalVariables+plonkcs.NbSecretVariables; i++ {
	// 	fmt.Printf("solution[%d] (s): %s\n", i, solution[i].String())
	// }
	// for i := plonkcs.NbInternalVariables + plonkcs.NbSecretVariables; i < len(solution); i++ {
	// 	fmt.Printf("solution[%d] (p): %s\n", i, solution[i].String())
	// }

	return solution, nil

}

// TODO plonkcs is not used, remove it
func (plonkcs *CS) logValue(entry backend.LogEntry, wireValues []fr.Element, wireInstantiated []bool) string {
	var toResolve []interface{}
	for j := 0; j < len(entry.ToResolve); j++ {
		wireID := entry.ToResolve[j]
		if !wireInstantiated[wireID] {
			panic("wire values was not instantiated")
		}
		toResolve = append(toResolve, wireValues[wireID].String())
	}
	return fmt.Sprintf(entry.Format, toResolve...)
}

func (plonkcs *CS) printLogs(wireValues []fr.Element, wireInstantiated []bool) {

	// for each log, resolve the wire values and print the log to stdout
	for i := 0; i < len(plonkcs.Logs); i++ {
		fmt.Print(plonkcs.logValue(plonkcs.Logs[i], wireValues, wireInstantiated))
	}
}
