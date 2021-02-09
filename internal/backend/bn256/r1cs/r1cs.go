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

// Code generated by gnark DO NOT EDIT

package r1cs

import (
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/fxamacker/cbor/v2"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/internal/backend/ioutils"

	"github.com/consensys/gurvy"

	"github.com/consensys/gurvy/bn256/fr"
)

// R1CS decsribes a set of R1CS constraint
type R1CS struct {
	// Wires
	NbWires       uint64
	NbPublicWires uint64 // includes ONE wire
	NbSecretWires uint64
	Logs          []backend.LogEntry
	DebugInfo     []backend.LogEntry

	// Constraints
	NbConstraints   uint64 // total number of constraints
	NbCOConstraints uint64 // number of constraints that need to be solved, the first of the Constraints slice
	Constraints     []backend.R1C
	Coefficients    []fr.Element // R1C coefficients indexes point here
}

// GetNbConstraints returns the total number of constraints
func (r1cs *R1CS) GetNbConstraints() uint64 {
	return r1cs.NbConstraints
}

// GetNbWires returns the number of wires
func (r1cs *R1CS) GetNbWires() uint64 {
	return r1cs.NbWires
}

// GetNbPublicWires returns the number of public wires
func (r1cs *R1CS) GetNbPublicWires() uint64 {
	return r1cs.NbPublicWires
}

// GetNbSecretWires returns the number of public wires
func (r1cs *R1CS) GetNbSecretWires() uint64 {
	return r1cs.NbSecretWires
}

// SizeFrElement return the size (in byte) of a fr.Element
func (r1cs *R1CS) SizeFrElement() int {
	return fr.Limbs * 8
}

// GetNbCoefficients return the number of unique coefficients needed in the R1CS
func (r1cs *R1CS) GetNbCoefficients() int {
	return len(r1cs.Coefficients)
}

// GetCurveID returns curve ID as defined in gurvy (gurvy.BN256)
func (r1cs *R1CS) GetCurveID() gurvy.ID {
	return gurvy.BN256
}

// WriteTo encodes R1CS into provided io.Writer using cbor
func (r1cs *R1CS) WriteTo(w io.Writer) (int64, error) {
	_w := ioutils.WriterCounter{W: w} // wraps writer to count the bytes written
	encoder := cbor.NewEncoder(&_w)

	// encode our object
	err := encoder.Encode(r1cs)
	return _w.N, err
}

// ReadFrom attempts to decode R1CS from io.Reader using cbor
func (r1cs *R1CS) ReadFrom(r io.Reader) (int64, error) {
	decoder := cbor.NewDecoder(r)

	err := decoder.Decode(r1cs)
	return int64(decoder.NumBytesRead()), err
}

// IsSolved returns nil if given witness solves the R1CS and error otherwise
// this method wraps r1cs.Solve() and allocates r1cs.Solve() inputs
func (r1cs *R1CS) IsSolved(witness []fr.Element) error {
	a := make([]fr.Element, r1cs.NbConstraints)
	b := make([]fr.Element, r1cs.NbConstraints)
	c := make([]fr.Element, r1cs.NbConstraints)
	wireValues := make([]fr.Element, r1cs.NbWires)
	return r1cs.Solve(witness, a, b, c, wireValues)
}

// Solve sets all the wires and returns the a, b, c vectors.
// the r1cs system should have been compiled before. The entries in a, b, c are in Montgomery form.
// witness: contains the input variables
// a, b, c vectors: ab-c = hz
// wireValues =  [intermediateVariables | secretInputs | publicInputs]
func (r1cs *R1CS) Solve(witness []fr.Element, a, b, c, wireValues []fr.Element) error {
	if len(witness) != int(r1cs.NbPublicWires+r1cs.NbSecretWires) {
		return fmt.Errorf("invalid witness size, got %d, expected %d = %d (public) + %d (secret)", len(witness), int(r1cs.NbPublicWires+r1cs.NbSecretWires), r1cs.NbPublicWires, r1cs.NbSecretWires)
	}
	// compute the wires and the a, b, c polynomials
	if len(a) != int(r1cs.NbConstraints) || len(b) != int(r1cs.NbConstraints) || len(c) != int(r1cs.NbConstraints) || len(wireValues) != int(r1cs.NbWires) {
		return errors.New("invalid input size: len(a, b, c) == r1cs.NbConstraints and len(wireValues) == r1cs.NbWires")
	}
	privateStartIndex := int(r1cs.NbWires - r1cs.NbPublicWires - r1cs.NbSecretWires)
	// keep track of wire that have a value
	wireInstantiated := make([]bool, r1cs.NbWires)
	copy(wireValues[privateStartIndex:], witness) // TODO factorize
	for i := 0; i < len(witness); i++ {
		wireInstantiated[i+privateStartIndex] = true
	}

	// now that we know all inputs are set, defer log printing once all wireValues are computed
	// (or sooner, if a constraint is not satisfied)
	defer r1cs.printLogs(wireValues, wireInstantiated)

	// check if there is an inconsistant constraint
	var check fr.Element

	// Loop through computational constraints (the one wwe need to solve and compute a wire in)
	for i := 0; i < int(r1cs.NbCOConstraints); i++ {

		// solve the constraint, this will compute the missing wire of the gate
		r1cs.solveR1C(&r1cs.Constraints[i], wireInstantiated, wireValues)

		// at this stage we are guaranteed that a[i]*b[i]=c[i]
		// if not, it means there is a bug in the solver
		a[i], b[i], c[i] = instantiateR1C(&r1cs.Constraints[i], r1cs, wireValues)

		check.Mul(&a[i], &b[i])
		if !check.Equal(&c[i]) {
			panic("error solving r1c: " + a[i].String() + "*" + b[i].String() + "=" + c[i].String())
		}
	}

	// Loop through the assertions -- here all wireValues should be instantiated
	// if a[i] * b[i] != c[i]; it means the constraint is not satisfied
	for i := int(r1cs.NbCOConstraints); i < len(r1cs.Constraints); i++ {

		// A this stage we are not guaranteed that a[i+sizecg]*b[i+sizecg]=c[i+sizecg] because we only query the values (computed
		// at the previous step)
		a[i], b[i], c[i] = instantiateR1C(&r1cs.Constraints[i], r1cs, wireValues)

		// check that the constraint is satisfied
		check.Mul(&a[i], &b[i])
		if !check.Equal(&c[i]) {
			debugInfo := r1cs.DebugInfo[i-int(r1cs.NbCOConstraints)]
			debugInfoStr := r1cs.logValue(debugInfo, wireValues, wireInstantiated)
			return fmt.Errorf("%w: %s", backend.ErrUnsatisfiedConstraint, debugInfoStr)
		}
	}

	return nil
}

func (r1cs *R1CS) logValue(entry backend.LogEntry, wireValues []fr.Element, wireInstantiated []bool) string {
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

func (r1cs *R1CS) printLogs(wireValues []fr.Element, wireInstantiated []bool) {

	// for each log, resolve the wire values and print the log to stdout
	for i := 0; i < len(r1cs.Logs); i++ {
		fmt.Print(r1cs.logValue(r1cs.Logs[i], wireValues, wireInstantiated))
	}
}

// AddTerm returns res += (value * term.Coefficient)
func (r1cs *R1CS) AddTerm(res *fr.Element, t backend.Term, value fr.Element) *fr.Element {
	coeffValue := t.CoeffValue()
	switch coeffValue {
	case 1:
		return res.Add(res, &value)
	case -1:
		return res.Sub(res, &value)
	case 0:
		return res
	case 2:
		var buffer fr.Element
		buffer.Double(&value)
		return res.Add(res, &buffer)
	default:
		var buffer fr.Element
		buffer.Mul(&r1cs.Coefficients[t.CoeffID()], &value)
		return res.Add(res, &buffer)
	}
}

// mulWireByCoeff returns into.Mul(into, term.Coefficient)
func (r1cs *R1CS) mulWireByCoeff(res *fr.Element, t backend.Term) *fr.Element {
	coeffValue := t.CoeffValue()
	switch coeffValue {
	case 1:
		return res
	case -1:
		return res.Neg(res)
	case 0:
		return res.SetZero()
	case 2:
		return res.Double(res)
	default:
		return res.Mul(res, &r1cs.Coefficients[t.CoeffID()])
	}
}

// compute left, right, o part of a r1cs constraint
// this function is called when all the wires have been computed
// it instantiates the l, r o part of a R1C
func instantiateR1C(r *backend.R1C, r1cs *R1CS, wireValues []fr.Element) (a, b, c fr.Element) {

	for _, t := range r.L {
		r1cs.AddTerm(&a, t, wireValues[t.VariableID()])
	}

	for _, t := range r.R {
		r1cs.AddTerm(&b, t, wireValues[t.VariableID()])
	}

	for _, t := range r.O {
		r1cs.AddTerm(&c, t, wireValues[t.VariableID()])
	}

	return
}

// solveR1c computes a wire by solving a r1cs
// the function searches for the unset wire (either the unset wire is
// alone, or it can be computed without ambiguity using the other computed wires
// , eg when doing a binary decomposition: either way the missing wire can
// be computed without ambiguity because the r1cs is correctly ordered)
func (r1cs *R1CS) solveR1C(r *backend.R1C, wireInstantiated []bool, wireValues []fr.Element) {

	switch r.Solver {

	// in this case we solve a R1C by isolating the uncomputed wire
	case backend.SingleOutput:

		// the index of the non zero entry shows if L, R or O has an uninstantiated wire
		// the content is the ID of the wire non instantiated
		var loc uint8

		var a, b, c fr.Element
		var termToCompute backend.Term

		processTerm := func(t backend.Term, val *fr.Element, locValue uint8) {
			cID := t.VariableID()
			if wireInstantiated[cID] {
				r1cs.AddTerm(val, t, wireValues[cID])
			} else {
				if loc != 0 {
					panic("found more than one wire to instantiate")
				}
				termToCompute = t
				loc = locValue
			}
		}

		for _, t := range r.L {
			processTerm(t, &a, 1)
		}

		for _, t := range r.R {
			processTerm(t, &b, 2)
		}

		for _, t := range r.O {
			processTerm(t, &c, 3)
		}

		// ensure we found the unset wire
		if loc == 0 {
			// this wire may have been instantiated as part of moExpression already
			return
		}

		// we compute the wire value and instantiate it
		cID := termToCompute.VariableID()

		switch loc {
		case 1:
			if !b.IsZero() {
				wireValues[cID].Div(&c, &b).
					Sub(&wireValues[cID], &a)
				r1cs.mulWireByCoeff(&wireValues[cID], termToCompute)
			}
		case 2:
			if !a.IsZero() {
				wireValues[cID].Div(&c, &a).
					Sub(&wireValues[cID], &b)
				r1cs.mulWireByCoeff(&wireValues[cID], termToCompute)
			}
		case 3:
			wireValues[cID].Mul(&a, &b).
				Sub(&wireValues[cID], &c)
			r1cs.mulWireByCoeff(&wireValues[cID], termToCompute)
		}

		wireInstantiated[cID] = true

	// in the case the R1C is solved by directly computing the binary decomposition
	// of the variable
	case backend.BinaryDec:

		// the binary decomposition must be called on the non Mont form of the number
		var n fr.Element
		for _, t := range r.O {
			r1cs.AddTerm(&n, t, wireValues[t.VariableID()])
		}
		var bigN big.Int
		n.ToBigIntRegular(&bigN)

		nbBits := len(r.L)

		// cs.reduce() is non deterministic, so the variables are not sorted according to the bit position
		// i->value of the ithbit
		bitSlice := make([]uint, nbBits)

		// binary decomposition of n
		for i := 0; i < nbBits; i++ {
			bitSlice[i] = bigN.Bit(i)
		}

		// log of c>0 where c is a power of 2
		quickLog := func(bi big.Int) int {
			var bCopy, zero, checker big.Int
			bCopy.Set(&bi)
			res := 0
			for bCopy.Cmp(&zero) != 0 {
				bCopy.Rsh(&bCopy, 1)
				res++
			}
			res--
			checker.SetInt64(1)
			checker.Lsh(&checker, uint(res))
			// bi is not a power of 2, meaning it has been reduced mod r,
			// so the bit is 0. We return the index of last entry of BitSlice,
			// which is 0
			if checker.Cmp(&bi) != 0 {
				return nbBits - 1
			}
			return res
		}

		// affecting the correct bit to the correct variable
		for _, t := range r.L {
			cID := t.VariableID()
			coefID := t.CoeffID()
			coef := r1cs.Coefficients[coefID]
			var bcoef big.Int
			coef.ToBigIntRegular(&bcoef)
			ithBit := quickLog(bcoef)
			wireValues[cID].SetUint64(uint64(bitSlice[ithBit]))
			wireInstantiated[cID] = true
		}

	default:
		panic("unimplemented solving method")
	}
}
