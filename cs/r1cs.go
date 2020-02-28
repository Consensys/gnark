/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cs

import (
	"fmt"
	"strconv"

	"github.com/consensys/gnark/cs/internal/curve"
	"github.com/consensys/gnark/internal/debug"
)

/*
	Algorithm to build the r1cs system
	----------------------------------

	Loop though all the Constraints

		If the constraint has a single wire, it must have not been visited (rule a).
			The constraint is computational only if:
				- its single wire is an unconstrained input
				- it is not an input (and has not been visited but it's automatically the case)
				In this case, put the constraint in the computationalConstraint list
			Split the other expressions on the constraint in structural Constraints (pure and inpure)
		else split the constraint into structural r1cs Constraints

	Then the wires are numbered:
	loop through the computational Constraints: (in the computational graph, 1 constraint <-> 1 wire)
		- the label of the current constraint's output wire is the current index
	loop through the private wires
		- the label of the wire is the current index in the wireTracker
	loop through the public wires
		- the label of the wire is the current index in the wireTracker

	At the end, the public wires are the last ones in the wireTracker.


	Compilation
	-----------

	Compling a r1cs system consists in ordering the computational Constraints, so
	that computing the wires result in running through the ordered computational Constraints.
	To compute the computational graph, one needs a 'root' wire if there are more than just input
	wires. There can be several root wires, hence several computational graph.

*/

// method to solve a r1cs
type solvingMethod int

const (
	singleOutput solvingMethod = iota
	binaryDec
)

// lwTerm lightweight version of a term, no pointers
type lwTerm struct {
	ID    int64         // index of the constraint used to compute this wire
	Coeff curve.Element // coefficient by which the wire is multiplied
}

// lwLinearExp lightweight version of linear expression
type lwLinearExp []lwTerm

// r1c used to compute the wires (wo pointers)
type r1c struct {
	L      lwLinearExp
	R      lwLinearExp
	O      lwLinearExp
	Solver solvingMethod
}

// OneWire is the assignment label / name used for the constant wire one
const OneWire = "ONE_WIRE"

// R1CS decsribes a set of R1CS constraint
type R1CS struct {

	//wiretracker = [..PrivateInputsStartIndex-1] || [PrivateInputsStartIndex..PublicInputsStartIndex-1] || [PublicInputsStartIndex...]. The label of the wire is the index in the wire tracker
	PrivateInputsStartIndex int
	PublicInputsStartIndex  int

	// index i = wire with index i
	WireTracker []wire

	// Actual description of the constraint system
	GraphOrdering      []int64 // order in which to compute the computational graph
	ComputationalGraph []r1c   // Constraints to instantiate the variables
	Constraints        []r1c   // Constraints left from the computational graph
}

// helpers for post ordering
type stack []int64

func newStack() stack {
	return make([]int64, 0)
}

func (s stack) push(elmt int64) stack {
	s = append(s, elmt)
	return s
}

func (s stack) pop() (stack, int64) {
	elmt := s[len(s)-1]
	s = s[:len(s)-1]
	return s, elmt
}

func (s stack) isEmpty() bool {
	return len(s) == 0
}

// NewR1CS builds a R1CS from a system of Constraints
func NewR1CS(circuit *CS) *R1CS {

	r1cs := &R1CS{}

	// those 3 slices store all the wires
	// those are needed to number the wires, before putting them in the wire tracker
	var wireTracker, publicInputs, privateInputs []*wire

	// we keep track of wire that are "unconstrained" to ignore them at step 2
	// unconstrained wires can be inputs or wires issued from a MOConstraint (like the i-th bit of a binary decomposition)
	ignoredConstraints := make(map[uint64]struct{})

	// step 1: fills the tmpwiretracker, public/private inputs tracker
	for k, c := range circuit.Constraints {

		// if it's a user input
		if c.outputWire.isUserInput() {
			if c.outputWire.IsPrivate {
				privateInputs = append(privateInputs, c.outputWire)
			} else {
				publicInputs = append(publicInputs, c.outputWire)
			}
		} else {
			wireTracker = append(wireTracker, c.outputWire)
			// it is a unconstrained wire, we will ignore the constraint on step2
			if len(c.expressions) == 0 {
				ignoredConstraints[k] = struct{}{}
			}
		}
	}

	// store the keys of the constraint map to loop in the same order at step 4
	var keys []uint64

	// to keep track of the number of constraints
	var ccCounter int64

	// step 2: Run through all the constraints, set the constraintID (except the ignored ones, corresponding to inputs), consume the wires
	for k, c := range circuit.Constraints {

		// we ignore monCosntraints in this loop
		if _, ok := ignoredConstraints[k]; ok {
			continue
		}
		keys = append(keys, k)

		if !c.outputWire.isUserInput() {
			c.expressions[0].consumeWires()       // only the first exp is consumed, the other might containt root of the computational graph
			c.outputWire.ConstraintID = ccCounter // tells the output wire from which constraint it is computed
			ccCounter++
		}
	}
	for _, c := range circuit.MOConstraints {
		c.setConstraintID(ccCounter)
		c.consumeWires() // tells the output wires from which constraint they are computed
		ccCounter++
	}

	// step 3: number the wires and fill the wire tracker
	for i, w := range wireTracker {
		w.WireID = int64(i)
		r1cs.WireTracker = append(r1cs.WireTracker, *w)
	}
	r1cs.PrivateInputsStartIndex = len(r1cs.WireTracker)
	// if we have no private inputs, we set the start index at -1
	if len(privateInputs) == 0 {
		r1cs.PrivateInputsStartIndex = -1
	}
	for i, w := range privateInputs {
		w.WireID = int64(i + r1cs.PrivateInputsStartIndex)
		r1cs.WireTracker = append(r1cs.WireTracker, *w)
	}
	r1cs.PublicInputsStartIndex = len(r1cs.WireTracker)
	for i, w := range publicInputs {
		w.WireID = int64(i + r1cs.PublicInputsStartIndex)
		r1cs.WireTracker = append(r1cs.WireTracker, *w)
	}

	// step 4: Now the attributes of all wires are synced up, no need of pointers anymore
	// We can split the constraints into r1cs
	for _, k := range keys {

		constraint := circuit.Constraints[k]

		batchR1CS := constraint.toR1CS(circuit)

		if constraint.outputWire.isUserInput() {
			r1cs.Constraints = append(r1cs.Constraints, batchR1CS...)
		} else {
			r1cs.ComputationalGraph = append(r1cs.ComputationalGraph, batchR1CS[0])

			if len(batchR1CS) > 1 {
				r1cs.Constraints = append(r1cs.Constraints, batchR1CS[1:]...)
			}
		}
	}
	for _, c := range circuit.MOConstraints {
		batchR1CS := c.toR1CS(circuit.Constraints[0].outputWire)
		r1cs.ComputationalGraph = append(r1cs.ComputationalGraph, batchR1CS)
	}
	for _, c := range circuit.NOConstraints {
		batchR1CS := c.toR1CS(circuit.Constraints[0].outputWire)
		r1cs.Constraints = append(r1cs.Constraints, batchR1CS)
	}

	// Keeps track of the visited constraints, useful to build the computational graph
	constraintTracker := make([]bool, len(r1cs.ComputationalGraph))

	// compile
	r1cs.compile(constraintTracker)
	//r1cs.compile()

	return r1cs
}

// NbConstraints returns the number of Constraints
func (r1cs *R1CS) NbConstraints() int {
	return len(r1cs.ComputationalGraph) + len(r1cs.Constraints)
}

// NbPublicInputs returns the number of Public inputs (without the ONEWIRE)
func (r1cs *R1CS) NbPublicInputs() int {
	w := len(r1cs.WireTracker)
	return w - r1cs.PublicInputsStartIndex - 1
}

// NbPrivateInputs returns the number of Private inputs
func (r1cs *R1CS) NbPrivateInputs() int {
	if r1cs.PrivateInputsStartIndex == -1 {
		return 0
	}
	return r1cs.PublicInputsStartIndex - r1cs.PrivateInputsStartIndex
}

// findRootConstraints find the root wires for post ordering
func (r1cs *R1CS) findRootConstraints() []int64 {
	var res []int64
	for _, w := range r1cs.WireTracker {
		if !w.IsConsumed {
			res = append(res, w.ConstraintID)
		}
	}
	return res
}

// compile order the gates (= computational Constraints)
func (r1cs *R1CS) compile(visited []bool) {

	rootConstraint := r1cs.findRootConstraints()

	for _, i := range rootConstraint {
		r1cs.postOrder(i, visited)
	}
}

// postOrder post order traversal the computational graph; i is the index of the constraint currently visited
// linear in the number of constraints (with visit each constraint once)
func (r1cs *R1CS) postOrder(constraintID int64, visited []bool) {

	// stackIn stores the unsivisted/non input wires in the order we
	// visit them
	stackIn := newStack()

	// stackOut stores the constraint in the order we should visit them to
	// solve them
	stackOut := newStack()

	node := constraintID

	stackIn = stackIn.push(node)

	for !stackIn.isEmpty() {

		// pick the node to update it, and put it back in the stack
		stackIn, node = stackIn.pop()
		stackIn = stackIn.push(node)

		// found is true when:
		// - a parent of the visited constraint has not been visited
		// - the parent not visited is not an input
		found := true

		// while an unvisited constraint is found, rewind the its subgraph, exploring
		// first the left wires, then the right, then the output of the constraint
		for found {

			constraint := r1cs.ComputationalGraph[node]

			found = false

			// explore left wires
			for _, l := range constraint.L {
				n := r1cs.WireTracker[l.ID].ConstraintID
				if n != -1 {
					if n != node && !visited[n] {
						stackIn = stackIn.push(n)
						found = true
						node = n
					}
				}
			}

			// explore right wires
			if !found {
				for _, r := range constraint.R {
					n := r1cs.WireTracker[r.ID].ConstraintID
					if n != -1 {
						if n != node && !visited[n] {
							stackIn = stackIn.push(n)
							found = true
							node = n
						}
					}
				}
			}

			// explore output wires
			if !found {
				for _, o := range constraint.O {
					n := r1cs.WireTracker[o.ID].ConstraintID
					if n != -1 {
						if n != node && !visited[n] {
							stackIn = stackIn.push(n)
							found = true
							node = n
						}
					}
				}
			}
			// if here found is false, we rewinded as much as possible a subgraph
			// the constraint directly above the visited/input wires will be pushed
			// in stackout
		}

		// once we are here we either we bumped on only input data or only
		// constraints that have been visited
		// so we pop the constraint from the stackin and push it in the stack out
		stackIn, node = stackIn.pop()
		stackOut = stackOut.push(node)

		// the constraint is tagged to not exploring its subgraph twice
		visited[node] = true
	}

	r1cs.GraphOrdering = append(r1cs.GraphOrdering, stackOut...)

}

// compute left, right, o part of a r1cs constraint
// this function is called when all the wires have been computed
// it instantiates the l, r o part of a r1c
func (r r1c) instantiate(r1cs *R1CS) (a, b, c curve.Element) {

	var tmp curve.Element

	for _, t := range r.L {
		debug.Assert(len(r1cs.WireTracker) > int(t.ID), "trying to access out of bound wire in wiretracker")
		tmp.Mul(&t.Coeff, &r1cs.WireTracker[t.ID].Value)
		a.Add(&a, &tmp)
	}

	for _, t := range r.R {
		debug.Assert(len(r1cs.WireTracker) > int(t.ID), "trying to access out of bound wire in wiretracker")
		tmp.Mul(&t.Coeff, &r1cs.WireTracker[t.ID].Value)
		b.Add(&b, &tmp)
	}

	for _, t := range r.O {
		debug.Assert(len(r1cs.WireTracker) > int(t.ID), "trying to access out of bound wire in wiretracker")
		tmp.Mul(&t.Coeff, &r1cs.WireTracker[t.ID].Value)
		c.Add(&c, &tmp)
	}

	return
}

// solveR1c computes a wire by solving a r1cs
// the function searches for the unset wire (either the unset wire is
// alone, or it can be computed without ambiguity using the other computed wires
// , eg when doing a binary decomposition: either way the missing wire can
// be computed without ambiguity because the r1cs is correctly ordered)
func (r r1c) solveR1c(wireTracker []wire) {

	switch r.Solver {

	// in this case we solve a r1c by isolating the uncomputed wire
	case singleOutput:

		// the index of the non zero entry shows if L, R or O has an uninstantiated wire
		// the content is the ID of the wire non instantiated
		location := [3]int64{-1, -1, -1}

		var tmp, a, b, c, backupCoeff curve.Element

		for _, t := range r.L {
			if wireTracker[t.ID].IsInstantiated {
				tmp.Mul(&t.Coeff, &wireTracker[t.ID].Value)
				a.Add(&a, &tmp)
			} else {
				backupCoeff.Set(&t.Coeff)
				location[0] = t.ID
			}
		}

		for _, t := range r.R {
			if wireTracker[t.ID].IsInstantiated {
				tmp.Mul(&t.Coeff, &wireTracker[t.ID].Value)
				b.Add(&b, &tmp)
			} else {
				backupCoeff.Set(&t.Coeff)
				location[1] = t.ID
			}
		}

		for _, t := range r.O {
			if wireTracker[t.ID].IsInstantiated {
				tmp.Mul(&t.Coeff, &wireTracker[t.ID].Value)
				c.Add(&c, &tmp)
			} else {
				backupCoeff.Set(&t.Coeff)
				location[2] = t.ID
			}
		}

		var zero curve.Element

		if location[0] != -1 {
			id := location[0]
			if b.Equal(&zero) {
				wireTracker[id].Value.SetZero()
			} else {
				wireTracker[id].Value.Div(&c, &b).
					Sub(&wireTracker[id].Value, &a).
					Mul(&wireTracker[id].Value, &backupCoeff)
			}
			wireTracker[id].IsInstantiated = true
		} else if location[1] != -1 {
			id := location[1]
			if a.Equal(&zero) {
				wireTracker[id].Value.SetZero()
			} else {
				wireTracker[id].Value.Div(&c, &a).
					Sub(&wireTracker[id].Value, &b).
					Mul(&wireTracker[id].Value, &backupCoeff)
			}
			wireTracker[id].IsInstantiated = true
		} else if location[2] != -1 {
			id := location[2]
			wireTracker[id].Value.Mul(&a, &b).
				Sub(&wireTracker[id].Value, &c).
				Mul(&wireTracker[id].Value, &backupCoeff)
			wireTracker[id].IsInstantiated = true
		}

	// in the case the r1c is solved by directly computing the binary decomposition
	// of the variable
	case binaryDec:

		// the binary decomposition must be called on the non Mont form of the number
		n := wireTracker[r.O[0].ID].Value.ToRegular()
		nbBits := len(r.L)

		// binary decomposition of n
		var i, j int
		for i*64 < nbBits {
			j = 0
			for j < 64 && i*64+j < len(r.L) {
				ithbit := (n[i] >> uint(j)) & 1
				if !wireTracker[r.L[i*64+j].ID].IsInstantiated {
					wireTracker[r.L[i*64+j].ID].Value.SetUint64(ithbit)
					wireTracker[r.L[i*64+j].ID].IsInstantiated = true
				}
				j++
			}
			i++
		}
	default:
		panic("unimplemented solving method")
	}
}

func nextPowerOfTwo(n uint) uint {
	p := uint(1)
	if (n & (n - 1)) == 0 {
		return n
	}
	for p < n {
		p <<= 1
	}
	return p
}

// Solve sets all the wires and returns the a, b, c vectors.
// the r1cs system should have been compiled before. The entries in a, b, c are in Montgomery form.
// assignment: map[string]value: contains the input variables
// a, b, c vectors: ab-c = hz
func (r1cs *R1CS) Solve(assignment map[string]Assignment) (a, b, c []curve.Element, err error) {

	// compute the wires and the a, b, c polynomials
	sizecg := len(r1cs.ComputationalGraph)
	sizec := len(r1cs.Constraints)

	lenVectors := sizecg + sizec
	cardinality := nextPowerOfTwo(uint(lenVectors))

	a = make([]curve.Element, lenVectors, cardinality)
	b = make([]curve.Element, lenVectors, cardinality)
	c = make([]curve.Element, lenVectors, cardinality)

	// instantiate the public/ private inputs
	instantiateInputs := func(start, end int, visibility Visibility) error {
		for i := start; i < end; i++ {
			w := &r1cs.WireTracker[i]

			if w.Name == OneWire {
				w.Value.SetOne()
				w.IsInstantiated = true
			} else {
				if val, ok := assignment[w.Name]; ok {
					if visibility == Secret && val.IsPublic || visibility == Public && !val.IsPublic {
						return fmt.Errorf("%q: %w", w.Name, ErrInputVisiblity)
					}
					w.Value.Set(&val.Value)
					w.IsInstantiated = true
				} else {
					return fmt.Errorf("%q: %w", w.Name, ErrInputNotSet)
				}
			}
		}
		return nil
	}
	// instantiate private inputs
	if r1cs.PrivateInputsStartIndex != -1 {
		if err := instantiateInputs(r1cs.PrivateInputsStartIndex, r1cs.PublicInputsStartIndex, Secret); err != nil {
			return nil, nil, nil, err
		}
	}
	// instantiate public inputs
	if err := instantiateInputs(r1cs.PublicInputsStartIndex, len(r1cs.WireTracker), Public); err != nil {
		return nil, nil, nil, err
	}

	// check if there is an inconsistant constraint
	var check curve.Element

	// Set the wires by looping through the computational graph
	for _, i := range r1cs.GraphOrdering {

		// r1cs.ComputationalGraph[i] contains exactly one uncomputed wire (due
		// to the graph being correctly ordered), we solve it
		r1cs.ComputationalGraph[i].solveR1c(r1cs.WireTracker)

		// We are not fully guaranteed that a[i]*b[i]=c[i]
		// for instance if we do a binary decomposition, and one of the bits is an input
		// an inconsistancy should be deteceted at this stage (the input bit will not be computed)
		a[i], b[i], c[i] = r1cs.ComputationalGraph[i].instantiate(r1cs)
		check.Mul(&a[i], &b[i])
		if !check.Equal(&c[i]) {
			invalidA := a[i]
			invalidB := b[i]
			invalidC := c[i]

			return a, b, c, fmt.Errorf("%w: %q * %q != %q", ErrUnsatisfiedConstraint,
				invalidA.String(),
				invalidB.String(),
				invalidC.String())
		}
	}

	// From here, all the wires are computed. To query the Value of
	// a wire, just look at the Value field of a wire.

	// Loop through the other Constraints
	for i, r1c := range r1cs.Constraints {

		// A this stage we are not guaranteed that a[i+sizecg]*b[i+sizecg]=c[i+sizecg] because we only query the values (computed
		// at the previous step)
		a[i+sizecg], b[i+sizecg], c[i+sizecg] = r1c.instantiate(r1cs)

		// check that the constraint is satisfied
		check.Mul(&a[i+sizecg], &b[i+sizecg])
		if !check.Equal(&c[i+sizecg]) {
			invalidA := a[i+sizecg]
			invalidB := b[i+sizecg]
			invalidC := c[i+sizecg]

			return a, b, c, fmt.Errorf("%w: %q * %q != %q", ErrUnsatisfiedConstraint,
				invalidA.String(),
				invalidB.String(),
				invalidC.String())
		}
	}

	return
}

// Inspect returns the tagged variables with their corresponding value
func (r1cs R1CS) Inspect() (map[string]curve.Element, error) {

	res := make(map[string]curve.Element)

	for _, wire := range r1cs.WireTracker {
		for _, tag := range wire.Tags {
			if _, ok := res[tag]; ok {
				return nil, ErrDuplicateTag // TODO ensure wire.Tag() checks for duplicates ?
			}
			res[tag] = wire.Value
		}
	}

	return res, nil
}

// String prints a r1c
func (r r1c) String(r1cs R1CS) string {

	res := ""

	lwts := func(lwt lwTerm) string {
		res := ""
		tmp := lwt.Coeff
		res = res + tmp.String() + r1cs.WireTracker[lwt.ID].String()
		return res
	}

	les := func(le lwLinearExp) string {
		res := ""
		for _, l := range le {
			res = res + lwts(l) + "+"
		}
		res = res[:len(res)-1]
		return res
	}

	res = "(" + les(r.L) + ")*(" + les(r.R) + ")=" + les(r.O) + "\n"

	return res

}

// String string format of the r1cs
func (r1cs R1CS) String() string {

	res := ""

	// display the wire tracker
	res += "wire tracker:\n"
	for _, c := range r1cs.WireTracker {
		res += c.String()
		res += ", "
	}
	res = res[:len(res)-2]
	res += "\n\n"

	// display the Constraints
	res += "computational gaph:\n"
	for _, c := range r1cs.GraphOrdering {
		res = res + r1cs.ComputationalGraph[c].String(r1cs)
	}
	res += "\nconstraints gaph:\n"
	for _, c := range r1cs.Constraints {
		res = res + c.String(r1cs)
	}

	// display the ordering
	res += "\nGraph ordering:\n"
	for _, c := range r1cs.GraphOrdering {
		res += strconv.Itoa(int(c)) + ", "
	}
	res = res[:len(res)-2]

	return res
}
