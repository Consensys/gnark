package frontend

import (
	"math/big"

	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/backend/r1cs/r1c"
)

// toR1CS builds a R1CS from a system of Constraints
// note that the return R1CS is untyped and contains big.Int
// this method should not be called directly in a normal workflow,
// as it is called by frontend.Compile()
// it is exposed for test purposses (backend and integration)
func (cs *CS) toR1CS() *r1cs.UntypedR1CS {

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

	// those 3 slices store all the wires
	// those are needed to number the wires, before putting them in the wire tracker
	wireTracker := make([]int, 0, len(cs.constraints))
	publicInputs := make([]int, 0, len(cs.publicWireNames))
	secretInputs := make([]int, 0, len(cs.secretWireNames))

	// initialize R1CS to return
	uR1CS := &r1cs.UntypedR1CS{
		Constraints:   make([]r1c.R1C, 0, len(cs.constraints)),
		SecretWires:   make([]string, len(cs.secretWireNames)),
		PublicWires:   make([]string, len(cs.publicWireNames)),
		NbPublicWires: len(cs.publicWireNames),
		NbSecretWires: len(cs.secretWireNames),
		WireTags:      make(map[int][]string),
	}

	// keep track of consumed wires (one wire and user inputs should be there to start with, as they can't be roots.)
	consumedWires := make(map[int]struct{})

	// step 1: fills the tmpwiretracker, public/private inputs tracker.
	// During this step the constraints are seen as variables: there is
	// a one-to-one correspondence between the content of the wireTracker
	// and non-inputs contraints. The wireTracker contains only wires that
	// are computed, ie all wires except the user inputs.
	for cID := 1; cID < len(cs.constraints); cID++ {
		if _, ok := cs.secretWireNames[cID]; ok {
			consumedWires[cID] = struct{}{}
			secretInputs = append(secretInputs, cID)
		} else if _, ok := cs.publicWireNames[cID]; ok {
			consumedWires[cID] = struct{}{}
			publicInputs = append(publicInputs, cID)
		} else {
			wireTracker = append(wireTracker, cID)
		}
	}

	// to keep track of the number of computational constraints
	// (constraints leading to a new wire)
	var ccCounter int

	// step 2: the computational constraints (ie those yielding a new variables)
	// are recorded and numbered according to their order of appearance. Those
	// constraints are exactly the moconstraints, plus the constraints having c.exp
	// field filled. When such a constraint is found, the wires in c.exp leading the
	// the computation of c.wire are recorded as 'consumed' in the consumedWires slice.
	for cID := 1; cID < len(cs.constraints); cID++ {
		c := cs.constraints[cID]

		// no expression leading to it: it's an input or the output of a moconstraint
		if c.exp == nil {
			continue
		}

		c.exp.consumeWires(consumedWires)
		c.finalConstraintID = ccCounter // tells the output wire from which constraint it is computed
		cs.constraints[cID] = c
		ccCounter++
	}
	for _, c := range cs.moExpressions { // a moconstraint yields new variables
		c.setConstraintID(cs, ccCounter)
		c.consumeWires(consumedWires) // tells the output wires from which constraint they are computed
		ccCounter++
	}
	lenComputationalGraph := ccCounter

	// step 3: number the wires and fill the wire tracker
	// note that contrary to the constraint numbering, we don't ignore moConstraints and user inputs here
	// as they are wires (without being constrained)
	// so the wire numbering and the constraint numbering will differ.
	// wires ordering is arbitrary, we chose:
	// [non-input wires|secretWires|publicWires]
	for i, cID := range wireTracker { // only non input wires in the wireTracker
		c := cs.constraints[cID]
		c.finalWireID = i
		cs.constraints[cID] = c
	}
	offset := len(wireTracker)

	for i, cID := range secretInputs {
		c := cs.constraints[cID]
		c.finalWireID = i + offset
		cs.constraints[cID] = c
		uR1CS.SecretWires[i] = cs.secretWireNames[cID]
		wireTracker = append(wireTracker, cID)
	}
	offset += len(secretInputs)
	for i, cID := range publicInputs {
		c := cs.constraints[cID]
		c.finalWireID = i + offset
		cs.constraints[cID] = c
		uR1CS.PublicWires[i] = cs.publicWireNames[cID]
		wireTracker = append(wireTracker, cID)
	}
	oneWireIDOrdered := cs.constraints[oneWireID].finalWireID

	// step 4: Now that the wires are numbered, we can split the constraint into R1C
	// using final IDs
	computationalGraph := make([]r1c.R1C, lenComputationalGraph)
	computationalGraphIdx := 0

	for cID := 1; cID < len(cs.constraints); cID++ {
		c := cs.constraints[cID]
		if c.exp == nil {
			// we ignore unconstrained wires (moConstraints or user inputs), as they don't yield a R1C
			continue
		}

		// convert underlying constraint's expression into R1C
		computationalGraph[computationalGraphIdx] = c.exp.toR1CS(uR1CS, cs, oneWireIDOrdered, c.ID)
		computationalGraphIdx++
	}
	for i := 0; i < len(cs.moExpressions); i++ {
		e := cs.moExpressions[i]
		computationalGraph[computationalGraphIdx] = e.toR1CS(uR1CS, cs, oneWireIDOrdered, -1)
		computationalGraphIdx++
	}

	// note that no output constraints yields no output, and hence, don't need to be in the computation graph
	// we directly add the R1C to the R1CS constraint list
	for i := 0; i < len(cs.noExpressions); i++ {
		e := cs.noExpressions[i]
		uR1CS.Constraints = append(uR1CS.Constraints, e.toR1CS(uR1CS, cs, oneWireIDOrdered, -1))
	}

	// set big.Int coefficient table
	uR1CS.Coefficients = make([]big.Int, len(cs.coeffs))
	copy(uR1CS.Coefficients, cs.coeffs)

	// Keeps track of the visited constraints, useful to build the computational graph
	visited := make([]bool, len(computationalGraph))

	// post oder computation graph: these are the constraints that need to be solved first (and in order)
	rootConstraints := findRootConstraints(cs, wireTracker, consumedWires)
	graphOrdering := make([]int, 0, len(computationalGraph))
	for _, i := range rootConstraints {
		graphOrdering = postOrder(cs, i, visited, computationalGraph, graphOrdering, wireTracker)
	}

	// re-order the constraints
	constraints := make([]r1c.R1C, len(graphOrdering))
	for i := 0; i < len(graphOrdering); i++ {
		constraints[i] = computationalGraph[graphOrdering[i]]
	}
	uR1CS.Constraints = append(constraints, uR1CS.Constraints...)

	// store R1CS nbWires and nbConstraints
	uR1CS.NbWires = len(wireTracker)
	uR1CS.NbConstraints = len(uR1CS.Constraints)
	uR1CS.NbCOConstraints = len(graphOrdering)

	// tags
	for i, w := range wireTracker {
		tags := cs.wireTags[w]
		if len(tags) > 0 {
			uR1CS.WireTags[i] = tags
		}
	}

	return uR1CS
}

// findRootConstraints find the root wires for post ordering
func findRootConstraints(cs *CS, wireTracker []int, consumedWires map[int]struct{}) []int {
	var res []int
	for _, w := range wireTracker {
		if _, ok := consumedWires[w]; !ok {
			res = append(res, cs.constraints[w].finalConstraintID)
		}
	}
	return res
}

// postOrder post order traversal the computational graph; i is the index of the constraint currently visited
// linear in the number of constraints (with visit each constraint once)
func postOrder(cs *CS, constraintID int, visited []bool, computationalGraph []r1c.R1C, graphOrdering []int, wireTracker []int) []int {

	// stackIn stores the unsivisted/non input wires in the order we
	// visit them
	stackIn := newStack(len(computationalGraph))

	// stackOut stores the constraint in the order we should visit them to
	// solve them
	stackOut := newStack(len(computationalGraph))

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

			c := computationalGraph[node]

			found = false

			// explore left wires
			for _, l := range c.L {
				n := cs.constraints[wireTracker[l.ConstraintID()]].finalConstraintID
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
				for _, r := range c.R {
					n := cs.constraints[wireTracker[r.ConstraintID()]].finalConstraintID
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
				for _, o := range c.O {
					n := cs.constraints[wireTracker[o.ConstraintID()]].finalConstraintID
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

	graphOrdering = append(graphOrdering, stackOut...)
	return graphOrdering
}

// helpers for post ordering
type stack []int

func newStack(cap int) stack {
	return make([]int, 0, cap)
}

func (s stack) push(elmt int) stack {
	s = append(s, elmt)
	return s
}

func (s stack) pop() (stack, int) {
	elmt := s[len(s)-1]
	s = s[:len(s)-1]
	return s, elmt
}

func (s stack) isEmpty() bool {
	return len(s) == 0
}
