package frontend

import (
	"github.com/consensys/gnark/backend/r1cs"
)

// ToR1CS builds a R1CS from a system of Constraints
// note that the return R1CS is untyped and contains big.Int
// this method should not be called directly in a normal workflow,
// as it is called by frontend.Compile()
// it exists for test purposses (backend and integration)
func (cs *CS) ToR1CS() *r1cs.UntypedR1CS {

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
	wireTracker := make([]int, 0, cs.nbConstraints)
	publicInputs := make([]int, 0)
	secretInputs := make([]int, 0)

	// we keep track of wire that are "unconstrained" to ignore them at step 2
	// unconstrained wires can be inputs or wires issued from a MOConstraint (like the i-th bit of a binary decomposition)
	ignoredConstraints := make(map[int]struct{})

	// keep track of consumed wires (one wire and user inputs should be there to start with, as they can't be roots.)
	consumedWires := make(map[int]struct{})

	// step 1: fills the tmpwiretracker, public/private inputs tracker
	for cID, c := range cs.Constraints {
		if cs.isDeleted(cID) {
			continue
		}
		wID := c.wireID
		// if it's a user input
		if cs.isUserInput(wID) {
			consumedWires[wID] = struct{}{}
			w := cs.Wires[wID]
			if w.IsSecret {
				secretInputs = append(secretInputs, wID)
			} else {
				publicInputs = append(publicInputs, wID)
			}
		} else {
			wireTracker = append(wireTracker, wID)
			// it is a unconstrained wire, we will ignore the constraint on step2
			if c.exp == nil {
				ignoredConstraints[cID] = struct{}{}
			}
		}
	}

	// store the keys of the constraint map to loop in the same order at step 4
	keys := make([]int, 0, len(cs.Constraints)-len(ignoredConstraints))

	// to keep track of the number of constraints
	var ccCounter int64

	// step 2: Run through all the constraints, set the constraintID (except the ignored ones, corresponding to inputs), consume the wires
	for cID, c := range cs.Constraints {
		if cs.isDeleted(cID) {
			continue
		}

		// we ignore monCosntraints in this loop
		if _, ok := ignoredConstraints[cID]; ok {
			continue
		}
		keys = append(keys, cID)

		if !cs.isUserInput(c.wireID) {
			c.exp.consumeWires(consumedWires) // only the first exp is consumed, the other might containt root of the computational graph
			w := cs.Wires[c.wireID]
			w.ConstraintID = ccCounter // tells the output wire from which constraint it is computed
			cs.Wires[c.wireID] = w
			ccCounter++
		}
	}
	for _, c := range cs.MOConstraints {
		c.setConstraintID(cs, ccCounter)
		c.consumeWires(consumedWires) // tells the output wires from which constraint they are computed
		ccCounter++
	}

	// step 3: number the wires and fill the wire tracker
	for i, w := range wireTracker {
		ww := cs.Wires[w]
		ww.WireIDOrdering = i
		cs.Wires[w] = ww
	}
	offset := len(wireTracker)

	uR1CS := &r1cs.UntypedR1CS{}
	uR1CS.PrivateWires = make([]string, len(secretInputs))
	for i, w := range secretInputs {
		ww := cs.Wires[w]
		ww.WireIDOrdering = i + offset
		cs.Wires[w] = ww
		uR1CS.PrivateWires[i] = ww.Name
		wireTracker = append(wireTracker, w)
	}
	offset += len(secretInputs)
	uR1CS.PublicWires = make([]string, len(publicInputs))
	for i, w := range publicInputs {
		ww := cs.Wires[w]
		ww.WireIDOrdering = i + offset
		cs.Wires[w] = ww
		uR1CS.PublicWires[i] = ww.Name
		wireTracker = append(wireTracker, w)
	}
	oneWireIDOrdered := cs.Wires[ONE_WIRE_ID].WireIDOrdering

	// step 4: Now the attributes of all wires are synced up, no need of pointers anymore
	// We can split the constraints into r1cs
	computationalGraph := make([]r1cs.R1C, 0, cs.nbConstraints)
	uR1CS.Constraints = make([]r1cs.R1C, 0, cs.nbConstraints)

	for _, k := range keys {

		c := cs.Constraints[k]

		batchR1CS := c.toR1CS(uR1CS, cs)

		if cs.isUserInput(c.wireID) {
			uR1CS.Constraints = append(uR1CS.Constraints, batchR1CS...)
		} else {
			computationalGraph = append(computationalGraph, batchR1CS[0])

			if len(batchR1CS) > 1 {
				uR1CS.Constraints = append(uR1CS.Constraints, batchR1CS[1:]...)
			}
		}
	}
	for _, c := range cs.MOConstraints {
		batchR1CS := c.toR1CS(uR1CS, cs, oneWireIDOrdered, -1)
		computationalGraph = append(computationalGraph, batchR1CS)
	}
	for _, c := range cs.NOConstraints {
		batchR1CS := c.toR1CS(uR1CS, cs, oneWireIDOrdered, -1)
		uR1CS.Constraints = append(uR1CS.Constraints, batchR1CS)
	}
	uR1CS.Coefficients = cs.Coefficients

	// Keeps track of the visited constraints, useful to build the computational graph
	visited := make([]bool, len(computationalGraph))

	// post oder computation graph: these are the constraints that need to be solved first (and in order)
	rootConstraints := findRootConstraints(cs, wireTracker, consumedWires)
	graphOrdering := make([]int64, 0, len(computationalGraph))
	for _, i := range rootConstraints {
		graphOrdering = postOrder(cs, i, visited, computationalGraph, graphOrdering, wireTracker)
	}

	// re-order the constraints
	constraints := make([]r1cs.R1C, len(graphOrdering))
	for i := 0; i < len(graphOrdering); i++ {
		constraints[i] = computationalGraph[graphOrdering[i]]
	}
	uR1CS.Constraints = append(constraints, uR1CS.Constraints...)

	// store R1CS nbWires and nbConstraints
	uR1CS.NbWires = len(wireTracker)
	uR1CS.NbConstraints = len(uR1CS.Constraints)
	uR1CS.NbCOConstraints = len(graphOrdering)
	uR1CS.NbPublicWires = len(publicInputs)
	uR1CS.NbPrivateWires = len(secretInputs)

	// tags
	uR1CS.WireTags = make(map[int][]string)
	for i, w := range wireTracker {
		tags := cs.WireTags[w]
		if len(tags) > 0 {
			uR1CS.WireTags[i] = tags
		}
	}

	return uR1CS
}

// findRootConstraints find the root wires for post ordering
func findRootConstraints(cs *CS, wireTracker []int, consumedWires map[int]struct{}) []int64 {
	var res []int64
	for _, w := range wireTracker {
		if _, ok := consumedWires[w]; !ok {
			res = append(res, cs.Wires[w].ConstraintID)
		}
	}
	return res
}

// postOrder post order traversal the computational graph; i is the index of the constraint currently visited
// linear in the number of constraints (with visit each constraint once)
func postOrder(cs *CS, constraintID int64, visited []bool, computationalGraph []r1cs.R1C, graphOrdering []int64, wireTracker []int) []int64 {

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
				n := cs.Wires[wireTracker[l.ConstraintID()]].ConstraintID
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
					n := cs.Wires[wireTracker[r.ConstraintID()]].ConstraintID
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
					n := cs.Wires[wireTracker[o.ConstraintID()]].ConstraintID
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
type stack []int64

func newStack(cap int) stack {
	return make([]int64, 0, cap)
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
