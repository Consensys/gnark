package frontend

// NewR1CS builds a R1CS from a system of Constraints
func (circuit *CS) ToR1CS() *R1CS {

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
	var wireTracker, publicInputs, privateInputs []*wire
	var computationalGraph []R1C

	// we keep track of wire that are "unconstrained" to ignore them at step 2
	// unconstrained wires can be inputs or wires issued from a MOConstraint (like the i-th bit of a binary decomposition)
	ignoredConstraints := make(map[uint64]struct{})

	// step 1: fills the tmpwiretracker, public/private inputs tracker
	for k, c := range circuit.Constraints {

		// if it's a user input
		if c.getOutputWire().isUserInput() {
			if c.getOutputWire().IsPrivate {
				privateInputs = append(privateInputs, c.getOutputWire())
			} else {
				publicInputs = append(publicInputs, c.getOutputWire())
			}
		} else {
			wireTracker = append(wireTracker, c.getOutputWire())
			// it is a unconstrained wire, we will ignore the constraint on step2
			if len(c.getExpressions()) == 0 {
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

		if !c.getOutputWire().isUserInput() {
			c.getExpressions()[0].consumeWires()       // only the first exp is consumed, the other might containt root of the computational graph
			c.getOutputWire().ConstraintID = ccCounter // tells the output wire from which constraint it is computed
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
	}
	offset := len(wireTracker)

	r1cs := &R1CS{}
	r1cs.PrivateWires = make([]string, len(privateInputs))
	for i, w := range privateInputs {
		w.WireID = int64(i + offset)
		r1cs.PrivateWires[i] = w.Name
		wireTracker = append(wireTracker, w)
	}
	offset += len(privateInputs)
	r1cs.PublicWires = make([]string, len(publicInputs))
	for i, w := range publicInputs {
		w.WireID = int64(i + offset)
		r1cs.PublicWires[i] = w.Name
		wireTracker = append(wireTracker, w)
	}

	// step 4: Now the attributes of all wires are synced up, no need of pointers anymore
	// We can split the constraints into r1cs
	for _, k := range keys {

		c := circuit.Constraints[k].(*constraint)

		batchR1CS := c.toR1CS(circuit)

		if c.getOutputWire().isUserInput() {
			r1cs.Constraints = append(r1cs.Constraints, batchR1CS...)
		} else {
			computationalGraph = append(computationalGraph, batchR1CS[0])

			if len(batchR1CS) > 1 {
				r1cs.Constraints = append(r1cs.Constraints, batchR1CS[1:]...)
			}
		}
	}
	for _, c := range circuit.MOConstraints {
		batchR1CS := c.toR1CS(circuit.Constraints[0].getOutputWire())
		computationalGraph = append(computationalGraph, batchR1CS)
	}
	for _, c := range circuit.NOConstraints {
		batchR1CS := c.toR1CS(circuit.Constraints[0].getOutputWire())
		r1cs.Constraints = append(r1cs.Constraints, batchR1CS)
	}

	// Keeps track of the visited constraints, useful to build the computational graph
	visited := make([]bool, len(computationalGraph))

	// post oder computation graph: these are the constraints that need to be solved first (and in order)
	rootConstraints := findRootConstraints(wireTracker)
	var graphOrdering []int64
	for _, i := range rootConstraints {
		graphOrdering = postOrder(i, visited, computationalGraph, graphOrdering, wireTracker)
	}

	// re-order the constraints
	constraints := make([]R1C, len(graphOrdering))
	for i := 0; i < len(graphOrdering); i++ {
		constraints[i] = computationalGraph[graphOrdering[i]]
	}
	r1cs.Constraints = append(constraints, r1cs.Constraints...)

	// store R1CS nbWires and nbConstraints
	r1cs.NbWires = len(wireTracker)
	r1cs.NbConstraints = len(r1cs.Constraints)
	r1cs.NbCOConstraints = len(graphOrdering)
	r1cs.NbPublicWires = len(publicInputs)
	r1cs.NbPrivateWires = len(privateInputs)

	// tags
	r1cs.WireTags = make(map[int][]string)
	// TODO here would be a good place to check for duplicate in the tags and make this method return an error?
	for i, wire := range wireTracker {
		if len(wire.Tags) > 0 {
			r1cs.WireTags[i] = wire.Tags
		}
	}

	return r1cs
}

// findRootConstraints find the root wires for post ordering
func findRootConstraints(wireTracker []*wire) []int64 {
	var res []int64
	for _, w := range wireTracker {
		if !w.IsConsumed {
			res = append(res, w.ConstraintID)
		}
	}
	return res
}

// postOrder post order traversal the computational graph; i is the index of the constraint currently visited
// linear in the number of constraints (with visit each constraint once)
func postOrder(constraintID int64, visited []bool, computationalGraph []R1C, graphOrdering []int64, wireTracker []*wire) []int64 {

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

			c := computationalGraph[node]

			found = false

			// explore left wires
			for _, l := range c.L {
				n := wireTracker[l.ID].ConstraintID
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
					n := wireTracker[r.ID].ConstraintID
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
					n := wireTracker[o.ID].ConstraintID
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
