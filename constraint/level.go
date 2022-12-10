package constraint

// TODO @gbotrel this should be done each time we add a constriant really, to keep the object consistent.

func buildR1CSLevels(ccs R1CSCore) [][]int {

	b := levelBuilder{
		mWireToNode: make(map[int]int, ccs.NbInternalVariables), // at which node we resolved which wire
		nodeLevels:  make([]int, len(ccs.Constraints)),          // level of a node
		mLevels:     make(map[int]int),                          // level counts
		mHints:      ccs.MHints,
		nbInputs:    len(ccs.Public) + len(ccs.Secret),
	}

	// for each constraint, we're going to find its direct dependencies
	// that is, wires (solved by previous constraints) on which it depends
	// each of these dependencies is tagged with a level
	// current constraint will be tagged with max(level) + 1
	for cID, c := range ccs.Constraints {

		b.nodeLevel = 0

		b.processLE(c.L, cID)
		b.processLE(c.R, cID)
		b.processLE(c.O, cID)
		b.nodeLevels[cID] = b.nodeLevel
		b.mLevels[b.nodeLevel]++

	}

	levels := make([][]int, len(b.mLevels))
	for i := 0; i < len(levels); i++ {
		// allocate memory
		levels[i] = make([]int, 0, b.mLevels[i])
	}

	for n, l := range b.nodeLevels {
		levels[l] = append(levels[l], n)
	}

	return levels
}

func buildSCSLevels(ccs SparseR1CSCore) [][]int {

	b := levelBuilder{
		mWireToNode: make(map[int]int, ccs.NbInternalVariables), // at which node we resolved which wire
		nodeLevels:  make([]int, len(ccs.Constraints)),          // level of a node
		mLevels:     make(map[int]int),                          // level counts
		mHints:      ccs.MHints,
		nbInputs:    len(ccs.Public) + len(ccs.Secret),
	}

	// for each constraint, we're going to find its direct dependencies
	// that is, wires (solved by previous constraints) on which it depends
	// each of these dependencies is tagged with a level
	// current constraint will be tagged with max(level) + 1
	for cID, c := range ccs.Constraints {

		b.nodeLevel = 0

		b.processTerm(c.L, cID)
		b.processTerm(c.R, cID)
		b.processTerm(c.O, cID)

		b.nodeLevels[cID] = b.nodeLevel
		b.mLevels[b.nodeLevel]++

	}

	levels := make([][]int, len(b.mLevels))
	for i := 0; i < len(levels); i++ {
		// allocate memory
		levels[i] = make([]int, 0, b.mLevels[i])
	}

	for n, l := range b.nodeLevels {
		levels[l] = append(levels[l], n)
	}

	return levels
}

type levelBuilder struct {
	// ccs      R1CSCore
	mHints   map[int]*Hint
	nbInputs int

	mWireToNode map[int]int // at which node we resolved which wire
	nodeLevels  []int       // level per node
	mLevels     map[int]int // number of constraint per level

	nodeLevel int // current level
}

func (b *levelBuilder) processLE(l LinearExpression, cID int) {

	for _, t := range l {
		wID := t.WireID()
		if wID < b.nbInputs {
			// it's an input, we ignore it
			continue
		}

		// if we know which constraint solves this wire, then it's a dependency
		n, ok := b.mWireToNode[wID]
		if ok {
			if n != cID { // can happen with hints...
				// we add a dependency, check if we need to increment our current level
				if b.nodeLevels[n] >= b.nodeLevel {
					b.nodeLevel = b.nodeLevels[n] + 1 // we are at the next level at least since we depend on it
				}
			}
			continue
		}

		// check if it's a hint and mark all the output wires
		if h, ok := b.mHints[wID]; ok {

			for _, in := range h.Inputs {
				b.processLE(in, cID)
			}

			for _, hwid := range h.Wires {
				b.mWireToNode[hwid] = cID
			}
			continue
		}

		// mark this wire solved by current node
		b.mWireToNode[wID] = cID
	}
}

func (b *levelBuilder) processTerm(t Term, cID int) {
	wID := t.WireID()
	if wID < b.nbInputs {
		// it's a input, we ignore it
		return
	}

	// if we know a which constraint solves this wire, then it's a dependency
	n, ok := b.mWireToNode[wID]
	if ok {
		if n != cID { // can happen with hints...
			// we add a dependency, check if we need to increment our current level
			if b.nodeLevels[n] >= b.nodeLevel {
				b.nodeLevel = b.nodeLevels[n] + 1 // we are at the next level at least since we depend on it
			}
		}
		return
	}

	// check if it's a hint and mark all the output wires
	if h, ok := b.mHints[wID]; ok {

		for _, in := range h.Inputs {
			for _, tt := range in {
				b.processTerm(tt, cID)
			}
		}

		for _, hwid := range h.Wires {
			b.mWireToNode[hwid] = cID
		}

		return
	}

	// mark this wire solved by current node
	b.mWireToNode[wID] = cID

}
