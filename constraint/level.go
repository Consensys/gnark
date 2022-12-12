package constraint

// TODO @gbotrel this should be done each time we add a constriant really, to keep the object consistent.

// The main idea here is to find a naive clustering of independent constraints that can be solved in parallel.
//
// We know that at each constraint, we will have at most one unsolved wire.
// (a constraint may have no unsolved wire in which case it is a plain check that the constraint hold,
// or it may additionally have some wires that will be solved by solver hints)
//
// We build a graph of dependency; we say that a wire is solved at a level l
// --> l = max(level_of_dependencies(wire)) + 1

type levelBuilder struct {
	mHints     map[int]*Hint
	wireOffset uint32   // nbInputs --> so wireLevel doesn't contains inputs just internal wires.
	wireLevel  []int    // at which level we solve a wire. init at -1.
	outputs    []uint32 // wire outputs for current constraint.
}

func newLevelBuilder(ccs *System, nbConstraints int) *levelBuilder {
	b := levelBuilder{
		wireLevel:  make([]int, ccs.GetNbInternalVariables()), // at which node we resolved which wire
		mHints:     ccs.MHints,
		wireOffset: uint32(ccs.GetNbPublicVariables() + ccs.GetNbSecretVariables()),
	}
	for i := 0; i < len(b.wireLevel); i++ {
		b.wireLevel[i] = -1
	}
	return &b
}

func (b *levelBuilder) processWire(wireID uint32, maxLevel *int) {
	if wireID < b.wireOffset {
		return // ignore inputs
	}
	wID := wireID - b.wireOffset
	for int(wID) >= len(b.wireLevel) {
		// we didn't encounter this wire yet, we need to grow b.wireLevels
		b.wireLevel = append(b.wireLevel, -1)
	}
	if b.wireLevel[wID] != -1 {
		// we know how to solve this wire, it's a dependency
		if b.wireLevel[wID] > *maxLevel {
			*maxLevel = b.wireLevel[wID]
		}
		return
	}
	// we don't know how to solve this wire; it's either THE wire we have to solve or a hint.
	if h, ok := b.mHints[int(wireID)]; ok {
		for _, hwid := range h.Wires {
			b.outputs = append(b.outputs, uint32(hwid)-b.wireOffset)
		}
		for _, in := range h.Inputs {
			for _, t := range in {
				b.processWire(t.VID, maxLevel)
			}
		}

		return
	}

	// it's the missing wire
	b.outputs = append(b.outputs, wID)
}

func (r1c *R1C) wIterator() func() int {
	curr := 0
	return func() int {
		if curr < len(r1c.L) {
			curr++
			return r1c.L[curr-1].WireID()
		}
		if curr < len(r1c.L)+len(r1c.R) {
			curr++
			return r1c.R[curr-1-len(r1c.L)].WireID()
		}
		if curr < len(r1c.L)+len(r1c.R)+len(r1c.O) {
			curr++
			return r1c.O[curr-1-len(r1c.L)-len(r1c.R)].WireID()
		}
		return -1
	}
}

func (c *SparseR1C) wIterator() func() int {
	curr := 0
	return func() int {
		switch curr {
		case 0:
			curr++
			return c.L.WireID()
		case 1:
			curr++
			return c.R.WireID()
		case 2:
			curr++
			return c.O.WireID()
		}
		return -1
	}
}

func buildR1CSLevels(ccs *R1CSCore) {
	b := newLevelBuilder(&ccs.System, len(ccs.Constraints))

	// for each constraint, we're going to find its direct dependencies
	// that is, wires (solved by previous constraints) on which it depends
	// each of these dependencies is tagged with a level
	// current constraint will be tagged with max(level) + 1
	for cID, c := range ccs.Constraints {
		b.outputs = b.outputs[:0]
		level := -1
		wireIterator := c.wIterator()
		for wID := wireIterator(); wID != -1; wID = wireIterator() {
			// iterate over all wires of the R1C
			b.processWire(uint32(wID), &level)
		}

		// level =  max(dependencies) + 1
		level++

		// mark output wire with level
		for _, wireID := range b.outputs {
			b.wireLevel[wireID] = level
		}

		// we can't skip levels, so appending is fine.
		if level >= len(ccs.Levels) {
			ccs.Levels = append(ccs.Levels, []int{cID})
		} else {
			ccs.Levels[level] = append(ccs.Levels[level], cID)
		}
	}

}

func buildSCSLevels(ccs *SparseR1CSCore) {

	b := newLevelBuilder(&ccs.System, len(ccs.Constraints))

	// for each constraint, we're going to find its direct dependencies
	// that is, wires (solved by previous constraints) on which it depends
	// each of these dependencies is tagged with a level
	// current constraint will be tagged with max(level) + 1
	for cID, c := range ccs.Constraints {
		b.outputs = b.outputs[:0]
		level := -1
		wireIterator := c.wIterator()
		for wID := wireIterator(); wID != -1; wID = wireIterator() {
			// iterate over all wires of the R1C
			b.processWire(uint32(wID), &level)
		}

		// level =  max(dependencies) + 1
		level++

		// mark output wire with level
		for _, wireID := range b.outputs {
			b.wireLevel[wireID] = level
		}

		// we can't skip levels, so appending is fine.
		if level >= len(ccs.Levels) {
			ccs.Levels = append(ccs.Levels, []int{cID})
		} else {
			ccs.Levels[level] = append(ccs.Levels[level], cID)
		}
	}
}
