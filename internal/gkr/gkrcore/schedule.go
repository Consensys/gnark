package gkrcore

import (
	"fmt"
	"slices"

	"github.com/consensys/gnark/constraint"
)

// UniqueGateInputs returns the unique gate input wire indices for all wires in the level,
// deduplicated in batch-then-wire-then-input order (first occurrence wins).
// For input wires (no gate inputs), the wire itself is returned.
func UniqueGateInputs[G any](level constraint.GkrProvingLevel, c Circuit[G]) []int {
	uniqueInputs, _ := InputMapping(level, c)
	return uniqueInputs
}

// InputMapping computes the unique gate inputs and the per-wire index mapping in a single pass.
// inputIndices[wireInLevel][gateInputJ] → position in uniqueInputs.
// For input wires: inputIndices[i] = []int{position of wI in uniqueInputs}.
func InputMapping[G any](level constraint.GkrProvingLevel, c Circuit[G]) (uniqueInputs []int, inputIndices [][]int) {
	var groups []constraint.GkrClaimGroup
	switch l := level.(type) {
	case constraint.GkrSumcheckLevel:
		groups = l
	case constraint.GkrSkipLevel:
		groups = []constraint.GkrClaimGroup{constraint.GkrClaimGroup(l)}
	}

	seen := make(map[int]int) // wire index → position in uniqueInputs
	for _, group := range groups {
		for _, wI := range group.Wires {
			wire := c[wI]
			inputs := wire.Inputs
			if wire.IsInput() {
				inputs = []int{wI}
			}

			indices := make([]int, len(inputs))
			for inWI, inW := range inputs {
				pos, ok := seen[inW]
				if !ok {
					pos = len(uniqueInputs)
					seen[inW] = pos
					uniqueInputs = append(uniqueInputs, inW)
				}
				indices[inWI] = pos
			}
			inputIndices = append(inputIndices, indices)
		}
	}
	return
}

// ReduplicateInputs expands unique evaluations to per-wire gate input evaluation lists.
func ReduplicateInputs[G, F any](level constraint.GkrProvingLevel, c Circuit[G], uniqueEvals []F) [][]F {
	_, inputIndices := InputMapping(level, c)
	result := make([][]F, len(inputIndices))
	for wireInLevel := range inputIndices {
		wireInputs := make([]F, len(inputIndices[wireInLevel]))
		for gateInputJ, uniqueI := range inputIndices[wireInLevel] {
			wireInputs[gateInputJ] = uniqueEvals[uniqueI]
		}
		result[wireInLevel] = wireInputs
	}
	return result
}

// Degree returns max(Gate.Degree across all wires in all groups) + 1.
func Degree[G any](level constraint.GkrSumcheckLevel, c Circuit[G]) int {
	maxDeg := 0
	for _, group := range level {
		for _, wI := range group.Wires {
			w := &c[wI]
			curr := 1
			if !w.IsInput() {
				curr = w.Gate.Degree
			}
			maxDeg = max(maxDeg, curr)
		}
	}
	return maxDeg + 1
}

// NbClaims returns the total number of claims in a sumcheck level.
func NbClaims(level constraint.GkrSumcheckLevel) int {
	n := 0
	for _, g := range level {
		n += len(g.Wires) * len(g.ClaimSources)
	}
	return n
}

// ProofSize returns the total number of field elements in a GKR proof.
func ProofSize[G any](schedule constraint.GkrProvingSchedule, c Circuit[G], logNbInstances int) int {
	size := 0
	for _, step := range schedule {
		s, ok := step.(constraint.GkrSumcheckLevel)
		if !ok {
			continue
		}
		size += logNbInstances * Degree(s, c) // partialSumPolys
		size += len(UniqueGateInputs(s, c))   // finalEvalProof
	}
	return size
}

// scheduleBuilder accumulates topology and per-wire claim sources while a schedule is being built.
// Steps are appended in out-to-in (topological) order and reversed by finalize.
// Claim source indices are stored as their index in the pre-reversal levels slice, with -1 as the
// sentinel for the initial challenge. finalize maps each src to its final absolute index via
// n-1-src, where n = len(levels), so -1 -> n (initial challenge) and i -> n-1-i (real levels).
type scheduleBuilder struct {
	circuit              SerializableCircuit
	wireOutputs          [][]int // wireOutputs[i] indices of wires that wire i feeds into, in increasing order and deduplicated.
	wireLevels           []int   // wireLevels[i] which level wire i has been put in
	wireProcessed        []bool
	claimSourcesCache    [][]int // claimSourcesCache[i] is the result of claimSourcesCache(i), or nil if not yet computed.
	firstUnprocessedWire int
	levels               constraint.GkrProvingSchedule
}

// newScheduleBuilder initialises a builder for the given circuit.
// It computes the outputs inverse-adjacency list.
func newScheduleBuilder(c SerializableCircuit) scheduleBuilder {
	b := scheduleBuilder{
		circuit:              c,
		wireOutputs:          make([][]int, len(c)),
		wireLevels:           make([]int, len(c)),
		wireProcessed:        make([]bool, len(c)),
		claimSourcesCache:    make([][]int, len(c)),
		firstUnprocessedWire: len(c) - 1,
	}
	seen := make(map[int]bool, len(c))
	for i := range c {
		for k := range seen {
			delete(seen, k)
		}
		for _, in := range c[i].Inputs {
			b.wireOutputs[in] = append(b.wireOutputs[in], i)
			seen[in] = true
		}
	}
	return b
}

// addSumcheckLevel appends a GkrSumcheckLevel to the schedule. Each batch is a set of wire indices
// to be proven together in a single zerocheck; all wires in a batch must share the same claim sources.
// All wires across all batches must be ready.
func (b *scheduleBuilder) addSumcheckLevel(batches ...[]int) error {
	claimGroups, err := b.buildClaimGroups(batches)
	if err != nil {
		return err
	}
	b.levels = append(b.levels, constraint.GkrSumcheckLevel(claimGroups))
	return nil
}

// addSkipLevel appends a GkrSkipLevel to the schedule for a single set of wire indices.
// All wires in the batch must share the same claim sources and must be ready.
func (b *scheduleBuilder) addSkipLevel(wireIndices []int) error {
	claimGroups, err := b.buildClaimGroups([][]int{wireIndices})
	if err != nil {
		return err
	}
	b.levels = append(b.levels, constraint.GkrSkipLevel(claimGroups[0]))
	return nil
}

// buildClaimGroups processes a set of batches, validates claim source consistency within each
// batch, updates wireLevels and wireProcessed, and returns the resulting GkrClaimGroups.
// Every ClaimSources slice is sorted. The user may reorder it to optimize eq handling.
func (b *scheduleBuilder) buildClaimGroups(batches [][]int) ([]constraint.GkrClaimGroup, error) {
	levelIdx := len(b.levels)
	claimGroups := make([]constraint.GkrClaimGroup, len(batches))
	for i, wireIndices := range batches {
		var claimSources []int
		for j, wI := range wireIndices {
			wireClaims, ok := b.claimSources(wI)
			if !ok {
				return nil, fmt.Errorf("wire %d is not ready", wI)
			}
			if j == 0 {
				claimSources = wireClaims
			} else if !slices.Equal(claimSources, wireClaims) {
				return nil, fmt.Errorf("wires %d and %d in the same batch have different claim sources", wireIndices[0], wI)
			}
			b.wireLevels[wI] = levelIdx
			b.wireProcessed[wI] = true
			if wI == b.firstUnprocessedWire {
				for b.firstUnprocessedWire--; b.firstUnprocessedWire >= 0 && b.wireProcessed[b.firstUnprocessedWire]; b.firstUnprocessedWire-- {
				}
			}
		}
		claimGroups[i] = constraint.GkrClaimGroup{Wires: slices.Clone(wireIndices), ClaimSources: claimSources}
	}
	return claimGroups, nil
}

// nextReady returns the highest wire index in the contiguous ready suffix starting at
// firstUnprocessedWire, along with each wire's claim sources in wire-index order.
// Returns firstUnprocessedWire, nil if no wires are ready.
func (b *scheduleBuilder) nextReady() (highestWireI int, sources [][]int) {
	for lowestWireI := b.firstUnprocessedWire; lowestWireI >= 0; lowestWireI-- {
		if b.wireProcessed[lowestWireI] {
			break
		}
		src, ok := b.claimSources(lowestWireI)
		if !ok {
			break
		}
		sources = append(sources, src)
	}
	slices.Reverse(sources)
	return b.firstUnprocessedWire, sources
}

// claimSources checks whether all consumers of wire wI have already been processed.
// If so, it returns the deduplicated sorted claim sources for wI and true.
// If not, it returns nil and false. Results are cached.
func (b *scheduleBuilder) claimSources(wI int) ([]int, bool) {
	if b.claimSourcesCache[wI] != nil {
		return b.claimSourcesCache[wI], true
	}
	var wireClaims []int
	if b.circuit[wI].Exported || len(b.wireOutputs[wI]) == 0 {
		wireClaims = append(wireClaims, -1)
	}
	for _, consumerWI := range b.wireOutputs[wI] {
		if !b.wireProcessed[consumerWI] {
			return nil, false
		}
		consumerLevel := b.wireLevels[consumerWI]
		if skip, ok := b.levels[consumerLevel].(constraint.GkrSkipLevel); ok {
			wireClaims = append(wireClaims, skip.ClaimSources...)
		} else {
			wireClaims = append(wireClaims, consumerLevel)
		}
	}
	slices.Sort(wireClaims)
	wireClaims = slices.Compact(wireClaims)
	b.claimSourcesCache[wI] = wireClaims
	return wireClaims, true
}

// finalize reverses the schedule into in-to-out order and returns the completed schedule.
// It errors if any wire has not been processed, meaning the caller did not schedule a layer for every wire.
func (b *scheduleBuilder) finalize() (constraint.GkrProvingSchedule, error) {
	for i, processed := range b.wireProcessed {
		if !processed {
			return nil, fmt.Errorf("wire %d has not been processed", i)
		}
	}

	n := len(b.levels)
	slices.Reverse(b.levels)
	// Fix up ClaimSources in every GkrClaimGroup: pre-reversal index src maps to n-1-src,
	// and the initial-challenge sentinel -1 maps to n.
	for _, layer := range b.levels {
		switch l := layer.(type) {
		case constraint.GkrSkipLevel:
			mirror(l.ClaimSources, n)
		case constraint.GkrSumcheckLevel:
			for _, cg := range l {
				mirror(cg.ClaimSources, n)
			}
		}
	}
	return b.levels, nil
}

// mirror maps each pre-reversal index src in-place to its post-reversal absolute index n-1-src.
// The initial-challenge sentinel -1 maps to n.
func mirror(s []int, n int) {
	n--
	for j := range s {
		s[j] = n - s[j]
	}
}

// DefaultProvingSchedule generates a schedule that greedily batches input wires with the same
// single claim source into the same GkrSkipLevel. Non-input wires, and input wires with multiple
// claim sources, each get their own GkrSumcheckLevel.
func DefaultProvingSchedule(c SerializableCircuit) (constraint.GkrProvingSchedule, error) {
	b := newScheduleBuilder(c)

	for b.firstUnprocessedWire >= 0 {
		highWI, claimSources := b.nextReady()
		// try and make a homogenous (same degree, same claims) batch
		w := c[highWI]
		batchClaimSources := claimSources[0]
		if w.IsInput() && len(batchClaimSources) == 1 {
			if err := b.addSkipLevel([]int{highWI}); err != nil {
				return nil, err
			}
			continue
		}

		// there is an actual "gate" in question
		batch := []int{highWI}
		for len(batch) < len(claimSources) {
			if w.Gate.Degree != c[highWI-len(batch)].Gate.Degree || !slices.Equal(claimSources[0], claimSources[len(batch)]) {
				break
			}
			batch = append(batch, highWI-len(batch))
		}
		if w.Gate.Degree == 1 && len(batchClaimSources) == 1 { // certain that skipping won't cause a claim blowup
			if err := b.addSkipLevel(batch); err != nil {
				return nil, err
			}
		} else {
			if err := b.addSumcheckLevel(batch); err != nil {
				return nil, err
			}
		}
	}
	return b.finalize()
}

// BasicProvingSchedule generates a schedule for a circuit where every wire gets its own level:
// Non-input wires get a GkrSumcheckLevel. Input wires with multiple consumers get a GkrSumcheckLevel
// to consolidate claims; input wires with a single consumer get a GkrSkipLevel.
func BasicProvingSchedule(c SerializableCircuit) (constraint.GkrProvingSchedule, error) {
	b := newScheduleBuilder(c)
	for wI := len(c) - 1; wI >= 0; wI-- {
		src, ready := b.claimSources(wI)
		if !ready {
			return nil, fmt.Errorf("circuit is not topologically sorted: wire %d not ready", wI)
		}
		var err error
		if !c[wI].IsInput() || len(src) > 1 {
			err = b.addSumcheckLevel([]int{wI})
		} else {
			err = b.addSkipLevel([]int{wI})
		}
		if err != nil {
			return nil, err
		}
	}
	return b.finalize()
}
