package gkrcore

import (
	"fmt"
	"slices"
)

type (
	// ClaimGroup represents a set of wires with their claim sources.
	// It is agnostic of the protocol - it only describes which wires have claims
	// from which sources, not what to do with them.
	//
	// ClaimSources contains step indices that produced evaluation claims for these wires.
	// The special value len(schedule) is a virtual step index representing the verifier's
	// initial challenge (rho). It is never an actual index into the schedule slice.
	ClaimGroup struct {
		Wires        []int `json:"wires"`
		ClaimSources []int `json:"claimSourcesCache"` // step indices; len(schedule) = initial challenge
	}

	// ProvingLevel is the interface for a single level in the proving schedule.
	// A level is either a SkipLevel or a SumcheckLevel.
	ProvingLevel interface {
	}

	// SkipLevel represents a level where zerocheck is skipped.
	// Claims propagate through at their existing evaluation points.
	SkipLevel ClaimGroup

	// SumcheckLevel represents a level where one or more zerochecks are batched
	// together in a single sumcheck. Each ClaimGroup within may have different
	// claim sources (sumcheck-level batching), or the same source (enabling
	// zerocheck-level batching with shared eq tables).
	SumcheckLevel []ClaimGroup

	// ProvingSchedule is a sequence of levels defining how to prove a GKR circuit.
	ProvingSchedule []ProvingLevel
)

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
	levels               ProvingSchedule
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

// addSumcheckLevel appends a SumcheckLevel to the schedule. Each batch is a set of wire indices
// to be proven together in a single zerocheck; all wires in a batch must share the same claim sources.
// All wires across all batches must be ready.
func (b *scheduleBuilder) addSumcheckLevel(batches ...[]int) error {
	claimGroups, err := b.buildClaimGroups(batches)
	if err != nil {
		return err
	}
	b.levels = append(b.levels, SumcheckLevel(claimGroups))
	return nil
}

// addSkipLevel appends a SkipLevel to the schedule for a single set of wire indices.
// All wires in the batch must share the same claim sources and must be ready.
func (b *scheduleBuilder) addSkipLevel(wireIndices []int) error {
	claimGroups, err := b.buildClaimGroups([][]int{wireIndices})
	if err != nil {
		return err
	}
	b.levels = append(b.levels, SkipLevel(claimGroups[0]))
	return nil
}

// buildClaimGroups processes a set of batches, validates claim source consistency within each
// batch, updates wireLevels and wireProcessed, and returns the resulting ClaimGroups.
// Every ClaimSources slice is sorted. The user may reorder it to optimize eq handling.
func (b *scheduleBuilder) buildClaimGroups(batches [][]int) ([]ClaimGroup, error) {
	levelIdx := len(b.levels)
	claimGroups := make([]ClaimGroup, len(batches))
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
		claimGroups[i] = ClaimGroup{Wires: slices.Clone(wireIndices), ClaimSources: claimSources}
	}
	return claimGroups, nil
}

// nextReady returns the largest i such that wires [i, len(circuit)) are all ready,
// along with their claim sources. Wires are considered in reverse index order (high-to-low).
// Returns len(circuit) if no wires are ready.
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

// claimSourcesCache checks whether all consumers of wire wI have already been processed.
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
		if skip, ok := b.levels[consumerLevel].(SkipLevel); ok {
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
func (b *scheduleBuilder) finalize() (ProvingSchedule, error) {
	for i, processed := range b.wireProcessed {
		if !processed {
			return nil, fmt.Errorf("wire %d has not been processed", i)
		}
	}

	n := len(b.levels)
	slices.Reverse(b.levels)
	// Fix up ClaimSources in every ClaimGroup: pre-reversal index src maps to n-1-src,
	// and the initial-challenge sentinel -1 maps to n.
	for _, layer := range b.levels {
		switch l := layer.(type) {
		case SkipLevel:
			mirror(l.ClaimSources, n)
		case SumcheckLevel:
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
// single claim source into the same SkipLevel. Non-input wires, and input wires with multiple
// claim sources, each get their own SumcheckLevel.
func DefaultProvingSchedule(c SerializableCircuit) (ProvingSchedule, error) {
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
		if w.Gate.Degree == 1 && len(batchClaimSources) == 1 {	// certain that skipping won't cause a claim blowup
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
// Non-input wires get a SumcheckLevel. Input wires with multiple consumers get a SumcheckLevel
// to consolidate claims; input wires with a single consumer get a SkipLevel.
func BasicProvingSchedule(c SerializableCircuit) (ProvingSchedule, error) {
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
