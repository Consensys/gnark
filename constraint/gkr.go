package constraint

type (
	// GkrClaimGroup represents a set of wires with their claim sources.
	// It is agnostic of the protocol - it only describes which wires have claims
	// from which sources, not what to do with them.
	//
	// ClaimSources contains step indices that produced evaluation claims for these wires.
	// The special value len(schedule) is a virtual step index representing the verifier's
	// initial challenge (rho). It is never an actual index into the schedule slice.
	GkrClaimGroup struct {
		Wires        []int `json:"wires"`
		ClaimSources []int `json:"claimSourcesCache"` // step indices; len(schedule) = initial challenge
	}

	// GkrProvingLevel is a sealed interface for a single level in the proving schedule.
	// A level is either a GkrSkipLevel or a GkrSumcheckLevel.
	GkrProvingLevel interface {
		gkrProvingLevel() // marker method restricting implementations to GkrSkipLevel and GkrSumcheckLevel
	}

	// GkrSkipLevel represents a level where zerocheck is skipped.
	// Claims propagate through at their existing evaluation points.
	GkrSkipLevel GkrClaimGroup

	// GkrSumcheckLevel represents a level where one or more zerochecks are batched
	// together in a single sumcheck. Each GkrClaimGroup within may have different
	// claim sources (sumcheck-level batching), or the same source (enabling
	// zerocheck-level batching with shared eq tables).
	GkrSumcheckLevel []GkrClaimGroup

	// GkrProvingSchedule is a sequence of levels defining how to prove a GKR circuit.
	GkrProvingSchedule []GkrProvingLevel
)

func (GkrSumcheckLevel) gkrProvingLevel() {}
func (GkrSkipLevel) gkrProvingLevel()     {}
