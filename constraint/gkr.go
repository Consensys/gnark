package constraint

type (
	// GkrClaimSource identifies an incoming evaluation claim for a wire.
	// Level is the level that produced the claim.
	// OutgoingClaimIndex selects which of that level's outgoing evaluation points is referenced;
	// always 0 for SumcheckLevels, 0..M-1 for SkipLevels with M inherited evaluation points.
	// The initial verifier challenge is represented as {Level: len(schedule), OutgoingClaimIndex: 0}.
	GkrClaimSource struct {
		Level              int `json:"level"`
		OutgoingClaimIndex int `json:"outgoingClaimIndex"`
	}

	// GkrClaimGroup represents a set of wires sharing identical claim sources.
	// finalEvalProof index = pos(wire, srcLevel) * NbOutgoingEvalPoints(srcLevel) + ClaimSources[claimI].OutgoingClaimIndex,
	// where pos(wire, srcLevel) is the wire's position in srcLevel's UniqueGateInputs list.
	GkrClaimGroup struct {
		Wires        []int            `json:"wires"`
		ClaimSources []GkrClaimSource `json:"claimSources"`
	}

	// GkrProvingLevel is a single level in the proving schedule.
	GkrProvingLevel interface {
		NbOutgoingEvalPoints() int
		NbClaims() int
		ClaimGroups() []GkrClaimGroup
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

func (g GkrClaimGroup) NbClaims() int { return len(g.Wires) * len(g.ClaimSources) }

func (l GkrSumcheckLevel) NbOutgoingEvalPoints() int { return 1 }
func (l GkrSumcheckLevel) NbClaims() int {
	n := 0
	for _, g := range l {
		n += len(g.Wires) * len(g.ClaimSources)
	}
	return n
}
func (l GkrSumcheckLevel) ClaimGroups() []GkrClaimGroup { return l }

func (l GkrSkipLevel) NbOutgoingEvalPoints() int { return len(l.ClaimSources) }
func (l GkrSkipLevel) NbClaims() int {
	return GkrClaimGroup(l).NbClaims()
}
func (l GkrSkipLevel) ClaimGroups() []GkrClaimGroup { return []GkrClaimGroup{GkrClaimGroup(l)} }
