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
		// NbClaims returns the total number of claims at this level.
		NbClaims() int
		ClaimGroups() []GkrClaimGroup
		// FinalEvalProofIndex returns where to find the evaluationPointI'th evaluation claim for the wireI'th input wire to the layer,
		// in the layer's final evaluation proof.
		FinalEvalProofIndex(wireI, evaluationPointI int) int
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
func (l GkrSumcheckLevel) ClaimGroups() []GkrClaimGroup         { return l }
func (l GkrSumcheckLevel) FinalEvalProofIndex(wireI, _ int) int { return wireI }

func (l GkrSkipLevel) NbOutgoingEvalPoints() int { return len(l.ClaimSources) }
func (l GkrSkipLevel) NbClaims() int {
	return GkrClaimGroup(l).NbClaims()
}
func (l GkrSkipLevel) ClaimGroups() []GkrClaimGroup { return []GkrClaimGroup{GkrClaimGroup(l)} }
func (l GkrSkipLevel) FinalEvalProofIndex(wireI, evaluationPointI int) int {
	return wireI*l.NbOutgoingEvalPoints() + evaluationPointI
}

// BindGkrFinalEvalProof binds the non-input-wire entries of finalEvalProof into the transcript.
// Input-wire evaluations are fully determined by the public assignment (and by evaluation points
// already committed to the transcript), so hashing them contributes nothing to Fiat-Shamir security.
// uniqueGateInputs is the deduplicated list of gate-input wire indices for the level in the same
// order as the finalEvalProof entries (i.e. the order returned by UniqueGateInputs).
func BindGkrFinalEvalProof[F any](transcript interface{ Bind(...F) }, finalEvalProof []F, uniqueGateInputs []int, isInput func(wireI int) bool, level GkrProvingLevel) {
	for i, inputWireI := range uniqueGateInputs {
		if !isInput(inputWireI) {
			transcript.Bind(finalEvalProof[level.FinalEvalProofIndex(i, 0):level.FinalEvalProofIndex(i+1, 0)]...)
		}
	}
}
