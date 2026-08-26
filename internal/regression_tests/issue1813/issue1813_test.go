package issue1813

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// recommitAcrossGapCircuit reproduces #1813: committing to a new variable
// together with a variable that is already part of an earlier commitment,
// where a non-linear wire created between the two commitments sits between
// the earlier commitment's wire index and this variable's own index.
type recommitAcrossGapCircuit struct {
	X, Y, Z frontend.Variable
}

func (c *recommitAcrossGapCircuit) Define(api frontend.API) error {
	committer := api.(frontend.Committer)
	if _, err := committer.Commit(c.X); err != nil {
		return err
	}
	// A genuinely new wire (not reducible to a linear combination), so its VID
	// falls after the first commitment's wire index.
	d := api.Mul(c.Y, c.Y)
	if _, err := committer.Commit(d); err != nil {
		return err
	}
	// Re-committing to d alongside a brand-new variable used to panic with
	// "index out of range" in builder.Commit.
	if _, err := committer.Commit(c.Z, d); err != nil {
		return err
	}
	return nil
}

func TestIssue1813RecommitAcrossGap(t *testing.T) {
	assert := test.NewAssert(t)
	assignment := &recommitAcrossGapCircuit{X: 2, Y: 3, Z: 4}
	assert.CheckCircuit(&recommitAcrossGapCircuit{}, test.WithValidAssignment(assignment))
}
