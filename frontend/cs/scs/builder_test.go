package scs

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/stretchr/testify/require"
)

func TestAddQuadraticConstraint(t *testing.T) {
	assert := require.New(t)
	cs := newBuilder(ecc.BN254, frontend.CompileConfig{})
	x := cs.newInternalVariable()

	// x must be 0, 1 or 2
	// x * (1 -x ) * (2 -x) == 0
	cs.AddQuadraticConstraint(x, cs.Mul(cs.Sub(1, x), cs.Sub(2, x)), 0, 0)

	assert.Equal(4, len(cs.Constraints), "expected 4 constraints")

}
