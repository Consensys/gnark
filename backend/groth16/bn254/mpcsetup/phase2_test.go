package mpcsetup

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPhase2WithCustomRandomSource(t *testing.T) {
	// Create a test random source
	testRandomSource := bytes.NewReader(make([]byte, 32))

	// Create options with custom random source
	options := DefaultPhase2Options().WithRandomSource(testRandomSource)

	// Create a new Phase2 instance with options
	phase2 := NewPhase2(options)

	// Check that options are set correctly
	assert.NotNil(t, phase2.options)
	assert.Equal(t, testRandomSource, phase2.options.RandomSource)

	// Generate contribution
	err := phase2.GenerateContribution()
	require.NoError(t, err)

	// Check that contribution was generated
	assert.NotNil(t, phase2.Parameters)
	assert.NotNil(t, phase2.Parameters.G1.Delta)
	assert.NotNil(t, phase2.Parameters.G2.Delta)
}

func TestPhase2WithDefaultOptions(t *testing.T) {
	// Create Phase2 with default options
	phase2 := NewPhase2(nil)

	// Check that default options are set
	assert.NotNil(t, phase2.options)
	assert.NotNil(t, phase2.options.RandomSource)

	// Generate contribution
	err := phase2.GenerateContribution()
	require.NoError(t, err)

	// Check that contribution was generated
	assert.NotNil(t, phase2.Parameters)
	assert.NotNil(t, phase2.Parameters.G1.Delta)
	assert.NotNil(t, phase2.Parameters.G2.Delta)
}
