package mpcsetup

import (
	"crypto/rand"
	"io"
)

// Phase2Options contains configuration options for Phase2
type Phase2Options struct {
	// RandomSource is the source of randomness for contribution generation
	RandomSource io.Reader
}

// DefaultPhase2Options returns default options for Phase2
func DefaultPhase2Options() *Phase2Options {
	return &Phase2Options{
		RandomSource: rand.Reader,
	}
}

// WithRandomSource sets a custom random source for Phase2Options
func (o *Phase2Options) WithRandomSource(source io.Reader) *Phase2Options {
	o.RandomSource = source
	return o
}
