// Package rangecheck implements range checking gadget
//
// This package chooses the most optimal path for performing range checks:
//   - if the backend supports native range checking and the frontend exports the variables in the proprietary format by implementing [frontend.Rangechecker], then use it directly;
//   - if the backend supports creating a commitment of variables by implementing [frontend.Committer], then we use the log-derivative variant [[Haböck22]] of the product argument as in [[BCG+18]].
//   - lacking these, we perform binary decomposition of variable into bits.
//
// [BCG+18]: https://eprint.iacr.org/2018/380
// [Haböck22]: https://eprint.iacr.org/2022/1530
package rangecheck

import (
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

// New returns a new range checker depending on the frontend capabilities.
func New(api frontend.API, opts ...Option) frontend.Rangechecker {
	if rc, ok := api.(frontend.Rangechecker); ok {
		return rc
	}
	if _, ok := api.(frontend.Committer); ok {
		return newCommitRangechecker(api, opts...)
	}
	if _, ok := api.(frontend.WideCommitter); ok {
		return newCommitRangechecker(api, opts...)
	}
	return plainChecker{api: api}
}

// GetHints returns all hints used in this package
func GetHints() []solver.Hint {
	return []solver.Hint{DecomposeHint}
}

type config struct {
	baseLength int
}

func newConfig(opts ...Option) (*config, error) {
	cfg := &config{
		baseLength: 0, // 0 means "auto"
	}
	for _, o := range opts {
		if err := o(cfg); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

// Option is a rangecheck option which allows to customize the rangecheck behavior.
type Option func(*config) error

// WithBaseLength sets the base length to use in the decomposition.
//
// Normally, the committer-based rangechecker finds an optimal table size to
// minimize the number of constraints used for constructing the lookup table and
// performing the range checks. When the table size is smaller than the variable
// size, the variable is decomposed into chunks of size baseLength. We then
// perform range checks on each chunk and show that the initial variable is
// reconstructed from these chunks.
//
// However, when the input variable does not fit exactly into chunks of size
// baseLength, the last chunk will be smaller. The range check on this last
// chunk is performed twice for the chunk and 2^(baselength-lastChunkSize)
// lastChunk. This means that for the last chunk we add two range checks instead
// of one, which can be suboptimal.
//
// By setting the baseLength manually, the user can control the chunk size and
// avoid this double range check on the last chunk. For example, if the input
// variable is 10 bits long, setting baseLength to 5 will result in two chunks
// of size 5 bits each, and only one range check per chunk.
//
// Note that this option only has an effect when using the committer-based
// rangechecker (i.e., when the backend implements frontend.Committer).
//
// As the range checker is cached in the compiler context and we don't have a
// global initializer, then setting this option will override any previous
// setting for the range checker in the same context. Having conflicting options
// called in different parts of the code does not produce an error, but the last
// option called will take precedence. We will log a warning when this happens.
func WithBaseLength(baseLength int) Option {
	return func(o *config) error {
		o.baseLength = baseLength
		return nil
	}
}
