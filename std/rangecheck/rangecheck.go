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
func New(api frontend.API) frontend.Rangechecker {
	if rc, ok := api.(frontend.Rangechecker); ok {
		return rc
	}
	if _, ok := api.(frontend.Committer); ok {
		return newCommitRangechecker(api)
	}
	if _, ok := api.(frontend.WideCommitter); ok {
		// native field extension package does not support inversion for now which is required
		// for the logderivate argument. However, we use wide committer only for small fields
		// where the backend already knows how to range check (and should implement Rangechecker interface).
		// So we can just panic here to detect the case when the backend does not implement
		// the range checker interface.
		//
		// See https://github.com/Consensys/gnark/pull/1493
		panic("wide committer does not support operations for range checking")
	}
	return plainChecker{api: api}
}

// GetHints returns all hints used in this package
func GetHints() []solver.Hint {
	return []solver.Hint{DecomposeHint}
}
