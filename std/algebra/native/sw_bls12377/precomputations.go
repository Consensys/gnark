/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sw_bls12377

import (
	"sync"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
)

// precomputed lines going through Q where Q is a fixed point in G2
var precomputedLines [2]LineEvaluations
var precomputedLinesOnce sync.Once

func getPrecomputedLines(Q bls12377.G2Affine) [2]LineEvaluations {
	precomputedLinesOnce.Do(func() {
		precomputedLines = precomputeLines(Q)
	})
	return precomputedLines
}

func precomputeLines(Q bls12377.G2Affine) [2]LineEvaluations {
	var PrecomputedLines [2]LineEvaluations
	lines := bls12377.PrecomputeLines(Q)
	for j := 0; j < 63; j++ {
		PrecomputedLines[0].Eval[j].R0.Assign(&lines[0][j].R0)
		PrecomputedLines[0].Eval[j].R1.Assign(&lines[0][j].R1)
		PrecomputedLines[1].Eval[j].R0.Assign(&lines[1][j].R0)
		PrecomputedLines[1].Eval[j].R1.Assign(&lines[1][j].R1)
	}

	return PrecomputedLines
}
