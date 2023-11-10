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

package sw_bls24315

import (
	"sync"

	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
)

// precomputed lines going through Q and multiples of Q
// where Q is the fixed canonical generator of G2
//
// Q.X.B0.A0 = 0x2f339ada8942f92aefa14196bfee2552a7c5675f5e5e9da798458f72ff50f96f5c357cf13710f63
// Q.X.B0.A1 = 0x20b1a8dca4b18842b40079be727cbfd1a16ed134a080b759ae503618e92871697838dc4c689911c
// Q.X.B1.A0 = 0x16eab1e76670eb9affa1bc77400be688d5cd69566f9325b329b40db85b47f236d5c34e8ffed7536
// Q.X.B1.A1 = 0x6e8c608261f21c41f2479ca4824deba561b9689a9c03a5b8b36a6cbbed0a7d9468e07e557d8569
// Q.Y.B0.A0 = 0x3cdd8218baa5276421c9923cde33a45399a1d878d5202fae600a8502a29681f74ccdcc053b278b7
// Q.Y.B0.A1 = 0x3a079c670190bb49b1bd21e10aac3191535e32ce99da592ddfa8bd09d57a7374ed63ad7f25e398d
// Q.Y.B1.A0 = 0x1b38dd0c5ec49a0883a950c631c688eb3b01f45b7c0d2990cd99052005ebf2fa9e7043bbd605ef5
// Q.Y.B1.A1 = 0x495d6de2e4fed6be3e1d24dd724163e01d88643f7e83d31528ab0a80ced619175a1a104574ac83

var precomputedLines [2][32]lineEvaluation
var precomputedLinesOnce sync.Once

func getPrecomputedLines() [2][32]lineEvaluation {
	precomputedLinesOnce.Do(func() {
		precomputedLines = computePrecomputedLines()
	})
	return precomputedLines
}

func computePrecomputedLines() [2][32]lineEvaluation {
	var PrecomputedLines [2][32]lineEvaluation
	_, _, _, G2AffGen := bls24315.Generators()
	lines := bls24315.PrecomputeLines(G2AffGen)
	for j := 0; j < 32; j++ {
		PrecomputedLines[0][j].R0.Assign(&lines[0][j].R0)
		PrecomputedLines[0][j].R1.Assign(&lines[0][j].R1)
		PrecomputedLines[1][j].R0.Assign(&lines[1][j].R0)
		PrecomputedLines[1][j].R1.Assign(&lines[1][j].R1)

	}

	return PrecomputedLines
}
