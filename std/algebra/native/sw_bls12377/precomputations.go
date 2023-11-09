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
	"github.com/consensys/gnark/std/algebra/native/fields_bls12377"
)

// precomputed lines going through Q and multiples of Q
// where Q is the fixed canonical generator of G2
//
// Q.X.A0 = 0x18480be71c785fec89630a2a3841d01c565f071203e50317ea501f557db6b9b71889f52bb53540274e3e48f7c005196
// Q.X.A1 = 0xea6040e700403170dc5a51b1b140d5532777ee6651cecbe7223ece0799c9de5cf89984bff76fe6b26bfefa6ea16afe
// Q.Y.A0 = 0x690d665d446f7bd960736bcbb2efb4de03ed7274b49a58e458c282f832d204f2cf88886d8c7c2ef094094409fd4ddf
// Q.Y.A1 = 0xf8169fd28355189e549da3151a70aa61ef11ac3d591bf12463b01acee304c24279b83f5e52270bd9a1cdd185eb8f93

var precomputedLines [4][63]fields_bls12377.E2
var precomputedLinesOnce sync.Once

func getPrecomputedLines() [4][63]fields_bls12377.E2 {
	precomputedLinesOnce.Do(func() {
		precomputedLines = computePrecomputedLines()
	})
	return precomputedLines
}

func computePrecomputedLines() [4][63]fields_bls12377.E2 {
	var PrecomputedLines [4][63]fields_bls12377.E2
	_, _, _, G2AffGen := bls12377.Generators()
	lines := bls12377.PrecomputeLines(G2AffGen)
	for j := 0; j < 63; j++ {
		PrecomputedLines[0][j].Assign(&lines[0][j].R0)
		PrecomputedLines[1][j].Assign(&lines[0][j].R1)
		PrecomputedLines[2][j].Assign(&lines[1][j].R0)
		PrecomputedLines[3][j].Assign(&lines[1][j].R1)
	}

	return PrecomputedLines
}
