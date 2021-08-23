/*
	Original Copyright 2015 https://gitlab.com/NebulousLabs
*/

/*
The MIT License (MIT)

Copyright (c) 2015 Nebulous

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

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

// Package merkle provides a ZKP-circuit function to verify merkle proofs.
package merkle

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// leafSum returns the hash created from data inserted to form a leaf.
// Without domain separation.
func leafSum(cs *frontend.ConstraintSystem, h mimc.MiMC, data frontend.Variable) frontend.Variable {

	h.Write(data)
	res := h.Sum()

	return res
}

// nodeSum returns the hash created from data inserted to form a leaf.
// Without domain separation.
func nodeSum(cs *frontend.ConstraintSystem, h mimc.MiMC, a, b frontend.Variable) frontend.Variable {

	h.Write(a, b)
	//res := h.Sum(a, b)
	res := h.Sum()

	return res
}

// GenerateProofHelper generates an array of 1 or 0 telling if during the proof verification
// the hash to compute is h(sum, proof[i]) or h(proof[i], sum). The size of the resulting slice is
// len(proofSet)-1.
// cf gitlab.com/NebulousLabs/merkletree for the algorithm
func GenerateProofHelper(proofSet [][]byte, proofIndex, numLeaves uint64) []int {

	res := make([]int, len(proofSet)-1)

	height := 1

	// While the current subtree (of height 'height') is complete, determine
	// the position of the next sibling using the complete subtree algorithm.
	// 'stableEnd' tells us the ending index of the last full subtree. It gets
	// initialized to 'proofIndex' because the first full subtree was the
	// subtree of height 1, created above (and had an ending index of
	// 'proofIndex').
	stableEnd := proofIndex
	for {
		// Determine if the subtree is complete. This is accomplished by
		// rounding down the proofIndex to the nearest 1 << 'height', adding 1
		// << 'height', and comparing the result to the number of leaves in the
		// Merkle tree.
		subTreeStartIndex := (proofIndex / (1 << uint(height))) * (1 << uint(height)) // round down to the nearest 1 << height
		subTreeEndIndex := subTreeStartIndex + (1 << (uint(height))) - 1              // subtract 1 because the start index is inclusive
		if subTreeEndIndex >= numLeaves {
			// If the Merkle tree does not have a leaf at index
			// 'subTreeEndIndex', then the subtree of the current height is not
			// a complete subtree.
			break
		}
		stableEnd = subTreeEndIndex

		if proofIndex-subTreeStartIndex < 1<<uint(height-1) {
			res[height-1] = 1
		} else {
			res[height-1] = 0
		}
		height++
	}

	// Determine if the next hash belongs to an orphan that was elevated. This
	// is the case IFF 'stableEnd' (the last index of the largest full subtree)
	// is equal to the number of leaves in the Merkle tree.
	if stableEnd != numLeaves-1 {
		res[height-1] = 1
		height++
	}

	// All remaining elements in the proof set will belong to a left sibling.
	for height < len(proofSet) {
		res[height-1] = 0
		height++
	}

	return res
}

// VerifyProof takes a Merkle root, a proofSet, and a proofIndex and returns
// true if the first element of the proof set is a leaf of data in the Merkle
// root. False is returned if the proof set or Merkle root is nil, and if
// 'numLeaves' equals 0.
func VerifyProof(cs *frontend.ConstraintSystem, h mimc.MiMC, merkleRoot frontend.Variable, proofSet, helper []frontend.Variable) {

	sum := leafSum(cs, h, proofSet[0])

	for i := 1; i < len(proofSet); i++ {
		cs.AssertIsBoolean(helper[i-1])
		d1 := cs.Select(helper[i-1], sum, proofSet[i])
		d2 := cs.Select(helper[i-1], proofSet[i], sum)
		sum = nodeSum(cs, h, d1, d2)
	}

	// Compare our calculated Merkle root to the desired Merkle root.
	cs.AssertIsEqual(sum, merkleRoot)

}
