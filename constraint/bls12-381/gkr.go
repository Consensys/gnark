// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by gnark DO NOT EDIT

package cs

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/gkr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/polynomial"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/utils"
	"github.com/consensys/gnark/constraint"
	hint "github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/utils/algo_utils"
	"hash"
	"math/big"
	"sync"
)

type GkrSolvingData struct {
	assignments gkr.WireAssignment
	circuit     gkr.Circuit
	memoryPool  polynomial.Pool
	workers     *utils.WorkerPool
}

func convertCircuit(noPtr constraint.GkrCircuit) (gkr.Circuit, error) {
	resCircuit := make(gkr.Circuit, len(noPtr))
	var found bool
	for i := range noPtr {
		if resCircuit[i].Gate, found = gkr.Gates[noPtr[i].Gate]; !found && noPtr[i].Gate != "" {
			return nil, fmt.Errorf("gate \"%s\" not found", noPtr[i].Gate)
		}
		resCircuit[i].Inputs = algo_utils.Map(noPtr[i].Inputs, algo_utils.SlicePtrAt(resCircuit))
	}
	return resCircuit, nil
}

func (d *GkrSolvingData) init(info constraint.GkrInfo) (assignment gkrAssignment, err error) {
	if d.circuit, err = convertCircuit(info.Circuit); err != nil {
		return
	}
	d.memoryPool = polynomial.NewPool(d.circuit.MemoryRequirements(info.NbInstances)...)
	d.workers = utils.NewWorkerPool()

	assignment = make(gkrAssignment, len(d.circuit))
	d.assignments = make(gkr.WireAssignment, len(d.circuit))
	for i := range assignment {
		assignment[i] = d.memoryPool.Make(info.NbInstances)
		d.assignments[&d.circuit[i]] = assignment[i]
	}
	return
}

func (d *GkrSolvingData) dumpAssignments() {
	for _, p := range d.assignments {
		d.memoryPool.Dump(p)
	}
}

// this module assumes that wire and instance indexes respect dependencies

type gkrAssignment [][]fr.Element //gkrAssignment is indexed wire first, instance second

func (a gkrAssignment) setOuts(circuit constraint.GkrCircuit, outs []*big.Int) {
	outsI := 0
	for i := range circuit {
		if circuit[i].IsOutput() {
			for j := range a[i] {
				a[i][j].BigInt(outs[outsI])
				outsI++
			}
		}
	}
	// Check if outsI == len(outs)?
}

func GkrSolveHint(info constraint.GkrInfo, solvingData *GkrSolvingData) hint.Hint {
	return func(_ *big.Int, ins, outs []*big.Int) error {
		// assumes assignmentVector is arranged wire first, instance second in order of solution
		circuit := info.Circuit
		nbInstances := info.NbInstances
		offsets := info.AssignmentOffsets()
		assignment, err := solvingData.init(info)
		if err != nil {
			return err
		}
		chunks := circuit.Chunks(nbInstances)

		solveTask := func(chunkOffset int) utils.Task {
			return func(startInChunk, endInChunk int) {
				start := startInChunk + chunkOffset
				end := endInChunk + chunkOffset
				inputs := solvingData.memoryPool.Make(info.MaxNIns)
				dependencyHeads := make([]int, len(circuit))
				for wI, w := range circuit {
					dependencyHeads[wI] = algo_utils.BinarySearchFunc(func(i int) int {
						return w.Dependencies[i].InputInstance
					}, len(w.Dependencies), start)
				}

				for instanceI := start; instanceI < end; instanceI++ {
					for wireI, wire := range circuit {
						if wire.IsInput() {
							if dependencyHeads[wireI] < len(wire.Dependencies) && instanceI == wire.Dependencies[dependencyHeads[wireI]].InputInstance {
								dep := wire.Dependencies[dependencyHeads[wireI]]
								assignment[wireI][instanceI].Set(&assignment[dep.OutputWire][dep.OutputInstance])
								dependencyHeads[wireI]++
							} else {
								assignment[wireI][instanceI].SetBigInt(ins[offsets[wireI]+instanceI-dependencyHeads[wireI]])
							}
						} else {
							// assemble the inputs
							inputIndexes := info.Circuit[wireI].Inputs
							for i, inputI := range inputIndexes {
								inputs[i].Set(&assignment[inputI][instanceI])
							}
							gate := solvingData.circuit[wireI].Gate
							assignment[wireI][instanceI] = gate.Evaluate(inputs[:len(inputIndexes)]...)
						}
					}
				}
				solvingData.memoryPool.Dump(inputs)
			}
		}

		start := 0
		for _, end := range chunks {
			solvingData.workers.Submit(end-start, solveTask(start), 1024).Wait()
			start = end
		}

		assignment.setOuts(info.Circuit, outs)

		return nil
	}
}

func frToBigInts(dst []*big.Int, src []fr.Element) {
	for i := range src {
		src[i].BigInt(dst[i])
	}
}

func GkrProveHint(hashName string, data *GkrSolvingData) hint.Hint {

	return func(_ *big.Int, ins, outs []*big.Int) error {
		insBytes := algo_utils.Map(ins[1:], func(i *big.Int) []byte { // the first input is dummy, just to ensure the solver's work is done before the prover is called
			b := make([]byte, fr.Bytes)
			i.FillBytes(b)
			return b[:]
		})

		hsh, err := GetHashBuilder(hashName)
		if err != nil {
			return err
		}

		proof, err := gkr.Prove(data.circuit, data.assignments, fiatshamir.WithHash(hsh(), insBytes...), gkr.WithPool(&data.memoryPool), gkr.WithWorkers(data.workers))
		if err != nil {
			return err
		}

		// serialize proof: TODO: In gnark-crypto?
		offset := 0
		for i := range proof {
			for _, poly := range proof[i].PartialSumPolys {
				frToBigInts(outs[offset:], poly)
				offset += len(poly)
			}
			if proof[i].FinalEvalProof != nil {
				finalEvalProof := proof[i].FinalEvalProof.([]fr.Element)
				frToBigInts(outs[offset:], finalEvalProof)
				offset += len(finalEvalProof)
			}
		}

		data.dumpAssignments()

		return nil

	}
}

// TODO: Move to gnark-crypto
var (
	hashBuilderRegistry = make(map[string]func() hash.Hash)
	hasBuilderLock      sync.RWMutex
)

func RegisterHashBuilder(name string, builder func() hash.Hash) {
	hasBuilderLock.Lock()
	defer hasBuilderLock.Unlock()
	hashBuilderRegistry[name] = builder
}

func GetHashBuilder(name string) (func() hash.Hash, error) {
	hasBuilderLock.RLock()
	defer hasBuilderLock.RUnlock()
	builder, ok := hashBuilderRegistry[name]
	if !ok {
		return nil, fmt.Errorf("hash function not found")
	}
	return builder, nil
}
