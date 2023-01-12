package gkr

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/utils/algo_utils"
	"math/bits"
	"sort"
)

type wireNoPtr struct {
	assignments     []frontend.Variable
	gate            Gate
	inputs          []int
	dependencies    []inputDependency // nil for input wires
	nbUniqueOutputs int
}

type circuitNoPtr []wireNoPtr

func (w wireNoPtr) isInput() bool {
	return len(w.inputs) == 0
}

func (w wireNoPtr) isOutput() bool {
	return w.nbUniqueOutputs == 0
}

type circuitDataNoPtr struct {
	circuit         circuitNoPtr
	maxNIns         int
	sortedInstances []int
	sortedWires     []int
}

type circuitDataForSnark struct {
	circuit     Circuit
	assignments WireAssignment
}

type circuitData struct {
	noPtr circuitDataNoPtr
	typed interface{} // curve-dependent data. for communication between solver and prover
}

type API struct {
	circuitData
}

type Solution struct {
	circuitData
	parentApi frontend.API
}

type Variable int // Just an alias to hide implementation details. May be more trouble than worth

func (c circuitNoPtr) nbInstances() int {
	for i := range c {
		if lenI := len(c[i].assignments); lenI != 0 {
			return lenI
		}
	}
	return -1
}

func (api *API) nbInstances() int {
	return api.noPtr.circuit.nbInstances()
}

func (api *API) logNbInstances() int {
	return log2(uint(api.nbInstances()))
}

// compile sorts the circuit wires, their dependencies and the instances
func (d *circuitDataNoPtr) compile() error { // (circuit Circuit, assignment WireAssignment) {

	nbInstances := d.circuit.nbInstances()
	// sort the instances to decide the order in which they are to be solved
	instanceDeps := make([][]int, nbInstances)
	for i := range d.circuit {
		for _, dep := range d.circuit[i].dependencies {
			instanceDeps[dep.inputInstance] = append(instanceDeps[dep.inputInstance], dep.outputInstance)
		}
	}

	d.sortedInstances, _ = algo_utils.TopologicalSort(instanceDeps)
	instancePermutationInv := algo_utils.InvertPermutation(d.sortedInstances)

	// this whole circuit sorting is a bit of a charade. if things are built using an api, there's no way it could NOT already be topologically sorted
	// worth keeping for future-proofing?

	inputs := algo_utils.Map(d.circuit, func(w wireNoPtr) []int {
		return w.inputs
	})

	var uniqueOuts [][]int
	d.sortedWires, uniqueOuts = algo_utils.TopologicalSort(inputs)
	wirePermutationInv := algo_utils.InvertPermutation(d.sortedWires)
	wirePermutationInvAt := algo_utils.SliceAt(wirePermutationInv)
	sorted := make([]wireNoPtr, len(d.circuit))
	for newI, oldI := range d.sortedWires {
		oldW := d.circuit[oldI]

		for i := 1; i < len(oldW.dependencies); i++ {
			if oldW.dependencies[i].inputInstance == oldW.dependencies[i-1].inputInstance {
				return fmt.Errorf("an input wire can only have one dependency per instance")
			}
		} // TODO: Check that dependencies and explicit assignments cover all instances

		if oldW.isInput() {
			algo_utils.Permute(oldW.assignments, instancePermutationInv)
			//oldW.assignments = algo_utils.Map(d.sortedInstances, algo_utils.SliceAt(oldW.assignments)) TODO: This if decided not to modify the user-given assignments
		} else {
			d.maxNIns = max(d.maxNIns, len(oldW.inputs))
		}

		for j := range oldW.dependencies {
			dep := &oldW.dependencies[j]
			dep.outputWire = wirePermutationInv[dep.outputWire]
			dep.inputInstance = instancePermutationInv[dep.inputInstance]
			dep.outputInstance = instancePermutationInv[dep.outputInstance]
		}

		sort.Slice(oldW.dependencies, func(i, j int) bool {
			return oldW.dependencies[i].inputInstance < oldW.dependencies[j].inputInstance
		})

		sorted[newI] = wireNoPtr{
			assignments:     oldW.assignments,
			gate:            oldW.gate,
			inputs:          algo_utils.Map(oldW.inputs, wirePermutationInvAt),
			dependencies:    oldW.dependencies,
			nbUniqueOutputs: len(uniqueOuts[oldI]),
		}

	}

	d.circuit = sorted

	return nil
}

func (d *circuitDataNoPtr) newInputVariable(assignment []frontend.Variable) Variable {
	i := len(d.circuit)
	d.circuit = append(d.circuit, wireNoPtr{assignments: assignment})
	return Variable(i)
}

func NewApi() *API {
	return &API{circuitData{
		noPtr: circuitDataNoPtr{
			circuit:         make(circuitNoPtr, 0),
			maxNIns:         0,
			sortedInstances: make([]int, 0),
		},
	}}
}

// log2 returns -1 if x is not a power of 2
func log2(x uint) int {
	if bits.OnesCount(x) != 1 {
		return -1
	}
	return bits.TrailingZeros(x)
}

// Series like in an electric circuit, binds an input of an instance to an output of another
func (api *API) Series(input, output frontend.Variable, inputInstance, outputInstance int) *API {
	i := input.(Variable)
	o := output.(Variable)
	if api.noPtr.circuit[i].assignments[inputInstance] != nil {
		panic("dependency attempting to override explicit value assignment")
	}
	api.noPtr.circuit[i].dependencies =
		append(api.noPtr.circuit[i].dependencies, inputDependency{
			outputWire:     int(o),
			outputInstance: outputInstance,
			inputInstance:  inputInstance,
		})
	return api
}

func (api *API) Import(assignment []frontend.Variable) (Variable, error) {
	nbInstances := len(assignment)
	logNbInstances := log2(uint(nbInstances))
	if logNbInstances == -1 {
		return -1, fmt.Errorf("number of assignments must be a power of 2")
	}

	if currentNbInstances := api.nbInstances(); currentNbInstances != -1 && currentNbInstances != nbInstances {
		return -1, fmt.Errorf("number of assignments must be consistent across all variables")
	}

	return api.noPtr.newInputVariable(assignment), nil
}

func appendNonNil(dst *[]frontend.Variable, src []frontend.Variable) {
	for i := range src {
		if src[i] != nil {
			*dst = append(*dst, src[i])
		}
	}
}

// Solve finalizes the GKR circuit and returns the output variables in the order created
func (api *API) Solve(parentApi frontend.API) (Solution, error) {

	if err := api.noPtr.compile(); err != nil {
		return Solution{}, err
	}

	nbInstances := api.nbInstances()
	circuit := api.noPtr.circuit

	solveHintNIn := 0
	solveHintNOut := 0

	for i := range circuit {
		v := &circuit[i]
		if v.isInput() {
			solveHintNIn += nbInstances - len(v.dependencies)
		} else if v.isOutput() {
			solveHintNOut += nbInstances
		}
	}

	// arrange inputs wire first, then in the order solved
	ins := make([]frontend.Variable, 0, solveHintNIn)
	for i := range circuit {
		if circuit[i].isInput() {
			appendNonNil(&ins, circuit[i].assignments)
		}
	}

	outsSerialized, err := parentApi.Compiler().NewHint(solveHint(&api.circuitData), solveHintNOut, ins...)
	if err != nil {
		return Solution{}, err
	}

	for i := range circuit {
		w := &circuit[i]
		if w.isOutput() {
			w.assignments = outsSerialized[:nbInstances]
			outsSerialized = outsSerialized[nbInstances:]
		}
	}

	for i := range circuit {
		for _, dep := range circuit[i].dependencies {
			circuit[i].assignments[dep.inputInstance] = circuit[dep.outputWire].assignments[dep.outputInstance]
		}
	}

	return Solution{
		circuitData: api.circuitData,
		parentApi:   parentApi,
	}, nil
}

func (s Solution) Export(v frontend.Variable) []frontend.Variable {
	return algo_utils.Map(s.noPtr.sortedInstances, algo_utils.SliceAt(s.noPtr.circuit[v.(Variable)].assignments))
}

func (s Solution) Verify(hash hash.Hash, initialChallenges ...frontend.Variable) error {
	// TODO: Translate transcriptSettings from snark to field ugh
	var (
		err             error
		proofSerialized []frontend.Variable
		proof           Proof
	)

	forSnark := s.noPtr.forSnark()
	logNbInstances := log2(uint(s.noPtr.circuit.nbInstances()))

	//	TODO: Find out if this hack is necessary
	/*for i := range s.noPtr.circuit {
		if s.noPtr.circuit[i].isOutput() {
			initialChallenges = append(initialChallenges, s.noPtr.circuit[i].assignments[0])
			break
		}
	}*/

	if proofSerialized, err = s.parentApi.Compiler().NewHint(
		proveHint(s.typed, hash), ProofSize(forSnark.circuit, logNbInstances), initialChallenges...); err != nil {
		return err
	}

	forSnarkSorted := algo_utils.MapRange(0, len(s.noPtr.circuit), slicePtrAt(forSnark.circuit))

	if proof, err = DeserializeProof(forSnarkSorted, proofSerialized); err != nil {
		return err
	}

	return Verify(s.parentApi, forSnark.circuit, forSnark.assignments, proof, fiatshamir.WithHash(hash, initialChallenges...), WithSortedCircuit(forSnarkSorted)) // TODO: Security critical: do a proper transcriptSetting

}

type inputDependency struct {
	outputWire     int
	outputInstance int
	inputInstance  int
}

func slicePtrAt[T any](slice []T) func(int) *T {
	return func(i int) *T {
		return &slice[i]
	}
}

func (d *circuitDataNoPtr) forSnark() circuitDataForSnark {
	circuit := make(Circuit, len(d.circuit))
	assignment := make(WireAssignment, len(d.circuit))
	circuitAt := slicePtrAt(circuit)
	for i := range circuit {
		w := d.circuit[i]
		circuit[i] = Wire{
			Gate:            w.gate,
			Inputs:          algo_utils.Map(w.inputs, circuitAt),
			nbUniqueOutputs: w.nbUniqueOutputs,
		}
		if !w.isInput() && !w.isOutput() && w.assignments != nil { // TODO: Remove
			panic("unexpected!!")
		}
		assignment[&circuit[i]] = w.assignments
	}
	return circuitDataForSnark{
		circuit:     circuit,
		assignments: assignment,
	}
}

// assignmentOffsets returns the index of the first value assigned to a wire TODO: Explain clearly
func (c circuitNoPtr) assignmentOffsets() []int {
	res := make([]int, len(c)+1)
	nbInstances := c.nbInstances()
	for i := range c {
		nbExplicitAssignments := 0
		if c[i].isInput() {
			nbExplicitAssignments = nbInstances - len(c[i].dependencies)
		}
		res[i+1] = res[i] + nbExplicitAssignments
	}
	return res
}
