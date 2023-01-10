package gkr

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/hash/mimc"
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
	noPtr    circuitDataNoPtr
	forSnark circuitDataForSnark
	typed    interface{} // curve-dependent data. for communication between solver and prover
}

type API struct {
	circuitData
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

func (i *API) nbInstances() int {
	return i.noPtr.circuit.nbInstances()
}

func (i *API) logNbInstances() int {
	return logNbInstances(uint(i.nbInstances()))
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
	//instancePermutationInvAt := algo_utils.SliceAt(instancePermutationInv)

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

		if !oldW.isInput() {
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

		algo_utils.Permute(oldW.assignments, instancePermutationInv)

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

func (i *API) isCompiled() bool {
	return i.forSnark.circuit != nil
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

// logNbInstances returns -1 if nbInstances is not a power of 2
func logNbInstances(nbInstances uint) int {
	if bits.OnesCount(nbInstances) != 1 {
		return -1
	}
	return bits.TrailingZeros(nbInstances)
}

// Series like in an electric circuit, binds an input of an instance to an output of another
func (i *API) Series(input, output Variable, inputInstance, outputInstance int) *API {
	if i.noPtr.circuit[input].assignments[inputInstance] != nil {
		panic("dependency attempting to override explicit value assignment")
	}
	i.noPtr.circuit[input].dependencies =
		append(i.noPtr.circuit[input].dependencies, inputDependency{
			outputWire:     int(output),
			outputInstance: outputInstance,
			inputInstance:  inputInstance,
		})
	return i
}

func (i *API) Import(assignment []frontend.Variable) (Variable, error) {
	if i.isCompiled() {
		return -1, fmt.Errorf("cannot import variables into compiled circuit")
	}
	nbInstances := len(assignment)
	logNbInstances := logNbInstances(uint(nbInstances))
	if logNbInstances == -1 {
		return -1, fmt.Errorf("number of assignments must be a power of 2")
	}

	if currentNbInstances := i.nbInstances(); currentNbInstances != -1 && currentNbInstances != nbInstances {
		return -1, fmt.Errorf("number of assignments must be consistent across all variables")
	}

	return i.noPtr.newInputVariable(assignment), nil
}

func appendNonNil(dst *[]frontend.Variable, src []frontend.Variable) {
	for i := range src {
		if src[i] != nil {
			*dst = append(*dst, src[i])
		}
	}
}

// Compile finalizes the GKR circuit and returns the output variables in the order created
func (i *API) Compile(parentApi frontend.API) ([][]frontend.Variable, error) {
	if i.isCompiled() {
		return nil, fmt.Errorf("already compiled")
	}

	if err := i.noPtr.compile(); err != nil {
		return nil, err
	}
	nbInstances := i.nbInstances()
	circuit := i.noPtr.circuit

	solveHintNIn := 0
	solveHintNOut := 0

	for j := range circuit {
		v := &circuit[j]
		if v.isInput() {
			solveHintNIn += nbInstances - len(v.dependencies)
		} else if v.isOutput() {
			solveHintNOut += nbInstances
		}
	}

	// arrange inputs wire first, then in the order solved
	ins := make([]frontend.Variable, 0, solveHintNIn)
	for j := range circuit {
		if circuit[j].isInput() {
			appendNonNil(&ins, circuit[j].assignments)
		}
	}

	outsSerialized, err := parentApi.Compiler().NewHint(solveHint(&i.circuitData), solveHintNOut, ins...)
	if err != nil {
		return nil, err
	}

	outs := make([][]frontend.Variable, len(outsSerialized)/nbInstances)

	for j := range outs {
		outs[j] = outsSerialized[:nbInstances]
		outsSerialized = outsSerialized[nbInstances:]
	}

	i.noPtr.circuit.addOutputAssignments(outs)

	var (
		proofSerialized []frontend.Variable
		proof           Proof
		_mimc           mimc.MiMC
	)

	i.forSnark = i.noPtr.forSnark()

	if proofSerialized, err = parentApi.Compiler().NewHint(
		proveHint(i.typed), ProofSize(i.forSnark.circuit, logNbInstances(uint(nbInstances)))); // , outsSerialized[0]	<- do this as a hack if order of execution got messed up
	err != nil {
		return nil, err
	}

	forSnarkSorted := algo_utils.MapRange(0, len(circuit), slicePtrAt(i.forSnark.circuit))

	if proof, err = DeserializeProof(forSnarkSorted, proofSerialized); err != nil {
		return nil, err
	}
	if _mimc, err = mimc.NewMiMC(parentApi); err != nil {
		return nil, err
	}

	if err = Verify(parentApi, i.forSnark.circuit, i.forSnark.assignments, proof, fiatshamir.WithHash(&_mimc), WithSortedCircuit(forSnarkSorted)); err != nil { // TODO: Security critical: do a proper transcriptSetting
		return nil, err
	}

	i.noPtr.toVirtualOrder(outs)

	return outs, nil
}

// completeAssignments creates assignment fields for the output vars and input instances that depend on them
func (c circuitNoPtr) addOutputAssignments(outs [][]frontend.Variable) {
	outI := 0
	for i := range c {
		if c[i].isOutput() {
			c[i].assignments = outs[outI]
			outI++
		}
	}
	for i := range c {
		if c[i].dependencies != nil && !c[i].isInput() { // TODO: Remove
			panic("data structure poorly maintained")
		}
		for _, dep := range c[i].dependencies {
			c[i].assignments[dep.inputInstance] = c[dep.outputWire].assignments[dep.outputInstance]
		}
	}
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

func (d *circuitDataNoPtr) toVirtualOrder(outs [][]frontend.Variable) {
	for j := range d.circuit {
		algo_utils.Permute(outs[j], d.sortedInstances)
	}
	algo_utils.Permute(outs, d.sortedWires)
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
