package gkr

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/utils/algo_utils"
	"math/bits"
)

type wireNoPtr struct {
	assignments  []frontend.Variable
	gate         Gate
	inputs       []int
	dependencies []inputDependency // nil for input wires
	isOutput     bool
}

func (w wireNoPtr) isInput() bool {
	return len(w.inputs) == 0
}

type circuitDataNoPtr struct {
	circuit         []wireNoPtr
	maxNIns         int
	sortedInstances []int
}

type circuitDataForSnark struct {
	circuit     Circuit
	assignments [][]frontend.Variable
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

func (d *circuitDataNoPtr) nbInstances() int {
	for i := range d.circuit {
		if lenI := len(d.circuit[i].inputs); lenI != 0 {
			return lenI
		}
	}
	return -1
}

func (i *API) nbInstances() int {
	return i.noPtr.nbInstances()
}

func (i *API) logNbInstances() int {
	return logNbInstances(uint(i.nbInstances()))
}

func (d *circuitDataNoPtr) compile() (circuit Circuit, assignment WireAssignment) {

	inputs := algo_utils.Map(d.circuit, func(w wireNoPtr) []int {
		return w.inputs
	})

	sorted, uniqueNbOuts := algo_utils.TopologicalSort(inputs)

	circuitInputsIndex = make([][]int, len(inputs))
	for i := range circuitInputsIndex {
		circuitInputsIndex[i] = algo_utils.Map(inputs[i], algo_utils.SliceAt(sorted))
	}

	circuit = make(Circuit, len(*d))
	circuitPtrAt := slicePtrAt(circuit)
	for i := range circuit {
		circuit[i] = Wire{
			Gate:            (*d)[sorted[i]].gate,
			Inputs:          algo_utils.Map(circuitInputsIndex[i], circuitPtrAt),
			nbUniqueOutputs: len(uniqueNbOuts[i]),
		}
	}

	circuit = make(Circuit, len(*d))
	assignment = make(WireAssignment, len(*d))

	at := func(i int) *Wire {
		return &circuit[i]
	}
	for i := range circuit {
		cI := (*d)[i]
		circuit[i].Inputs = algo_utils.Map(cI.inputs, at)
		assignment[&circuit[i]] = cI.assignments
	}
	return
}

func (d *circuitDataNoPtr) newVariable(assignment []frontend.Variable) Variable {
	i := len(*d)
	*d = append(*d, wireNoPtr{assignments: assignment})
	return Variable(i)
}

func (i *API) isCompiled() bool {
	return i.dataNoPtr == nil
}

func NewApi() *API {
	return &API{dataNoPtr: make(circuitDataNoPtr, 0), logNbInstances: -1}
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
	i.dataNoPtr[input].assignments[inputInstance] = inputDependency{
		Output:         output,
		OutputInstance: outputInstance,
	}
	return i
}

func (i *API) Import(assignment []frontend.Variable) (Variable, error) {
	if i.isCompiled() {
		return -1, fmt.Errorf("cannot import variables into compiled circuit")
	}
	nbInstances := uint(len(assignment))
	logNbInstances := logNbInstances(nbInstances)
	if logNbInstances == -1 {
		return -1, fmt.Errorf("number of assignments must be a power of 2")
	}
	if i.logNbInstances == -1 {
		i.logNbInstances = logNbInstances
	} else if logNbInstances != i.logNbInstances {
		return -1, fmt.Errorf("number of assignments must be consistent across all variables")
	}

	return i.dataNoPtr.newVariable(assignment), nil
}

func (i *API) nbInputValueAssignments(variable Variable) int {
	res := 0
	for j := range i.assignments[variable] {
		if _, ok := i.assignments[variable][j].(inputDependency); !ok {
			res++
		}
	}
	return res
}

// Compile finalizes the GKR circuit and returns the output variables in the order created
func (i *API) Compile(parentApi frontend.API) ([][]frontend.Variable, error) {
	if i.isCompiled {
		return nil, fmt.Errorf("already compiled")
	}
	i.isCompiled = true

	i.compiled.sorted = topologicalSort(i.circuit) // unnecessary(?) but harmless
	i.compiled.nbInstances = 1 << i.logNbInstances
	indexMap := circuitIndexMap(i.compiled.sorted)
	i.compiled.circuitInputsIndex, i.compiled.inputIndexes =
		circuitInputsIndex(i.compiled.sorted, indexMap)

	solveHintNIn := 0
	solveHintNOut := 0
	for j := range i.circuit {
		v := &i.circuit[j]
		if v.IsInput() {
			solveHintNIn += i.nbInputValueAssignments(v)
		} else if v.IsOutput() {
			solveHintNOut += i.compiled.nbInstances
		}
	}

	ins := make([]frontend.Variable, 0, solveHintNIn)
	for j := range i.circuit {
		if i.circuit[j].IsInput() {
			assignment := i.assignments[&i.circuit[j]]
			for k := range assignment {
				if _, ok := assignment[k].(inputDependency); !ok {
					ins = append(ins, assignment[k])
				}
			}
		} else {
			i.compiled.maxGateDegree = max(i.compiled.maxGateDegree, i.circuit[j].Gate.Degree())
		}
	}

	i.compiled.circuitInputsIndex, i.compiled.inputIndexes = circuitInputsIndex(i.compiled.sorted, indexMap)

	outsSerialized, err := parentApi.Compiler().NewHint(solveHint(&i.compiled), solveHintNOut, ins...)
	if err != nil {
		return nil, err
	}

	outs := make([][]frontend.Variable, len(outsSerialized)/i.compiled.nbInstances)

	for j := range outs {
		outs[j] = outsSerialized[:i.compiled.nbInstances]
		outsSerialized = outsSerialized[i.compiled.nbInstances:]
	}

	var (
		proofSerialized []frontend.Variable
		proof           Proof
		_mimc           mimc.MiMC
	)
	if proofSerialized, err = parentApi.Compiler().NewHint(proveHint(&i.compiled), ProofSize(i.circuit, i.logNbInstances)); // , outsSerialized[0]	<- do this as a hack if order of execution got messed up
	err != nil {
		return nil, err
	}
	if proof, err = DeserializeProof(i.compiled.sorted, proofSerialized); err != nil {
		return nil, err
	}
	if _mimc, err = mimc.NewMiMC(parentApi); err != nil {
		return nil, err
	}

	i.addOutAssignments(outs)
	if err = Verify(parentApi, i.circuit, i.assignments, proof, fiatshamir.WithHash(&_mimc), WithSortedCircuit(i.compiled.sorted)); err != nil { // TODO: Security critical: do a proper transcriptSetting

	}

	return outs, nil
}

func (i *API) addOutAssignments(outs [][]frontend.Variable) {
	// TODO: Increase map size here, since we already know how many we're adding?
	outI := 0
	for _, w := range i.compiled.sorted {
		if w.IsOutput() {
			i.assignments[w] = outs[outI]
			outI++
		}
	}
}

func circuitIndexMap(sorted []*Wire) map[*Wire]int {
	indexes := make(map[*Wire]int, len(sorted))
	for i := range sorted {
		indexes[sorted[i]] = i
	}
	return indexes
}

// circuitInputsIndex returns a description of the circuit, with indexes instead of pointers. It also returns the indexes of the input wires
func circuitInputsIndex(sorted []*Wire, indexes map[*Wire]int) ([][]int, []int) {
	res := make([][]int, len(sorted))
	inputIndexes := make([]int, 0)
	for i, w := range sorted {
		if w.IsInput() {
			inputIndexes = append(inputIndexes, i)
		}
		res[i] = Map(w.Inputs, func(v *Wire) int {
			return indexes[v] // is it possible to pass a reference to a particular map object's [] operator?
		})
	}

	return res, inputIndexes
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
