package gkr

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/gkr"
	"math/bits"
)

type API struct {
	compiled       bool
	logNbInstances int
	circuitData    CircuitData
	circuit        Circuit
	assignments    map[Variable][]frontend.Variable
}

type CircuitData struct {
	Sorted             []*Wire
	NbInstances        int
	CircuitInputsIndex [][]int
	InputIndexes       []int
}

type Variable *Wire

func (i *API) NbInstances() int {
	return 1 << i.logNbInstances
}

func NewGkrApi() *API {
	return &API{circuit: make(Circuit, 0), assignments: make(map[Variable][]frontend.Variable), logNbInstances: -1}
	/*var res API
	res.inOutEqualities = make([][2]int, len(inOutEqualities))
	copy(res.inOutEqualities, inOutEqualities)
	sort.Slice(res.inOutEqualities, func(i int, j int) bool {
		if res.inOutEqualities[i][0] < res.inOutEqualities[j][0] {
			return true
		}
		return res.inOutEqualities[i][1] < res.inOutEqualities[j][1]
	})


	if len(inOutEqualities) == 0 {
		res.nbOutputBoundIns = 0
	} else {
		res.nbOutputBoundIns = 1
		for i := 1; i < len(res.inOutEqualities); i++ {
			if res.inOutEqualities[i][0] != res.inOutEqualities[i][1] {

			}
		}
	}
	res.inOutEqualities = inOutEqualities
	res.circuit = make(Circuit, 0, len(inOutEqualities))

	return res*/
}

func logNbInstances(nbInstances uint) int {
	if bits.OnesCount(nbInstances) != 1 {
		return -1
	}
	return bits.TrailingZeros(nbInstances)
}

func (i *API) Series(input, output Variable, inputInstance, outputInstance int) *API {
	i.assignments[input][inputInstance] = InputDependency{
		Output:         output,
		OutputInstance: outputInstance,
	}
	return i
}

func (i *API) Import(assignment []frontend.Variable) (Variable, error) {
	if i.compiled {
		return nil, fmt.Errorf("cannot import variables into compiled circuit")
	}
	nbInstances := uint(len(assignment))
	logNbInstances := logNbInstances(nbInstances)
	if logNbInstances == -1 {
		return nil, fmt.Errorf("number of assignments must be a power of 2")
	}
	if i.logNbInstances == -1 {
		i.logNbInstances = logNbInstances
	} else if logNbInstances != i.logNbInstances {
		return nil, fmt.Errorf("number of assignments must be consistent across all variables")
	}
	i.circuit = append(i.circuit, Wire{
		Gate:   nil,
		Inputs: []*Wire{},
	})
	return &i.circuit[len(i.circuit)-1], nil
}

func (i *API) nbInputValueAssignments(variable Variable) int {
	res := 0
	for j := range i.assignments[variable] {
		if _, ok := i.assignments[variable][j].(InputDependency); !ok {
			res++
		}
	}
	return res
}

// Compile finalizes the GKR circuit and returns the output variables in the order created
func (i *API) Compile(parentApi frontend.API) ([][]frontend.Variable, error) {
	if i.compiled {
		return nil, fmt.Errorf("already compiled")
	}
	i.compiled = true

	i.circuitData.Sorted = topologicalSort(i.circuit)
	i.circuitData.NbInstances = 1 << i.logNbInstances
	indexes := circuitIndexMap(i.circuitData.Sorted)
	i.circuitData.CircuitInputsIndex, i.circuitData.InputIndexes =
		circuitInputsIndex(i.circuitData.Sorted, indexes)

	solveHintNIn := 0
	//solveHintNOut := ProofSize(i.circuit, i.logNbInstances)
	solveHintNOut := 0
	for j := range i.circuit {
		v := &i.circuit[j]
		if v.IsInput() {
			solveHintNIn += i.nbInputValueAssignments(v)
		} else if v.IsOutput() {
			solveHintNOut += i.circuitData.NbInstances
		}
	}

	ins := make([]frontend.Variable, 0, solveHintNIn)
	for j := range i.circuit {
		if i.circuit[j].IsInput() {
			assignment := i.assignments[&i.circuit[j]]
			for k := range assignment {
				if _, ok := assignment[k].(InputDependency); !ok {
					ins = append(ins, assignment[k])
				}
			}
		}
	}

	i.circuitData.Sorted = topologicalSort(i.circuit)
	indexMap := circuitIndexMap(i.circuitData.Sorted)
	i.circuitData.CircuitInputsIndex, i.circuitData.InputIndexes = circuitInputsIndex(i.circuitData.Sorted, indexMap)

	solveHint := gkr.SolveHint(&i.circuitData)

	outsSerialized, err := parentApi.Compiler().NewHint(solveHint, solveHintNOut, ins...)
	if err != nil {
		return nil, err
	}

	outs := make([][]frontend.Variable, len(outsSerialized)/i.circuitData.NbInstances)

	offset := 0
	for j := range outs {
		outs[j] = outsSerialized[offset : offset+i.circuitData.NbInstances]
		offset += i.circuitData.NbInstances
	}

	return outs, nil
}

// Verify produces a subcircuit guaranteeing the correctness of the solved values
func (i *API) Verify(statement []frontend.Variable) error {
	return fmt.Errorf("not implemented")
}

func circuitIndexMap(sorted []*Wire) map[*Wire]int {
	indexes := make(map[*Wire]int, len(sorted))
	for i := range sorted {
		indexes[sorted[i]] = i
	}
	return indexes
}

func circuitInputsIndex(sorted []*Wire, indexes map[*Wire]int) ([][]int, []int) {
	res := make([][]int, len(sorted))
	inputIndexes := make([]int, 0)
	for i, w := range sorted {
		if w.IsInput() {
			inputIndexes = append(inputIndexes, i)
		}
		res[i] = make([]int, len(w.Inputs))
		for j, v := range w.Inputs {
			res[i][j] = indexes[v]
		}
	}

	return res, inputIndexes
}

type InputDependency struct {
	Output         *Wire
	OutputInstance int
}

type IndexedInputDependency struct {
	OutputInstance  int
	OutputWireIndex int
}

type inputDependencies [][]IndexedInputDependency // instance first, then wire

func (d inputDependencies) NbDependencies(inputIndex int) int {
	count := 0
	for _, instance := range d {
		if instance[inputIndex].OutputWireIndex != -1 {
			count++
		}
	}
	return count
}
