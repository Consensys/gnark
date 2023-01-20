package gkr

import (
	"fmt"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/utils/algo_utils"
	"math/big"
	"math/bits"
)

type circuitDataForSnark struct {
	circuit     Circuit
	assignments WireAssignment
}

type API struct {
	toStore     constraint.GkrInfo
	assignments assignment
}

type Solution struct {
	toStore      constraint.GkrInfo
	assignments  assignment
	parentApi    frontend.API
	permutations constraint.GkrPermutations
}

func (api *API) nbInstances() int {
	return api.assignments.NbInstances()
}

func (api *API) logNbInstances() int {
	return log2(uint(api.nbInstances()))
}

func NewApi() *API {
	return &API{
		toStore: constraint.GkrInfo{
			Circuit: make(constraint.GkrCircuit, 0),
			MaxNIns: 0,
		},
	}
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
	i := input.(constraint.GkrVariable)
	o := output.(constraint.GkrVariable)
	if api.assignments[i][inputInstance] != nil {
		panic("dependency attempting to override explicit value assignment")
	}
	api.toStore.Circuit[i].Dependencies =
		append(api.toStore.Circuit[i].Dependencies, constraint.InputDependency{
			OutputWire:     int(o),
			OutputInstance: outputInstance,
			InputInstance:  inputInstance,
		})
	return api
}

func (api *API) Import(assignment []frontend.Variable) (constraint.GkrVariable, error) {
	nbInstances := len(assignment)
	logNbInstances := log2(uint(nbInstances))
	if logNbInstances == -1 {
		return -1, fmt.Errorf("number of assignments must be a power of 2")
	}

	if currentNbInstances := api.nbInstances(); currentNbInstances != -1 && currentNbInstances != nbInstances {
		return -1, fmt.Errorf("number of assignments must be consistent across all variables")
	}
	newVar := api.toStore.NewInputVariable()
	api.assignments = append(api.assignments, assignment)
	return newVar, nil
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

	var p constraint.GkrPermutations
	var err error
	if p, err = api.toStore.Compile(api.assignments.NbInstances()); err != nil {
		return Solution{}, err
	}
	api.assignments.Permute(p)

	nbInstances := api.toStore.NbInstances
	circuit := api.toStore.Circuit

	solveHintNIn := 0
	solveHintNOut := 0

	for i := range circuit {
		v := &circuit[i]
		if v.IsInput() {
			solveHintNIn += nbInstances - len(v.Dependencies)
		} else if v.IsOutput() {
			solveHintNOut += nbInstances
		}
	}

	// arrange inputs wire first, then in the order solved
	ins := make([]frontend.Variable, 0, solveHintNIn)
	for i := range circuit {
		if circuit[i].IsInput() {
			appendNonNil(&ins, api.assignments[i])
		}
	}

	outsSerialized, err := parentApi.Compiler().NewHint(SolveHintPlaceholder, solveHintNOut, ins...)
	api.toStore.SolveHintID = hint.UUID(SolveHintPlaceholder)
	if err != nil {
		return Solution{}, err
	}

	for i := range circuit {
		if circuit[i].IsOutput() {
			api.assignments[i] = outsSerialized[:nbInstances]
			outsSerialized = outsSerialized[nbInstances:]
		}
	}

	for i := range circuit {
		for _, dep := range circuit[i].Dependencies {
			api.assignments[i][dep.InputInstance] = api.assignments[dep.OutputWire][dep.OutputInstance]
		}
	}

	return Solution{
		toStore:      api.toStore,
		assignments:  api.assignments,
		parentApi:    parentApi,
		permutations: p,
	}, nil
}

func (s Solution) Export(v frontend.Variable) []frontend.Variable {
	return algo_utils.Map(s.permutations.SortedInstances, algo_utils.SliceAt(s.assignments[v.(constraint.GkrVariable)]))
}

func (s Solution) Verify(hashName string, initialChallenges ...frontend.Variable) error {
	var (
		err             error
		proofSerialized []frontend.Variable
		proof           Proof
	)

	forSnark := newCircuitDataForSnark(s.toStore, s.assignments)
	logNbInstances := log2(uint(s.assignments.NbInstances()))

	hintIns := make([]frontend.Variable, len(initialChallenges)+1) // hack: adding one of the outputs of the solve hint to ensure "prove" is called after "solve"
	for i, w := range s.toStore.Circuit {
		if w.IsOutput() {
			hintIns[0] = s.assignments[i][0]
			break
		}
	}
	copy(hintIns[1:], initialChallenges)

	if proofSerialized, err = s.parentApi.Compiler().NewHint(
		ProveHintPlaceholder, ProofSize(forSnark.circuit, logNbInstances), hintIns...); err != nil {
		return err
	}
	s.toStore.ProveHintID = hint.UUID(ProveHintPlaceholder)

	forSnarkSorted := algo_utils.MapRange(0, len(s.toStore.Circuit), slicePtrAt(forSnark.circuit))

	if proof, err = DeserializeProof(forSnarkSorted, proofSerialized); err != nil {
		return err
	}

	var hsh hash.Hash
	hsh, err = hash.BuilderRegistry[hashName](s.parentApi)
	s.toStore.HashName = hashName

	err = Verify(s.parentApi, forSnark.circuit, forSnark.assignments, proof, fiatshamir.WithHash(hsh, initialChallenges...), WithSortedCircuit(forSnarkSorted))
	if err != nil {
		return err
	}

	return s.parentApi.Compiler().SetGkrInfo(s.toStore)
}

func SolveHintPlaceholder(*big.Int, []*big.Int, []*big.Int) error {
	return fmt.Errorf("placeholder - not meant to be called")
}

func ProveHintPlaceholder(*big.Int, []*big.Int, []*big.Int) error {
	return fmt.Errorf("placeholder - not meant to be called")
}

func slicePtrAt[T any](slice []T) func(int) *T {
	return func(i int) *T {
		return &slice[i]
	}
}

func newCircuitDataForSnark(info constraint.GkrInfo, assignment assignment) circuitDataForSnark {
	circuit := make(Circuit, len(info.Circuit))
	snarkAssignment := make(WireAssignment, len(info.Circuit))
	circuitAt := slicePtrAt(circuit)
	for i := range circuit {
		w := info.Circuit[i]
		circuit[i] = Wire{
			Gate:            RegisteredGates[w.Gate],
			Inputs:          algo_utils.Map(w.Inputs, circuitAt),
			nbUniqueOutputs: w.NbUniqueOutputs,
		}
		snarkAssignment[&circuit[i]] = assignment[i]
	}
	return circuitDataForSnark{
		circuit:     circuit,
		assignments: snarkAssignment,
	}
}

type assignment [][]frontend.Variable

func (a assignment) NbInstances() int {
	for i := range a {
		if lenI := len(a[i]); lenI != 0 {
			return lenI
		}
	}
	return -1
}

func (a assignment) Permute(p constraint.GkrPermutations) {
	algo_utils.Permute(a, p.WiresPermutation)
	for i := range a {
		if a[i] != nil {
			algo_utils.Permute(a[i], p.InstancesPermutation)
		}
	}
}
