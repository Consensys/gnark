package gkrapi

import (
	"errors"
	"fmt"
	"math/bits"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/constraint/solver/gkrgates"
	"github.com/consensys/gnark/frontend"
	gadget "github.com/consensys/gnark/internal/gkr"
	"github.com/consensys/gnark/internal/gkr/gkrinfo"
	"github.com/consensys/gnark/internal/utils"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/gkr"
	"github.com/consensys/gnark/std/hash"
)

type circuitDataForSnark struct {
	circuit     gadget.Circuit
	assignments gadget.WireAssignment
}

type API struct {
	toStore     gkrinfo.StoringInfo
	assignments gadget.WireAssignment
}

type Solution struct {
	toStore      gkrinfo.StoringInfo
	assignments  gadget.WireAssignment
	parentApi    frontend.API
	permutations gkrinfo.Permutations
}

func (api *API) nbInstances() int {
	return api.assignments.NbInstances()
}

// New creates a new GKR API
func New() *API {
	return &API{}
}

// log2 returns -1 if x is not a power of 2
func log2(x uint) int {
	if bits.OnesCount(x) != 1 {
		return -1
	}
	return bits.TrailingZeros(x)
}

// Series like in an electric circuit, binds an input of an instance to an output of another
func (api *API) Series(input, output gkr.Variable, inputInstance, outputInstance int) *API {
	if api.assignments[input][inputInstance] != nil {
		panic("dependency attempting to override explicit value assignment")
	}
	api.toStore.Dependencies[input] =
		append(api.toStore.Dependencies[input], gkrinfo.InputDependency{
			OutputWire:     int(output),
			OutputInstance: outputInstance,
			InputInstance:  inputInstance,
		})
	return api
}

// Import creates a new input variable, whose values across all instances are given by assignment.
// If the value in an instance depends on an output of another instance, leave the corresponding index in assignment nil and use Series to specify the dependency.
func (api *API) Import(assignment []frontend.Variable) (gkr.Variable, error) {
	nbInstances := len(assignment)
	logNbInstances := log2(uint(nbInstances))
	if logNbInstances == -1 {
		return -1, errors.New("number of assignments must be a power of 2")
	}

	if currentNbInstances := api.nbInstances(); currentNbInstances != -1 && currentNbInstances != nbInstances {
		return -1, errors.New("number of assignments must be consistent across all variables")
	}
	api.assignments = append(api.assignments, assignment)
	return gkr.Variable(api.toStore.NewInputVariable()), nil
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

	var p gkrinfo.Permutations
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
		in, out := v.IsInput(), v.IsOutput()
		if in && out {
			return Solution{}, fmt.Errorf("unused input (variable #%d)", i)
		}

		if in {
			solveHintNIn += nbInstances - len(api.toStore.Dependencies[i])
		} else if out {
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

	solveHintPlaceholder := SolveHintPlaceholder(api.toStore)
	outsSerialized, err := parentApi.Compiler().NewHint(solveHintPlaceholder, solveHintNOut, ins...)
	api.toStore.SolveHintID = solver.GetHintID(solveHintPlaceholder)
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
		for _, dep := range api.toStore.Dependencies[i] {
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

// Export returns the values of an output variable across all instances
func (s Solution) Export(v gkr.Variable) []frontend.Variable {
	return utils.Map(s.permutations.SortedInstances, utils.SliceAt(s.assignments[v]))
}

// Verify encodes the verification circuitry for the GKR circuit
func (s Solution) Verify(hashName string, initialChallenges ...frontend.Variable) error {
	var (
		err             error
		proofSerialized []frontend.Variable
		proof           gadget.Proof
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

	proveHintPlaceholder := ProveHintPlaceholder(hashName)
	if proofSerialized, err = s.parentApi.Compiler().NewHint(
		proveHintPlaceholder, gadget.ProofSize(forSnark.circuit, logNbInstances), hintIns...); err != nil {
		return err
	}
	s.toStore.ProveHintID = solver.GetHintID(proveHintPlaceholder)

	forSnarkSorted := utils.MapRange(0, len(s.toStore.Circuit), slicePtrAt(forSnark.circuit))

	if proof, err = gadget.DeserializeProof(forSnarkSorted, proofSerialized); err != nil {
		return err
	}

	var hsh hash.FieldHasher
	if hsh, err = hash.GetFieldHasher(hashName, s.parentApi); err != nil {
		return err
	}
	s.toStore.HashName = hashName

	err = gadget.Verify(s.parentApi, forSnark.circuit, forSnark.assignments, proof, fiatshamir.WithHash(hsh, initialChallenges...), gadget.WithSortedCircuit(forSnarkSorted))
	if err != nil {
		return err
	}

	return s.parentApi.(gkrinfo.ConstraintSystem).SetGkrInfo(s.toStore)
}

func slicePtrAt[T any](slice []T) func(int) *T {
	return func(i int) *T {
		return &slice[i]
	}
}

func ite[T any](condition bool, ifNot, IfSo T) T {
	if condition {
		return IfSo
	}
	return ifNot
}

func newCircuitDataForSnark(info gkrinfo.StoringInfo, assignment gadget.WireAssignment) circuitDataForSnark {
	circuit := make(gadget.Circuit, len(info.Circuit))
	snarkAssignment := make(gadget.WireAssignment, len(info.Circuit))

	for i := range circuit {
		w := info.Circuit[i]
		circuit[i] = gadget.Wire{
			Gate:            gkrgates.Get(ite(w.IsInput(), gkr.GateName(w.Gate), gkr.Identity)),
			Inputs:          w.Inputs,
			NbUniqueOutputs: w.NbUniqueOutputs,
		}
		snarkAssignment[i] = assignment[i]
	}
	return circuitDataForSnark{
		circuit:     circuit,
		assignments: snarkAssignment,
	}
}
