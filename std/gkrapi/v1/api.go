package gkrapi

import (
	"cmp"
	"errors"
	"math/bits"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/gkr/gkrtypes"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/gkrapi/v2"
	"github.com/consensys/gnark/std/gkrapi/v2/gkr"
)

type API struct {
	assignments  gkrtypes.WireAssignment
	api          gkrapi.API
	dependencies []inputDependency
}

type inputDependency struct {
	outputWire     int
	outputInstance int
	inputWire      int
	inputInstance  int
}

func (api *API) NamedGate(gate gkr.GateName, in ...gkr.Variable) gkr.Variable {
	api.assignments = append(api.assignments, nil)
	return api.api.NamedGate(gate, in...)
}

func (api *API) Gate(gate gkr.GateFunction, in ...gkr.Variable) gkr.Variable {
	api.assignments = append(api.assignments, nil)
	return api.api.Gate(gate, in...)
}

func (api *API) namedGate2PlusIn(gate gkr.GateName, in1, in2 gkr.Variable, in ...gkr.Variable) gkr.Variable {
	inCombined := make([]gkr.Variable, 2+len(in))
	inCombined[0] = in1
	inCombined[1] = in2
	for i := range in {
		inCombined[i+2] = in[i]
	}
	return api.NamedGate(gate, inCombined...)
}

func (api *API) Add(i1, i2 gkr.Variable) gkr.Variable {
	api.assignments = append(api.assignments, nil)
	return api.api.Add(i1, i2)
}

func (api *API) Neg(i1 gkr.Variable) gkr.Variable {
	api.assignments = append(api.assignments, nil)
	return api.api.Neg(i1)
}

func (api *API) Sub(i1, i2 gkr.Variable) gkr.Variable {
	api.assignments = append(api.assignments, nil)
	return api.api.Sub(i1, i2)
}

func (api *API) Mul(i1, i2 gkr.Variable) gkr.Variable {
	api.assignments = append(api.assignments, nil)
	return api.api.Mul(i1, i2)
}

type solution struct {
	assignments       gkrtypes.WireAssignment
	hashName          string
	initialChallenges []frontend.Variable
}

type Solution struct {
	*solution
}

func (api *API) nbInstances() int {
	if len(api.assignments) == 0 {
		return -1
	}
	return api.assignments.NbInstances()
}

// New creates a new GKR API
// Deprecated: Use [github.com/consensys/gnark/std/gkrapi/v2.New] instead
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

	api.dependencies =
		append(api.dependencies, inputDependency{
			outputWire:     int(output),
			inputWire:      int(input),
			outputInstance: outputInstance,
			inputInstance:  inputInstance,
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
	return api.api.NewInput(), nil
}

// Solve finalizes the GKR circuit and returns the output variables in the order created.
func (api *API) Solve(parentApi frontend.API) (Solution, error) {
	res := Solution{&solution{
		assignments: api.assignments,
	}}

	// 1. compile circuit
	circuit := api.api.Compile(
		parentApi,
		gkrapi.WithHashNameProvider(func() string { return res.hashName }),
		gkrapi.WithInitialChallenge(func() []frontend.Variable { return res.initialChallenges }),
	)

	// 2. sort dependencies so that they can be added in order (for j > i, instance i must not depend on instance j)
	dependenciesNoWire := make([][]int, api.nbInstances())
	dependencies := make([][]inputDependency, api.nbInstances())
	for _, dep := range api.dependencies {
		dependenciesNoWire[dep.inputInstance] = append(dependenciesNoWire[dep.inputInstance], dep.outputInstance)
		dependencies[dep.inputInstance] = append(dependencies[dep.inputInstance], dep)
	}
	for i := range dependencies {
		slices.SortFunc(dependencies[i], func(a, b inputDependency) int {
			return cmp.Compare(a.inputWire, b.inputWire)
		})
	}
	v2ToV1, _ := utils.TopologicalSort(dependenciesNoWire)

	// 3. add instances and sort outputs into the original order
	isInput := make([]bool, len(res.assignments))
	for i := range res.assignments {
		if res.assignments[i] == nil {
			// Note: This is rather inefficient at compile time. Intermediate wires do not need
			// explicit assignments.
			res.assignments[i] = make([]frontend.Variable, api.nbInstances())
		} else {
			isInput[i] = true
		}
	}

	ins := make(map[gkr.Variable]frontend.Variable)
	for _, v1Index := range v2ToV1 {
		for wI, assignment := range res.assignments {
			if !isInput[wI] {
				continue
			}
			ins[gkr.Variable(wI)] = assignment[v1Index]
			if assignment[v1Index] == nil { // dependency
				dep := dependencies[v1Index][0]
				dependencies[v1Index] = dependencies[v1Index][1:]

				if dep.inputInstance != v1Index || dep.inputWire != wI {
					return Solution{nil}, errors.New("unexpected dependency")
				}

				ins[gkr.Variable(wI)] = res.assignments[dep.outputWire][dep.outputInstance]
			}
		}

		outs, err := circuit.AddInstance(ins)
		for wI, v := range outs {
			res.assignments[wI][v1Index] = v
		}
		if err != nil {
			return Solution{nil}, err
		}

	}

	return res, nil
}

// Export returns the values of an output variable across all instances.
func (s Solution) Export(v gkr.Variable) []frontend.Variable {
	return s.assignments[v]
}

// Verify encodes the verification circuitry for the GKR circuit.
func (s Solution) Verify(hashName string, initialChallenges ...frontend.Variable) error {
	s.hashName = hashName
	s.initialChallenges = initialChallenges

	return nil
}
