package gkrapi

import (
	"fmt"
	"math/bits"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/constraint/solver/gkrgates"
	"github.com/consensys/gnark/frontend"
	gadget "github.com/consensys/gnark/internal/gkr"
	"github.com/consensys/gnark/internal/gkr/gkrinfo"
	"github.com/consensys/gnark/internal/gkr/gkrtypes"
	"github.com/consensys/gnark/internal/utils"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/gkrapi/gkr"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/mimc"
)

type circuitDataForSnark struct {
	circuit     gkrtypes.Circuit
	assignments gkrtypes.WireAssignment
}

type InitialChallengeGetter func() []frontend.Variable

// Circuit represents a GKR circuit.
type Circuit struct {
	toStore              gkrinfo.StoringInfo
	assignments          gkrtypes.WireAssignment
	getInitialChallenges InitialChallengeGetter // optional getter for the initial Fiat-Shamir challenge
	ins                  []gkr.Variable
	outs                 []gkr.Variable
	api                  frontend.API // the parent API used for hints
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

// NewInput creates a new input variable.
func (api *API) NewInput() gkr.Variable {
	return gkr.Variable(api.toStore.NewInputVariable())
}

type compileOption func(*Circuit)

// WithInitialChallenge provides a getter for the initial Fiat-Shamir challenge.
// If not provided, the initial challenge will be a commitment to all the input and output values of the circuit.
func WithInitialChallenge(getInitialChallenge InitialChallengeGetter) compileOption {
	return func(c *Circuit) {
		c.getInitialChallenges = getInitialChallenge
	}
}

// Compile finalizes the GKR circuit.
// From this point on, the circuit cannot be modified.
// But instances can be added to the circuit.
func (api *API) Compile(parentApi frontend.API, fiatshamirHashName string, options ...compileOption) *Circuit {
	// TODO define levels here
	res := Circuit{
		toStore:     api.toStore,
		assignments: make(gkrtypes.WireAssignment, len(api.toStore.Circuit)),
		api:         parentApi,
	}

	api.toStore.HashName = fiatshamirHashName

	for _, opt := range options {
		opt(&res)
	}

	for i := range res.toStore.Circuit {
		if res.toStore.Circuit[i].IsOutput() {
			res.outs = append(res.ins, gkr.Variable(i))
		}
		if res.toStore.Circuit[i].IsInput() {
			res.ins = append(res.ins, gkr.Variable(i))
		}
	}
	res.toStore.SolveHintID = solver.GetHintID(SolveHintPlaceholder(res.toStore))
	res.toStore.ProveHintID = solver.GetHintID(ProveHintPlaceholder(fiatshamirHashName))

	parentApi.Compiler().Defer(res.verify)

	return &res
}

// AddInstance adds a new instance to the GKR circuit, returning the values of output variables for the instance.
func (c *Circuit) AddInstance(input map[gkr.Variable]frontend.Variable) (map[gkr.Variable]frontend.Variable, error) {
	if len(input) != len(c.ins) {
		for k := range input {
			if k >= gkr.Variable(len(c.ins)) {
				return nil, fmt.Errorf("variable %d is out of bounds (max %d)", k, len(c.ins)-1)
			}
			if !c.toStore.Circuit[k].IsInput() {
				return nil, fmt.Errorf("value provided for non-input variable %d", k)
			}
		}
	}
	hintIn := make([]frontend.Variable, 1+len(c.ins)) // first input denotes the instance number
	hintIn[0] = c.toStore.NbInstances
	for hintInI, in := range c.ins {
		if inV, ok := input[in]; !ok {
			return nil, fmt.Errorf("missing entry for input variable %d", in)
		} else {
			hintIn[hintInI+1] = inV
		}
	}

	c.toStore.NbInstances++
	solveHintPlaceholder := SolveHintPlaceholder(c.toStore)
	outsSerialized, err := c.api.Compiler().NewHint(solveHintPlaceholder, len(c.outs), hintIn...)
	if err != nil {
		return nil, fmt.Errorf("failed to create solve hint: %w", err)
	}
	res := make(map[gkr.Variable]frontend.Variable, len(c.outs))
	for i, v := range c.outs {
		res[v] = outsSerialized[i]
		c.assignments[v] = append(c.assignments[v], outsSerialized[i])
	}

	return res, nil
}

// verify encodes the verification circuitry for the GKR circuit
func (c *Circuit) verify(api frontend.API) error {
	if api != c.api {
		panic("api mismatch")
	}

	if len(c.outs) == 0 || len(c.assignments[0]) == 0 {
		return nil
	}

	var (
		err               error
		proofSerialized   []frontend.Variable
		proof             gadget.Proof
		initialChallenges []frontend.Variable
	)

	if c.getInitialChallenges != nil {
		initialChallenges = c.getInitialChallenges()
	} else {
		// default initial challenge is a commitment to all input and output values
		initialChallenges = make([]frontend.Variable, 0, (len(c.ins)+len(c.outs))*len(c.assignments[c.ins[0]]))
		for _, in := range c.ins {
			initialChallenges = append(initialChallenges, c.assignments[in]...)
		}
		for _, out := range c.outs {
			initialChallenges = append(initialChallenges, c.assignments[out]...)
		}

		if initialChallenges[0], err = api.(frontend.Committer).Commit(initialChallenges...); err != nil {
			return fmt.Errorf("failed to commit to in/out values: %w", err)
		}
		initialChallenges = initialChallenges[:1] // use the commitment as the only initial challenge
	}

	forSnark := newCircuitDataForSnark(c.toStore, c.assignments)
	logNbInstances := log2(uint(c.assignments.NbInstances()))

	hintIns := make([]frontend.Variable, len(initialChallenges)+1) // hack: adding one of the outputs of the solve hint to ensure "prove" is called after "solve"
	firstOutputAssignment := c.assignments[c.outs[0]]
	hintIns[0] = firstOutputAssignment[len(firstOutputAssignment)-1] // take the last output of the first output wire

	copy(hintIns[1:], initialChallenges)

	proveHintPlaceholder := ProveHintPlaceholder(c.toStore.HashName)
	if proofSerialized, err = api.Compiler().NewHint(
		proveHintPlaceholder, gadget.ProofSize(forSnark.circuit, logNbInstances), hintIns...); err != nil {
		return err
	}
	c.toStore.ProveHintID = solver.GetHintID(proveHintPlaceholder)

	forSnarkSorted := utils.MapRange(0, len(c.toStore.Circuit), slicePtrAt(forSnark.circuit))

	if proof, err = gadget.DeserializeProof(forSnarkSorted, proofSerialized); err != nil {
		return err
	}

	var hsh hash.FieldHasher
	if hsh, err = hash.GetFieldHasher(c.toStore.HashName, api); err != nil {
		return err
	}

	err = gadget.Verify(api, forSnark.circuit, forSnark.assignments, proof, fiatshamir.WithHash(hsh, initialChallenges...), gadget.WithSortedCircuit(forSnarkSorted))
	if err != nil {
		return err
	}

	return api.(gkrinfo.ConstraintSystem).SetGkrInfo(c.toStore)
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

func newCircuitDataForSnark(info gkrinfo.StoringInfo, assignment gkrtypes.WireAssignment) circuitDataForSnark {
	circuit := make(gkrtypes.Circuit, len(info.Circuit))
	snarkAssignment := make(gkrtypes.WireAssignment, len(info.Circuit))

	for i := range circuit {
		w := info.Circuit[i]
		circuit[i] = gkrtypes.Wire{
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

func init() {
	// TODO Move this to the hash package if the import cycle issue is fixed.
	hash.Register("mimc", func(api frontend.API) (hash.FieldHasher, error) {
		h, err := mimc.NewMiMC(api)
		return &h, err
	})
}
