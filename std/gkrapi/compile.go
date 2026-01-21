package gkrapi

import (
	"errors"
	"fmt"
	"math/bits"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver/gkrgates"
	"github.com/consensys/gnark/frontend"
	gadget "github.com/consensys/gnark/internal/gkr"
	"github.com/consensys/gnark/internal/gkr/gkrhints"
	"github.com/consensys/gnark/internal/gkr/gkrinfo"
	"github.com/consensys/gnark/internal/gkr/gkrtypes"
	"github.com/consensys/gnark/internal/utils"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/gkrapi/gkr"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/multicommit"
)

type circuitDataForSnark struct {
	circuit     gkrtypes.Circuit
	assignments gkrtypes.WireAssignment
}

// The InitialChallengeGetter provides a one-time initial Fiat-Shamir challenge for the GKR prover.
// Normally, these should include a unique circuit identifier and all input-output pairs.
type InitialChallengeGetter func() []frontend.Variable

// Circuit represents a GKR circuit.
type Circuit struct {
	toStore              *gkrinfo.StoringInfo
	assignments          gkrtypes.WireAssignment
	getInitialChallenges InitialChallengeGetter // optional getter for the initial Fiat-Shamir challenge
	ins                  []gkr.Variable
	outs                 []gkr.Variable
	api                  frontend.API              // the parent API used for hints
	hints                *gkrhints.TestEngineHints // hints for the GKR circuit, used for testing purposes
	index                int                       // index among all GKR circuits
}

// New creates a new GKR API
func New(api frontend.API) (*API, error) {
	gkrer, ok := api.Compiler().(gkrinfo.ConstraintSystem)
	if !ok {
		return nil, errors.New("provided api does not support GKR")
	}
	toStore, index := gkrer.NewGkr()
	return &API{
		toStore:   toStore,
		index:     index,
		parentApi: api,
	}, nil
}

// NewInput creates a new input variable.
func (api *API) NewInput() gkr.Variable {
	return gkr.Variable(api.toStore.NewInputVariable())
}

type CompileOption func(*Circuit)

// WithInitialChallenge provides a getter for the initial Fiat-Shamir challenge.
// If not provided, the initial challenge will be a commitment to all the input and output values of the circuit.
func WithInitialChallenge(getInitialChallenge InitialChallengeGetter) CompileOption {
	return func(c *Circuit) {
		c.getInitialChallenges = getInitialChallenge
	}
}

// Compile finalizes the GKR circuit.
// From this point on, the circuit cannot be modified,
// but instances can be added to it.
func (api *API) Compile(fiatshamirHashName string, options ...CompileOption) (*Circuit, error) {
	res := Circuit{
		toStore:     api.toStore,
		index:       api.index,
		assignments: make(gkrtypes.WireAssignment, len(api.toStore.Circuit)),
		api:         api.parentApi,
	}

	res.toStore.HashName = fiatshamirHashName
	res.toStore.Circuit = api.toStore.Circuit

	var err error
	res.hints, err = gkrhints.NewTestEngineHints(res.toStore)
	if err != nil {
		return nil, fmt.Errorf("failed to call GKR hints: %w", err)
	}

	for _, opt := range options {
		opt(&res)
	}

	notOut := make([]bool, len(res.toStore.Circuit))
	for i := range res.toStore.Circuit {
		if res.toStore.Circuit[i].IsInput() {
			res.ins = append(res.ins, gkr.Variable(i))
		}
		for _, inWI := range res.toStore.Circuit[i].Inputs {
			notOut[inWI] = true
		}
	}

	if len(res.ins) == len(res.toStore.Circuit) {
		return nil, errors.New("circuit has no non-input wires")
	}

	for i := range res.toStore.Circuit {
		if !notOut[i] {
			res.outs = append(res.outs, gkr.Variable(i))
		}
	}

	res.api.Compiler().Defer(res.finalize)

	return &res, nil
}

// AddInstance adds a new instance to the GKR circuit, returning the values of output variables for the instance.
func (c *Circuit) AddInstance(input map[gkr.Variable]frontend.Variable) (map[gkr.Variable]frontend.Variable, error) {
	if len(input) != len(c.ins) {
		for k := range input {
			if k >= gkr.Variable(len(c.toStore.Circuit)) {
				return nil, fmt.Errorf("variable %d is out of bounds (max %d)", k, len(c.toStore.Circuit)-1)
			}
			if !c.toStore.Circuit[k].IsInput() {
				return nil, fmt.Errorf("value provided for non-input variable %d", k)
			}
		}
	}
	hintIn := make([]frontend.Variable, 2+len(c.ins)) // first and second input denote the circuit and instance, respectively.
	hintIn[0] = c.index
	hintIn[1] = c.toStore.NbInstances
	for hintInI, wI := range c.ins {
		if inV, ok := input[wI]; !ok {
			return nil, fmt.Errorf("missing entry for input variable %d", wI)
		} else {
			hintIn[hintInI+2] = inV
			c.assignments[wI] = append(c.assignments[wI], inV)
		}
	}

	outsSerialized, err := c.api.Compiler().NewHint(c.hints.Solve, len(c.outs), hintIn...)
	if err != nil {
		return nil, fmt.Errorf("failed to call solve hint: %w", err)
	}
	c.toStore.NbInstances++
	res := make(map[gkr.Variable]frontend.Variable, len(c.outs))
	for i, v := range c.outs {
		res[v] = outsSerialized[i]
		c.assignments[v] = append(c.assignments[v], outsSerialized[i])
	}

	return res, nil
}

// finalize encodes the verification circuitry for the GKR circuit.
func (c *Circuit) finalize(api frontend.API) error {

	// if the circuit is empty or with no instances, there is nothing to do.
	if len(c.outs) == 0 || len(c.assignments[0]) == 0 { // wire 0 is always an input wire
		return nil
	}

	// pad instances to the next power of 2
	nbPaddedInstances := int(ecc.NextPowerOfTwo(uint64(c.toStore.NbInstances)))
	// pad instances to the next power of 2 by repeating the last instance
	if c.toStore.NbInstances < nbPaddedInstances && c.toStore.NbInstances > 0 {
		for _, wI := range c.ins {
			c.assignments[wI] = utils.ExtendRepeatLast(c.assignments[wI], nbPaddedInstances)
		}
		for _, wI := range c.outs {
			c.assignments[wI] = utils.ExtendRepeatLast(c.assignments[wI], nbPaddedInstances)
		}
	}

	// if the circuit consists of only one instance, directly solve the circuit
	if len(c.assignments[c.ins[0]]) == 1 {
		circuit, err := gkrtypes.NewCircuit(c.toStore.Circuit, gkrgates.Get)
		if err != nil {
			return fmt.Errorf("failed to convert GKR info to circuit: %w", err)
		}
		gateIn := make([]frontend.Variable, circuit.MaxGateNbIn())
		for wI, w := range circuit {
			if w.IsInput() {
				continue
			}
			for inI, inWI := range w.Inputs {
				gateIn[inI] = c.assignments[inWI][0] // take the first (only) instance
			}
			res := w.Gate.Evaluate(gadget.FrontendAPIWrapper{API: api}, gateIn[:len(w.Inputs)]...)
			if w.IsOutput() {
				api.AssertIsEqual(res, c.assignments[wI][0])
			} else {
				c.assignments[wI] = append(c.assignments[wI], res)
			}
		}
		return nil
	}

	if c.getInitialChallenges != nil {
		return c.verify(api, c.getInitialChallenges())
	}

	// default initial challenge is a commitment to all input and output values
	insOuts := make([]frontend.Variable, 0, (len(c.ins)+len(c.outs))*len(c.assignments[c.ins[0]]))
	for _, in := range c.ins {
		insOuts = append(insOuts, c.assignments[in]...)
	}
	for _, out := range c.outs {
		insOuts = append(insOuts, c.assignments[out]...)
	}

	multicommit.WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
		return c.verify(api, []frontend.Variable{commitment})
	}, insOuts...)

	return nil
}

func (c *Circuit) verify(api frontend.API, initialChallenges []frontend.Variable) error {
	forSnark, err := newCircuitDataForSnark(utils.FieldToCurve(api.Compiler().Field()), c.toStore, c.assignments)
	if err != nil {
		return fmt.Errorf("failed to create circuit data for snark: %w", err)
	}

	// first input is the circuit index.
	// hack: adding one of the outputs of the solve hint to ensure "prove" is called after "solve".
	hintIns := make([]frontend.Variable, len(initialChallenges)+2)
	firstOutputAssignment := c.assignments[c.outs[0]]
	hintIns[0] = c.index
	hintIns[1] = firstOutputAssignment[len(firstOutputAssignment)-1] // take the last output of the first output wire

	copy(hintIns[2:], initialChallenges)

	var (
		proofSerialized []frontend.Variable
		proof           gadget.Proof
	)

	if proofSerialized, err = api.Compiler().NewHint(
		c.hints.Prove, gadget.ProofSize(forSnark.circuit, bits.TrailingZeros(uint(len(c.assignments[0])))), hintIns...); err != nil {
		return err
	}

	forSnarkSorted := utils.SliceOfRefs(forSnark.circuit)

	if proof, err = gadget.DeserializeProof(forSnarkSorted, proofSerialized); err != nil {
		return err
	}

	var hsh hash.FieldHasher
	if hsh, err = hash.GetFieldHasher(c.toStore.HashName, api); err != nil {
		return err
	}

	return gadget.Verify(api, forSnark.circuit, forSnark.assignments, proof, fiatshamir.WithHash(hsh, initialChallenges...), gadget.WithSortedCircuit(forSnarkSorted))
}

func newCircuitDataForSnark(curve ecc.ID, info *gkrinfo.StoringInfo, assignment gkrtypes.WireAssignment) (circuitDataForSnark, error) {
	circuit, err := gkrtypes.NewCircuit(info.Circuit, gkrgates.Get)
	if err != nil {
		return circuitDataForSnark{}, fmt.Errorf("failed to convert GKR info to circuit: %w", err)
	}

	for i := range circuit {
		if !circuit[i].Gate.SupportsCurve(curve) {
			return circuitDataForSnark{}, fmt.Errorf("gate \"%s\" not usable over curve \"%s\"", info.Circuit[i].Gate, curve)
		}
	}

	return circuitDataForSnark{
		circuit:     circuit,
		assignments: assignment,
	}, nil
}

// GetValue is a debugging utility returning the value of variable v at instance i.
// While v can be an input or output variable, GetValue is most useful for querying intermediate values in the circuit.
func (c *Circuit) GetValue(v gkr.Variable, i int) frontend.Variable {
	// last input to ensure the solver's work is done before GetAssignment is called
	res, err := c.api.Compiler().NewHint(c.hints.GetAssignment, 1, c.index, int(v), i, c.assignments[c.outs[0]][i])
	if err != nil {
		panic(err)
	}
	return res[0]
}
