package gkrapi

import (
	"errors"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver/gkrgates"
	"github.com/consensys/gnark/frontend"
	gadget "github.com/consensys/gnark/internal/gkr"
	gkrbn254 "github.com/consensys/gnark/internal/gkr/bn254"
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
	circuit              gkrinfo.Circuit // untyped circuit definition
	assignments          gkrtypes.WireAssignment
	getInitialChallenges InitialChallengeGetter // optional getter for the initial Fiat-Shamir challenge
	ins                  []gkr.Variable
	outs                 []gkr.Variable
	api                  frontend.API // the parent API

	// Blueprint-based fields
	solveBlueprintID constraint.BlueprintID
	proveBlueprintID constraint.BlueprintID
	blueprint        interface{} // actual type is *gkrbn254.BlueprintSolve

	// Metadata
	hashName    string
	nbInstances int
}

// New creates a new GKR API
func New(api frontend.API) (*API, error) {
	return &API{
		circuit:   make(gkrinfo.Circuit, 0),
		parentApi: api,
	}, nil
}

// NewInput creates a new input variable.
func (api *API) NewInput() gkr.Variable {
	i := len(api.circuit)
	api.circuit = append(api.circuit, gkrinfo.Wire{})
	return gkr.Variable(i)
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
		circuit:     api.circuit,
		assignments: make(gkrtypes.WireAssignment, len(api.circuit)),
		api:         api.parentApi,
		hashName:    fiatshamirHashName,
	}

	// Create and populate blueprint
	if err := res.createBlueprint(); err != nil {
		return nil, fmt.Errorf("failed to create GKR blueprint: %w", err)
	}

	for _, opt := range options {
		opt(&res)
	}

	notOut := make([]bool, len(res.circuit))
	for i := range res.circuit {
		if res.circuit[i].IsInput() {
			res.ins = append(res.ins, gkr.Variable(i))
		}
		for _, inWI := range res.circuit[i].Inputs {
			notOut[inWI] = true
		}
	}

	if len(res.ins) == len(res.circuit) {
		return nil, errors.New("circuit has no non-input wires")
	}

	for i := range res.circuit {
		if !notOut[i] {
			res.outs = append(res.outs, gkr.Variable(i))
		}
	}

	res.api.Compiler().Defer(res.finalize)

	return &res, nil
}

// createBlueprint creates and initializes the GKR blueprint for this circuit
func (c *Circuit) createBlueprint() error {
	blueprint := &gkrbn254.BlueprintSolve{}

	// Convert circuit to typed circuit
	circuit, err := gkrtypes.NewCircuit(c.circuit, gkrgates.Get)
	if err != nil {
		return fmt.Errorf("failed to convert circuit: %w", err)
	}

	blueprint.Circuit = circuit
	blueprint.MaxNbIn = circuit.MaxGateNbIn()

	// Identify input wires
	for i := range circuit {
		if circuit[i].IsInput() {
			blueprint.NbInputs++
			blueprint.InputWires = append(blueprint.InputWires, i)
		}
	}

	// Identify output wires (not inputs to any other wire)
	isOutput := make([]bool, len(circuit))
	for i := range circuit {
		isOutput[i] = true
	}
	for _, wire := range c.circuit {
		for _, inIdx := range wire.Inputs {
			isOutput[inIdx] = false
		}
	}
	for i := range circuit {
		if isOutput[i] {
			blueprint.NbOutputVars++
			blueprint.OutputWires = append(blueprint.OutputWires, i)
		}
	}

	// Note: evaluatorPool is initialized lazily on first Solve() call

	// Register solve blueprint with compiler
	c.solveBlueprintID = c.api.Compiler().AddBlueprint(blueprint)
	c.blueprint = blueprint

	// Create and register prove blueprint with reference to solve blueprint
	proveBlueprint := &gkrbn254.BlueprintProve{
		SolveBlueprintID: c.solveBlueprintID,
		SolveBlueprint:   blueprint,
		HashName:         c.hashName,
	}
	c.proveBlueprintID = c.api.Compiler().AddBlueprint(proveBlueprint)

	return nil
}

// AddInstance adds a new instance to the GKR circuit, returning the values of output variables for the instance.
func (c *Circuit) AddInstance(input map[gkr.Variable]frontend.Variable) (map[gkr.Variable]frontend.Variable, error) {
	if len(input) != len(c.ins) {
		for k := range input {
			if k >= gkr.Variable(len(c.circuit)) {
				return nil, fmt.Errorf("variable %d is out of bounds (max %d)", k, len(c.circuit)-1)
			}
			if !c.circuit[k].IsInput() {
				return nil, fmt.Errorf("value provided for non-input variable %d", k)
			}
		}
	}

	// Build instruction calldata for blueprint
	// Format: [0]=instanceIndex, [1...]=input values as linear expressions
	compiler := c.api.Compiler()
	calldata := make([]uint32, 1, 1+len(c.ins)*2+2) // pre-allocate roughly
	calldata[0] = uint32(c.nbInstances)             // instance index

	// Encode input variables
	for _, wI := range c.ins {
		inV, ok := input[wI]
		if !ok {
			return nil, fmt.Errorf("missing entry for input variable %d", wI)
		}
		// Store in assignment for later use
		c.assignments[wI] = append(c.assignments[wI], inV)

		// Encode as linear expression in calldata
		v := compiler.ToCanonicalVariable(inV)
		v.Compress(&calldata)
	}

	// Execute solve blueprint instruction
	outputs := compiler.AddInstruction(c.solveBlueprintID, calldata)

	// Track instance count
	c.nbInstances++

	// Convert outputs to map
	res := make(map[gkr.Variable]frontend.Variable, len(c.outs))
	for i, v := range c.outs {
		outVar := compiler.InternalVariable(outputs[i])
		res[v] = outVar
		c.assignments[v] = append(c.assignments[v], outVar)
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
	nbPaddedInstances := int(ecc.NextPowerOfTwo(uint64(c.nbInstances)))
	// pad instances to the next power of 2 by repeating the last instance
	if c.nbInstances < nbPaddedInstances && c.nbInstances > 0 {
		for _, wI := range c.ins {
			c.assignments[wI] = utils.ExtendRepeatLast(c.assignments[wI], nbPaddedInstances)
		}
		for _, wI := range c.outs {
			c.assignments[wI] = utils.ExtendRepeatLast(c.assignments[wI], nbPaddedInstances)
		}
	}

	// if the circuit consists of only one instance, directly solve the circuit
	if len(c.assignments[c.ins[0]]) == 1 {
		circuit, err := gkrtypes.NewCircuit(c.circuit, gkrgates.Get)
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
	forSnark, err := newCircuitDataForSnark(utils.FieldToCurve(api.Compiler().Field()), c.circuit, c.assignments)
	if err != nil {
		return fmt.Errorf("failed to create circuit data for snark: %w", err)
	}

	compiler := api.Compiler()

	// Build calldata for prove instruction
	// Format: [0...]=challenge linear expressions (no metadata)
	proveCalldata := make([]uint32, 0, len(initialChallenges)*2+2)

	// Encode initial challenges
	for _, challenge := range initialChallenges {
		v := compiler.ToCanonicalVariable(challenge)
		v.Compress(&proveCalldata)
	}

	// Execute prove blueprint instruction
	proofOutputs := compiler.AddInstruction(c.proveBlueprintID, proveCalldata)

	// Convert outputs to proof
	proofSerialized := make([]frontend.Variable, len(proofOutputs))
	for i, wireID := range proofOutputs {
		proofSerialized[i] = compiler.InternalVariable(wireID)
	}

	var proof gadget.Proof

	forSnarkSorted := utils.SliceOfRefs(forSnark.circuit)

	if proof, err = gadget.DeserializeProof(forSnarkSorted, proofSerialized); err != nil {
		return err
	}

	var hsh hash.FieldHasher
	if hsh, err = hash.GetFieldHasher(c.hashName, api); err != nil {
		return err
	}

	return gadget.Verify(api, forSnark.circuit, forSnark.assignments, proof, fiatshamir.WithHash(hsh, initialChallenges...), gadget.WithSortedCircuit(forSnarkSorted))
}

func newCircuitDataForSnark(curve ecc.ID, untypedCircuit gkrinfo.Circuit, assignment gkrtypes.WireAssignment) (circuitDataForSnark, error) {
	circuit, err := gkrtypes.NewCircuit(untypedCircuit, gkrgates.Get)
	if err != nil {
		return circuitDataForSnark{}, fmt.Errorf("failed to convert GKR info to circuit: %w", err)
	}

	for i := range circuit {
		if !circuit[i].Gate.SupportsCurve(curve) {
			return circuitDataForSnark{}, fmt.Errorf("gate \"%s\" not usable over curve \"%s\"", untypedCircuit[i].Gate, curve)
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
	// Access blueprint directly to get assignment
	// The blueprint stores all wire assignments after solving
	if c.blueprint == nil {
		panic("blueprint not initialized")
	}

	// Get blueprint (GKR only works with U64/large fields)
	bp := c.blueprint.(*gkrbn254.BlueprintSolve)
	compiler := c.api.Compiler()
	solver, ok := compiler.(constraint.Solver[constraint.U64])
	if !ok {
		panic("compiler does not implement Solver[U64] interface")
	}
	val, err := bp.GetAssignment(solver, int(v), i)
	if err != nil {
		panic(err)
	}
	return val
}
