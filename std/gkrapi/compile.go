package gkrapi

import (
	"errors"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	gadget "github.com/consensys/gnark/internal/gkr"
	gkrbls12377 "github.com/consensys/gnark/internal/gkr/bls12-377"
	gkrbls12381 "github.com/consensys/gnark/internal/gkr/bls12-381"
	gkrbn254 "github.com/consensys/gnark/internal/gkr/bn254"
	gkrbw6761 "github.com/consensys/gnark/internal/gkr/bw6-761"
	"github.com/consensys/gnark/internal/gkr/gkrtypes"
	"github.com/consensys/gnark/internal/utils"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/gkrapi/gkr"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/multicommit"
)

// The InitialChallengeGetter provides a one-time initial Fiat-Shamir challenge for the GKR prover.
// Normally, these should include a unique circuit identifier and all input-output pairs.
type InitialChallengeGetter func() []frontend.Variable

// Circuit represents a GKR circuit.
type Circuit struct {
	circuit              gkrtypes.GadgetCircuit
	gates                []gkrtypes.GateBytecode
	assignments          gadget.WireAssignment
	getInitialChallenges InitialChallengeGetter // optional getter for the initial Fiat-Shamir challenge
	ins                  []gkr.Variable
	outs                 []gkr.Variable
	api                  frontend.API // the parent API

	// Blueprint-based fields
	blueprints gkrtypes.Blueprints

	// Metadata
	hashName    string
	nbInstances int
}

// New creates a new GKR API
func New(api frontend.API) (*API, error) {
	return &API{
		parentApi:    api,
		gateRegistry: newGateRegistry(utils.FieldToCurve(api.Compiler().Field())),
	}, nil
}

// NewInput creates a new input variable.
func (api *API) NewInput() gkr.Variable {
	i := len(api.circuit)
	api.circuit = append(api.circuit, gkrtypes.SerializableWire{})
	api.assignments = append(api.assignments, nil)
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
		circuit:     api.gateRegistry.toGadgetCircuit(api.circuit),
		assignments: make(gadget.WireAssignment, len(api.circuit)),
		api:         api.parentApi,
		hashName:    fiatshamirHashName,
	}

	// Dispatch to curve-specific factory
	curveID := utils.FieldToCurve(api.parentApi.Compiler().Field())
	compiler := api.parentApi.Compiler()

	eCircuit := api.gateRegistry.toExecutableCircuit(api.circuit)

	switch curveID {
	case ecc.BN254:
		res.blueprints = gkrbn254.NewBlueprints(eCircuit, fiatshamirHashName, compiler)
	case ecc.BLS12_377:
		res.blueprints = gkrbls12377.NewBlueprints(eCircuit, fiatshamirHashName, compiler)
	case ecc.BLS12_381:
		res.blueprints = gkrbls12381.NewBlueprints(eCircuit, fiatshamirHashName, compiler)
	case ecc.BW6_761:
		res.blueprints = gkrbw6761.NewBlueprints(eCircuit, fiatshamirHashName, compiler)
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curveID)
	}

	for _, opt := range options {
		opt(&res)
	}

	// Use circuit helper methods for inputs and outputs
	inputIndices := res.circuit.Inputs()
	res.circuit.OutputsList() // for side effects
	outputIndices := res.circuit.Outputs()

	if len(inputIndices) == len(res.circuit) {
		return nil, errors.New("circuit has no non-input wires")
	}

	res.ins = make([]gkr.Variable, len(inputIndices))
	for i, inI := range inputIndices {
		res.ins[i] = gkr.Variable(inI)
	}

	res.outs = make([]gkr.Variable, len(outputIndices))
	for i, outI := range outputIndices {
		res.outs[i] = gkr.Variable(outI)
	}

	res.api.Compiler().Defer(res.finalize)

	return &res, nil
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

	// Build instruction calldata for solveBlueprint
	// Format: [0]=totalSize, [1]=instanceIndex, [2...]=input values as linear expressions
	compiler := c.api.Compiler()
	calldata := make([]uint32, 2, 2+len(c.ins)*3) // pre-allocate: size + instanceIndex + linear expressions
	calldata[1] = uint32(c.nbInstances)

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

	// Update total size
	calldata[0] = uint32(len(calldata))

	// Execute solve blueprint instruction
	outputs := compiler.AddInstruction(c.blueprints.SolveID, calldata)

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

	c.blueprints.Solve.SetNbInstances(uint32(c.nbInstances))

	// if the circuit consists of only one instance, directly solve the circuit
	if len(c.assignments[c.ins[0]]) == 1 {
		gateIn := make([]frontend.Variable, c.circuit.MaxGateNbIn())
		for wI, w := range c.circuit {
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
		return c.verify(api, c.circuit, c.getInitialChallenges())
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
		return c.verify(api, c.circuit, []frontend.Variable{commitment})
	}, insOuts...)

	return nil
}

func (c *Circuit) verify(api frontend.API, circuit gkrtypes.GadgetCircuit, initialChallenges []frontend.Variable) error {

	compiler := api.Compiler()

	// Build calldata for prove instruction
	// Format: [0]=totalSize, [1...]=challenge linear expressions
	calldata := make([]uint32, 1, 1+len(initialChallenges)*3)

	// Encode initial challenges
	for _, challenge := range initialChallenges {
		v := compiler.ToCanonicalVariable(challenge)
		v.Compress(&calldata)
	}

	// Update total size
	calldata[0] = uint32(len(calldata))

	// Execute prove solveBlueprint instruction
	proofOutputs := compiler.AddInstruction(c.blueprints.ProveID, calldata)

	// Convert outputs to proof
	proofSerialized := make([]frontend.Variable, len(proofOutputs))
	for i, wireID := range proofOutputs {
		proofSerialized[i] = compiler.InternalVariable(wireID)
	}

	var (
		proof gadget.Proof
		err   error
	)

	forSnarkSorted := utils.SliceOfRefs(circuit)

	if proof, err = gadget.DeserializeProof(forSnarkSorted, proofSerialized); err != nil {
		return err
	}

	var hsh hash.FieldHasher
	if hsh, err = hash.GetFieldHasher(c.hashName, api); err != nil {
		return err
	}

	return gadget.Verify(api, circuit, c.assignments, proof, fiatshamir.WithHash(hsh, initialChallenges...), gadget.WithSortedCircuit(forSnarkSorted))
}

// GetValue is a debugging utility returning the value of variable v at instance i.
// While v can be an input or output variable, GetValue is most useful for querying intermediate values in the circuit.
func (c *Circuit) GetValue(v gkr.Variable, i int) frontend.Variable {
	// Create an instruction that will retrieve the assignment at solve time
	compiler := c.api.Compiler()

	// Build calldata: [0]=totalSize, [1]=wireI, [2]=instanceI, [3...]=dependency_wire_as_linear_expression
	// The dependency ensures this instruction runs after the solve instruction for instance i
	calldata := make([]uint32, 3, 6) // pre-allocate: size + wireI + instanceI + dependency linear expression (typically 3)
	calldata[1] = uint32(v)
	calldata[2] = uint32(i)

	// Use the first output variable from instance i as a dependency
	// This ensures the solve instruction for this instance has completed
	if len(c.outs) == 0 || i >= len(c.assignments[c.outs[0]]) {
		panic("GetValue called with invalid instance or before instance was added")
	}
	dependencyWire := c.assignments[c.outs[0]][i]
	depVar := compiler.ToCanonicalVariable(dependencyWire)
	depVar.Compress(&calldata)

	// Update total size
	calldata[0] = uint32(len(calldata))

	outputs := compiler.AddInstruction(c.blueprints.GetAssignmentID, calldata)
	return compiler.InternalVariable(outputs[0])
}
