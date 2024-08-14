package gkrnonative

import (
	"fmt"
	cryptofiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/utils"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/parallel"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/polynomial"
	"github.com/consensys/gnark/std/recursion"
	"github.com/consensys/gnark/std/recursion/sumcheck"
	"math/big"
	"slices"
	"strconv"
)

// Gate must be a low-degree polynomial
type Gate interface {
	Evaluate(*sumcheck.BigIntEngine, ...*big.Int) []*big.Int
	Degree() int
	NbInputs() int
	NbOutputs() int
	GetName() string
}

type WireBundle struct {
	Gate             Gate
	Layer            int
	Depth 			 int
	Inputs           []*Wires // if there are no Inputs, the wire is assumed an input wire
	Outputs          []*Wires `SameBundle:"true"` // if there are no Outputs, the wire is assumed an output wire
	nbUniqueOutputs  int     // number of other wires using it as input, not counting duplicates (i.e. providing two inputs to the same gate counts as one)
}

func bundleKey(wireBundle *WireBundle) string {
	return fmt.Sprintf("%d-%s", wireBundle.Layer, wireBundle.Gate.GetName())
}

func bundleKeyEmulated[FR emulated.FieldParams](wireBundle *WireBundleEmulated[FR]) string {
	return fmt.Sprintf("%d-%s", wireBundle.Layer, wireBundle.Gate.GetName())
}

// InitFirstWireBundle initializes the first WireBundle for Layer 0 padded with IdentityGate as relayer
func InitFirstWireBundle(inputsLen int, numLayers int) WireBundle {
	gate := IdentityGate[*sumcheck.BigIntEngine, *big.Int]{Arity: inputsLen}
	inputs := make([]*Wires, inputsLen)
	for i := 0; i < inputsLen; i++ {
		inputs[i] = &Wires{
			SameBundle:      true,
			BundleIndex:     -1,
			BundleLength:    inputsLen,
			WireIndex:       i,
			nbUniqueOutputs: 0,
		}
	}

	outputs := make([]*Wires, gate.NbOutputs())
	for i := 0; i < len(outputs); i++ {
		outputs[i] = &Wires{
			SameBundle:      true,
			BundleIndex:     0,
			BundleLength:    len(outputs),
			WireIndex:       i,
			nbUniqueOutputs: 0,
		}
	}

	return WireBundle{
		Gate:            gate,
		Layer:           0,
		Depth: 			 numLayers,
		Inputs:          inputs,
		Outputs:         outputs,
		nbUniqueOutputs: 0,
	}
}

// NewWireBundle connects previous output wires to current input wires and initializes the current output wires
func NewWireBundle(gate Gate, inputWires []*Wires, layer int, numLayers int) WireBundle {
	inputs := make([]*Wires, len(inputWires))
	for i := 0; i < len(inputWires); i++ {
		inputs[i] = &Wires{
			SameBundle:      true,
			BundleIndex:     layer - 1, //takes inputs from previous layer
			BundleLength:    len(inputs),
			WireIndex:       i,
			nbUniqueOutputs: inputWires[i].nbUniqueOutputs,
		}
	}

	outputs := make([]*Wires, gate.NbOutputs())
	for i := 0; i < len(outputs); i++ {
		outputs[i] = &Wires{
			SameBundle:      true,
			BundleIndex:     layer,
			BundleLength:    len(outputs),
			WireIndex:       i,
			nbUniqueOutputs: 0,
		}
	}

	return WireBundle{
		Gate:            gate,
		Layer:           layer,
		Depth: 			 numLayers,
		Inputs:          inputs,
		Outputs:         outputs,
		nbUniqueOutputs: 0,
	}
}

type Wires struct {
	SameBundle 	 bool
	BundleIndex  int
	BundleLength int
	WireIndex    int
	nbUniqueOutputs  int     // number of other wires using it as input, not counting duplicates (i.e. providing two inputs to the same gate counts as one)
}

type Wire struct {
	Gate            Gate
	Inputs          []*Wire // if there are no Inputs, the wire is assumed an input wire
	nbUniqueOutputs int     // number of other wires using it as input, not counting duplicates (i.e. providing two inputs to the same gate counts as one)
}

// Gate must be a low-degree polynomial
type GateEmulated[FR emulated.FieldParams] interface {
	Evaluate(*sumcheck.EmuEngine[FR], ...*emulated.Element[FR]) []*emulated.Element[FR]
	NbInputs() int
	NbOutputs() int
	Degree() int
	GetName() string
}

type WireEmulated[FR emulated.FieldParams] struct {
	Gate             GateEmulated[FR]
	Inputs           []*WireEmulated[FR] // if there are no Inputs, the wire is assumed an input wire
	nbUniqueOutputs  int                 // number of other wires using it as input, not counting duplicates (i.e. providing two inputs to the same gate counts as one)
}

type WireBundleEmulated[FR emulated.FieldParams] struct {
	Gate             GateEmulated[FR]
	Layer            int
	Depth            int
	Inputs           []*Wires // if there are no Inputs, the wire is assumed an input wire
	Outputs          []*Wires `SameBundle:"true"` // if there are no Outputs, the wire is assumed an output wire
	nbUniqueOutputs  int     // number of other wires using it as input, not counting duplicates (i.e. providing two inputs to the same gate counts as one)
}

// InitFirstWireBundle initializes the first WireBundle for Layer 0 padded with IdentityGate as relayer
func InitFirstWireBundleEmulated[FR emulated.FieldParams](inputsLen int, numLayers int) WireBundleEmulated[FR] {
	gate := IdentityGate[*sumcheck.EmuEngine[FR], *emulated.Element[FR]]{Arity: inputsLen}
	inputs := make([]*Wires, inputsLen)
	for i := 0; i < inputsLen; i++ {
		inputs[i] = &Wires{
			SameBundle:      true,
			BundleIndex:     -1,
			BundleLength:    inputsLen,
			WireIndex:       i,
			nbUniqueOutputs: 0,
		}
	}

	outputs := make([]*Wires, gate.NbOutputs())
	for i := 0; i < len(outputs); i++ {
		outputs[i] = &Wires{
			SameBundle:      true,
			BundleIndex:     0,
			BundleLength:    len(outputs),
			WireIndex:       i,
			nbUniqueOutputs: 0,
		}
	}

	return WireBundleEmulated[FR]{
		Gate:            gate,
		Layer:           0,
		Depth: 			 numLayers,
		Inputs:          inputs,
		Outputs:         outputs,
		nbUniqueOutputs: 0,
	}
}

// NewWireBundle connects previous output wires to current input wires and initializes the current output wires
func NewWireBundleEmulated[FR emulated.FieldParams](gate GateEmulated[FR], inputWires []*Wires, layer int, numLayers int) WireBundleEmulated[FR] {
	inputs := make([]*Wires, len(inputWires))
	for i := 0; i < len(inputWires); i++ {
		inputs[i] = &Wires{
			SameBundle:      true,
			BundleIndex:     layer - 1,
			BundleLength:    len(inputs),
			WireIndex:       i,
			nbUniqueOutputs: inputWires[i].nbUniqueOutputs,
		}
	}

	outputs := make([]*Wires, gate.NbOutputs())
	for i := 0; i < len(outputs); i++ {
		outputs[i] = &Wires{
			SameBundle:      true,
			BundleIndex:     layer,
			BundleLength:    len(outputs),
			WireIndex:       i,
			nbUniqueOutputs: 0,
		}
	}

	return WireBundleEmulated[FR]{
		Gate:            gate,
		Layer:           layer,
		Depth: 			 numLayers,
		Inputs:          inputs,
		Outputs:         outputs,
		nbUniqueOutputs: 0,
	}
}

type Circuit []Wire

func (w Wire) IsInput() bool {
	return len(w.Inputs) == 0
}

func (w Wire) IsOutput() bool {
	return w.nbUniqueOutputs == 0
}

func (w Wire) NbClaims() int {
	if w.IsOutput() {
		return 1
	}
	return w.nbUniqueOutputs
}

func (w Wire) nbUniqueInputs() int {
	set := make(map[*Wire]struct{}, len(w.Inputs))
	for _, in := range w.Inputs {
		set[in] = struct{}{}
	}
	return len(set)
}

func (w Wire) noProof() bool {
	return w.IsInput() && w.NbClaims() == 1
}

type CircuitBundle []WireBundle

func (w WireBundle) IsInput() bool {
	return w.Layer == 0
}

func (w WireBundle) IsOutput() bool {
	return w.Layer == w.Depth - 1
	//return w.nbUniqueOutputs == 0 && w.Layer != 0
}

func (w WireBundle) NbClaims() int {
	//todo check this
	if w.IsOutput() {
		return w.Gate.NbOutputs()
	}
	return w.nbUniqueOutputs
}

func (w WireBundle) nbUniqueInputs() int {
	set := make(map[*Wires]struct{}, len(w.Inputs))
	for _, in := range w.Inputs {
		set[in] = struct{}{}
	}
	return len(set)
}

func (w WireBundle) noProof() bool {
	return w.IsInput() // && w.NbClaims() == 1
}

func (c Circuit) maxGateDegree() int {
	res := 1
	for i := range c {
		if !c[i].IsInput() {
			res = utils.Max(res, c[i].Gate.Degree())
		}
	}
	return res
}

type CircuitBundleEmulated[FR emulated.FieldParams] []WireBundleEmulated[FR]
//todo change these methods
func (w WireBundleEmulated[FR]) IsInput() bool {
	return w.Layer == 0
}

func (w WireBundleEmulated[FR]) IsOutput() bool {
	return w.Layer == w.Depth - 1
	//return w.nbUniqueOutputs == 0
}

//todo check this - assuming single claim per individual wire
func (w WireBundleEmulated[FR]) NbClaims() int {
	return w.Gate.NbOutputs()
	// if w.IsOutput() {
	// 	return 1
	// }
	//return w.nbUniqueOutputs
}

func (w WireBundleEmulated[FR]) nbUniqueInputs() int {
	set := make(map[*Wires]struct{}, len(w.Inputs))
	for _, in := range w.Inputs {
		set[in] = struct{}{}
	}

	return len(set)
}

func (w WireBundleEmulated[FR]) noProof() bool {
	return w.IsInput() // && w.NbClaims() == 1
}

type CircuitEmulated[FR emulated.FieldParams] []WireEmulated[FR]

func (w WireEmulated[FR]) IsInput() bool {
	return len(w.Inputs) == 0
}

func (w WireEmulated[FR]) IsOutput() bool {
	return w.nbUniqueOutputs == 0
}

func (w WireEmulated[FR]) NbClaims() int {
	if w.IsOutput() {
		return 1
	}
	return w.nbUniqueOutputs
}

func (w WireEmulated[FR]) nbUniqueInputs() int {
	set := make(map[*WireEmulated[FR]]struct{}, len(w.Inputs))
	for _, in := range w.Inputs {
		set[in] = struct{}{}
	}
	return len(set)
}

func (w WireEmulated[FR]) noProof() bool {
	return w.IsInput() && w.NbClaims() == 1
}

// WireAssignment is assignment of values to the same wire across many instances of the circuit
type WireAssignment map[string]sumcheck.NativeMultilinear

type WireAssignmentBundle map[*WireBundle]WireAssignment

// WireAssignment is assignment of values to the same wire across many instances of the circuit
type WireAssignmentEmulated[FR emulated.FieldParams] map[string]polynomial.Multilinear[FR]

// WireAssignment is assignment of values to the same wire across many instances of the circuit
type WireAssignmentBundleEmulated[FR emulated.FieldParams] map[*WireBundleEmulated[FR]]WireAssignmentEmulated[FR]

type Proofs[FR emulated.FieldParams] []sumcheck.Proof[FR] // for each layer, for each wire, a sumcheck (for each variable, a polynomial)

type eqTimesGateEvalSumcheckLazyClaimsEmulated[FR emulated.FieldParams] struct {
	wire               *Wires
	commonGate 		    GateEmulated[FR]
	evaluationPoints   [][]emulated.Element[FR]
	claimedEvaluations []emulated.Element[FR]
	manager            *claimsManagerEmulated[FR] // WARNING: Circular references
	verifier           *GKRVerifier[FR]
	engine             *sumcheck.EmuEngine[FR]
}

func (e *eqTimesGateEvalSumcheckLazyClaimsEmulated[FR]) NbClaims() int {
	return len(e.evaluationPoints)
}

func (e *eqTimesGateEvalSumcheckLazyClaimsEmulated[FR]) NbVars() int {
	return len(e.evaluationPoints[0])
}

func (e *eqTimesGateEvalSumcheckLazyClaimsEmulated[FR]) CombinedSum(a *emulated.Element[FR]) *emulated.Element[FR] {
	evalsAsPoly := polynomial.Univariate[FR](e.claimedEvaluations)
	return e.verifier.p.EvalUnivariate(evalsAsPoly, a)
}

func (e *eqTimesGateEvalSumcheckLazyClaimsEmulated[FR]) Degree(int) int {
	return 1 + e.commonGate.Degree()
}

type eqTimesGateEvalSumcheckLazyClaimsBundleEmulated[FR emulated.FieldParams] struct {
	wireBundle         		*WireBundleEmulated[FR]
	claimsMapOutputsLazy    map[string]*eqTimesGateEvalSumcheckLazyClaimsEmulated[FR]
	claimsMapInputsLazy     map[string]*eqTimesGateEvalSumcheckLazyClaimsEmulated[FR]
	verifier           		*GKRVerifier[FR]
	engine             		*sumcheck.EmuEngine[FR]
}

func (e *eqTimesGateEvalSumcheckLazyClaimsBundleEmulated[FR]) addOutput(wire *Wires, evaluationPoint []emulated.Element[FR], evaluation emulated.Element[FR]) {
	claim := e.claimsMapOutputsLazy[wireKey(wire)]
	i := len(claim.evaluationPoints)
	claim.claimedEvaluations[i] = evaluation
	claim.evaluationPoints = append(claim.evaluationPoints, evaluationPoint)
}

// todo assuming single claim per wire
func (e *eqTimesGateEvalSumcheckLazyClaimsBundleEmulated[FR]) NbClaims() int {
	return len(e.claimsMapOutputsLazy)
}

// to batch sumchecks in the bundle all claims should have the same number of variables - taking first outputwire
func (e *eqTimesGateEvalSumcheckLazyClaimsBundleEmulated[FR]) NbVars() int {
	return len(e.claimsMapOutputsLazy[wireKey(e.wireBundle.Outputs[0])].evaluationPoints[0])
}

func (e *eqTimesGateEvalSumcheckLazyClaimsBundleEmulated[FR]) CombinedSum(a *emulated.Element[FR]) *emulated.Element[FR] {
	//dummy challenges only for testing
	challengesRLC := make([]*emulated.Element[FR], len(e.claimsMapOutputsLazy))
	for i := range challengesRLC {
		challengesRLC[i] = e.engine.Const(big.NewInt(int64(i+1))) // todo check this
	}
	acc := e.engine.Const(big.NewInt(0))
	for i, claim := range e.claimsMapOutputsLazy {
		_, wireIndex := parseWireKey(i)
		sum := claim.CombinedSum(a)
		sumRLC := e.engine.Mul(sum, challengesRLC[wireIndex])
		acc = e.engine.Add(acc, sumRLC)
	}
	return acc  
}

func (e *eqTimesGateEvalSumcheckLazyClaimsBundleEmulated[FR]) Degree(int) int {
	return 1 + e.wireBundle.Gate.Degree()
}

func (e *eqTimesGateEvalSumcheckLazyClaimsBundleEmulated[FR]) AssertEvaluation(r []*emulated.Element[FR], combinationCoeff, expectedValue *emulated.Element[FR], proof sumcheck.EvaluationProof) error {
	inputEvaluationsNoRedundancy := proof.([]emulated.Element[FR])
	
	field, err := emulated.NewField[FR](e.verifier.api)
	if err != nil {
		return fmt.Errorf("failed to create field: %w", err)
	}
	p, err := polynomial.New[FR](e.verifier.api)
	if err != nil {
		return err
	}

	// dummy challenges for testing, get from transcript
	challengesRLC := make([]*emulated.Element[FR], len(e.wireBundle.Outputs))
	for i := range challengesRLC {
		challengesRLC[i] = e.engine.Const(big.NewInt(int64(i+1))) 
	}

	var evaluationFinal emulated.Element[FR]
	// the eq terms
	evaluationEq := make([]*emulated.Element[FR], len(e.claimsMapOutputsLazy))
	for k, claims := range e.claimsMapOutputsLazy {
		_, wireIndex := parseWireKey(k)
		numClaims := len(claims.evaluationPoints)
		eval := p.EvalEqual(polynomial.FromSlice(claims.evaluationPoints[numClaims - 1]), r) // assuming single claim per wire
		// for i := numClaims - 2; i >= 0; i-- { 	// todo change this to handle multiple claims per wire - assuming single claim per wire so don't need to combine
		// 	eval = field.Mul(eval, combinationCoeff)
		// 	eq  := p.EvalEqual(polynomial.FromSlice(claims.evaluationPoints[i]), r)
		// 	eval = field.Add(eval, eq)
		// }
		evaluationEq[wireIndex] = eval
	}

	// the g(...) term
	if e.wireBundle.IsInput() { // From previous impl - was not needed as this is already handled with noproof before initiating sumcheck verify
		// for _, output := range e.wireBundle.Outputs { // doing on output as first layer is dummy layer with identity gate
		// 	gateEvaluationsPtr, err := p.EvalMultilinear(r, e.claimsMapOutputsLazy[wireKey(output)].manager.assignment[wireKey(output)])
		// 	if err != nil {
		// 	return err
		// 	}
		// 	gateEvaluations = append(gateEvaluations, *gateEvaluationsPtr)
		// 	for i, s := range gateEvaluations {
		// 		gateEvaluationRLC := e.engine.Mul(&s, challengesRLC[i])
		// 		gateEvaluation = *e.engine.Add(&gateEvaluation, gateEvaluationRLC)
		// 	}
		// }
	} else {
		inputEvaluations := make([]emulated.Element[FR], len(e.wireBundle.Inputs))
		indexesInProof := make(map[*Wires]int, len(inputEvaluationsNoRedundancy))

		proofI := 0
		for inI, in := range e.wireBundle.Inputs {
			indexInProof, found := indexesInProof[in]
			if !found {
				indexInProof = proofI
				indexesInProof[in] = indexInProof

				// defer verification, store new claim
				e.claimsMapInputsLazy[wireKey(in)].manager.add(in, polynomial.FromSliceReferences(r), inputEvaluationsNoRedundancy[indexInProof])
				proofI++
			}
			inputEvaluations[inI] = inputEvaluationsNoRedundancy[indexInProof]
		}
		if proofI != len(inputEvaluationsNoRedundancy) {
			return fmt.Errorf("%d input wire evaluations given, %d expected", len(inputEvaluationsNoRedundancy), proofI)
		}
		gateEvaluationOutputs := e.wireBundle.Gate.Evaluate(e.engine, polynomial.FromSlice(inputEvaluations)...)

		for i , s := range gateEvaluationOutputs {
			evaluationRLC := e.engine.Mul(s, challengesRLC[i])
			evaluationFinal = *e.engine.Add(&evaluationFinal, evaluationRLC)
		}
	}

	evaluationFinal = *e.engine.Mul(&evaluationFinal, evaluationEq[0])

	field.AssertIsEqual(&evaluationFinal, expectedValue)
	return nil
}

type claimsManagerEmulated[FR emulated.FieldParams] struct {
	claimsMap  map[string]*eqTimesGateEvalSumcheckLazyClaimsEmulated[FR]
	assignment WireAssignmentEmulated[FR]
}

func (m *claimsManagerEmulated[FR]) add(wire *Wires, evaluationPoint []emulated.Element[FR], evaluation emulated.Element[FR]) {
	claim := m.claimsMap[wireKey(wire)]
	i := len(claim.evaluationPoints) //todo check this
	claim.claimedEvaluations[i] = evaluation
	claim.evaluationPoints = append(claim.evaluationPoints, evaluationPoint)
}

type claimsManagerBundleEmulated[FR emulated.FieldParams] struct {
	claimsMap  map[string]*eqTimesGateEvalSumcheckLazyClaimsBundleEmulated[FR]
	assignment WireAssignmentBundleEmulated[FR]
}

func newClaimsManagerBundleEmulated[FR emulated.FieldParams](c CircuitBundleEmulated[FR], assignment WireAssignmentBundleEmulated[FR], verifier GKRVerifier[FR]) (claims claimsManagerBundleEmulated[FR]) {
	claims.assignment = assignment
	claims.claimsMap = make(map[string]*eqTimesGateEvalSumcheckLazyClaimsBundleEmulated[FR], len(c))
	engine, err := sumcheck.NewEmulatedEngine[FR](verifier.api)
	if err != nil {
		panic(err)
	}

	for i := range c {
		wireBundle := &c[i]
		claimsMapOutputs := make(map[string]*eqTimesGateEvalSumcheckLazyClaimsEmulated[FR], len(wireBundle.Outputs))
		claimsMapInputs := make(map[string]*eqTimesGateEvalSumcheckLazyClaimsEmulated[FR], len(wireBundle.Inputs))

		for _, wire := range wireBundle.Outputs {
			inputClaimsManager := &claimsManagerEmulated[FR]{}
			inputClaimsManager.assignment = assignment[wireBundle]
			// todo we assume each individual wire has only one claim
			inputClaimsManager.claimsMap = make(map[string]*eqTimesGateEvalSumcheckLazyClaimsEmulated[FR], 1)
			new_claim := &eqTimesGateEvalSumcheckLazyClaimsEmulated[FR]{
				wire:               wire,
				commonGate: 		wireBundle.Gate,
				evaluationPoints:   make([][]emulated.Element[FR], 0, 1), // assuming single claim per wire
				claimedEvaluations: make([]emulated.Element[FR], 1),
				manager:            inputClaimsManager,
				verifier:           &verifier,
				engine:             engine,
			}
			inputClaimsManager.claimsMap[wireKey(wire)] = new_claim
			claimsMapOutputs[wireKey(wire)] = new_claim
		}
		for _, wire := range wireBundle.Inputs {
			inputClaimsManager := &claimsManagerEmulated[FR]{}
			inputClaimsManager.assignment = assignment[wireBundle]
			// todo we assume each individual wire has only one claim
			inputClaimsManager.claimsMap = make(map[string]*eqTimesGateEvalSumcheckLazyClaimsEmulated[FR], 1)
			new_claim := &eqTimesGateEvalSumcheckLazyClaimsEmulated[FR]{
				wire:               wire,
				commonGate: 		wireBundle.Gate,
				evaluationPoints:   make([][]emulated.Element[FR], 0, 1), // assuming single claim per wire
				claimedEvaluations: make([]emulated.Element[FR], 1),
				manager:            inputClaimsManager,
				verifier:           &verifier,
				engine:             engine,
			}
			inputClaimsManager.claimsMap[wireKey(wire)] = new_claim
			claimsMapInputs[wireKey(wire)] = new_claim
		}
		claims.claimsMap[bundleKeyEmulated(wireBundle)] = &eqTimesGateEvalSumcheckLazyClaimsBundleEmulated[FR]{
			wireBundle: 			wireBundle,
			claimsMapOutputsLazy:   claimsMapOutputs,
			claimsMapInputsLazy:    claimsMapInputs,
			verifier:           	&verifier,
			engine:             	engine,
		}
	}
	return
}

func (m *claimsManagerBundleEmulated[FR]) getLazyClaim(wire *WireBundleEmulated[FR]) *eqTimesGateEvalSumcheckLazyClaimsBundleEmulated[FR] {
	return m.claimsMap[bundleKeyEmulated(wire)]
}

func (m *claimsManagerBundleEmulated[FR]) deleteClaim(wireBundle *WireBundleEmulated[FR], previousWireBundle *WireBundleEmulated[FR]) {
	if !wireBundle.IsInput() {
		sewnClaimsMapOutputs := m.claimsMap[bundleKeyEmulated(wireBundle)].claimsMapInputsLazy
		m.claimsMap[bundleKeyEmulated(previousWireBundle)].claimsMapOutputsLazy = sewnClaimsMapOutputs
	}
	delete(m.claimsMap, bundleKeyEmulated(wireBundle))
}

type claimsManager struct {
	claimsMap  map[string]*eqTimesGateEvalSumcheckLazyClaims
	assignment WireAssignment
}

func wireKey(w *Wires) string { 
	return fmt.Sprintf("%d-%d", w.BundleIndex, w.WireIndex)
}

func getOuputWireKey(w *Wires) string { 
	return fmt.Sprintf("%d-%d", w.BundleIndex + 1, w.WireIndex)
}

func getInputWireKey(w *Wires) string { 
	return fmt.Sprintf("%d-%d", w.BundleIndex - 1, w.WireIndex)
}

func parseWireKey(key string) (int, int) {
	var bundleIndex, wireIndex int
	_, err := fmt.Sscanf(key, "%d-%d", &bundleIndex, &wireIndex)
	if err != nil {
		panic(err)
	}
	return bundleIndex, wireIndex
}

type claimsManagerBundle struct {
	claimsMap  map[string]*eqTimesGateEvalSumcheckLazyClaimsBundle // bundleKey(wireBundle)
	assignment WireAssignmentBundle
}

func newClaimsManagerBundle(c CircuitBundle, assignment WireAssignmentBundle) (claims claimsManagerBundle) {
	claims.assignment = assignment
	claims.claimsMap = make(map[string]*eqTimesGateEvalSumcheckLazyClaimsBundle, len(c))

	for i := range c {
		wireBundle := &c[i]
		claimsMapOutputs := make(map[string]*eqTimesGateEvalSumcheckLazyClaims, len(wireBundle.Outputs))
		claimsMapInputs := make(map[string]*eqTimesGateEvalSumcheckLazyClaims, len(wireBundle.Inputs))
		for _, wire := range wireBundle.Outputs {
			inputClaimsManager := &claimsManager{}
			inputClaimsManager.assignment = assignment[wireBundle]
			// todo we assume each individual wire has only one claim
			inputClaimsManager.claimsMap = make(map[string]*eqTimesGateEvalSumcheckLazyClaims, len(wireBundle.Inputs))
			new_claim := &eqTimesGateEvalSumcheckLazyClaims{
				wire:               wire,
				evaluationPoints:   make([][]big.Int, 0, 1), //assuming single claim per wire
				claimedEvaluations: make([]big.Int, 1),
				manager:            inputClaimsManager,
			}
			inputClaimsManager.claimsMap[wireKey(wire)] = new_claim
			claimsMapOutputs[wireKey(wire)] = new_claim
		}
		for _, wire := range wireBundle.Inputs {
			inputClaimsManager := &claimsManager{}
			inputClaimsManager.assignment = assignment[wireBundle]
			// todo we assume each individual wire has only one claim
			inputClaimsManager.claimsMap = make(map[string]*eqTimesGateEvalSumcheckLazyClaims, len(wireBundle.Inputs))
			new_claim := &eqTimesGateEvalSumcheckLazyClaims{
				wire:               wire,
				evaluationPoints:   make([][]big.Int, 0, 1), //assuming single claim per wire
				claimedEvaluations: make([]big.Int, 1),
				manager:            inputClaimsManager,
			}
			inputClaimsManager.claimsMap[wireKey(wire)] = new_claim
			claimsMapInputs[wireKey(wire)] = new_claim
		}
		claims.claimsMap[bundleKey(wireBundle)] = &eqTimesGateEvalSumcheckLazyClaimsBundle{
			wireBundle: 	     	 wireBundle,
			claimsMapOutputsLazy:    claimsMapOutputs,
			claimsMapInputsLazy: 	 claimsMapInputs,
		}
	}
	return
}

func (m *claimsManagerBundle) getClaim(engine *sumcheck.BigIntEngine, wireBundle *WireBundle) *eqTimesGateEvalSumcheckClaimsBundle {	
	lazyClaimsOutputs := m.claimsMap[bundleKey(wireBundle)].claimsMapOutputsLazy
	lazyClaimsInputs  := m.claimsMap[bundleKey(wireBundle)].claimsMapInputsLazy
	claimsMapOutputs := make(map[string]*eqTimesGateEvalSumcheckClaims, len(lazyClaimsOutputs))
	claimsMapInputs := make(map[string]*eqTimesGateEvalSumcheckClaims, len(lazyClaimsInputs))
	
	for _, lazyClaim := range lazyClaimsOutputs {
		output_claim := &eqTimesGateEvalSumcheckClaims{
			wire:               lazyClaim.wire,
			evaluationPoints:   lazyClaim.evaluationPoints,
			claimedEvaluations: lazyClaim.claimedEvaluations,
			manager:            lazyClaim.manager,
			engine:             engine,
		}

		claimsMapOutputs[wireKey(lazyClaim.wire)] = output_claim

		if wireBundle.IsInput() {
			output_claim.inputPreprocessors = []sumcheck.NativeMultilinear{m.assignment[wireBundle][getInputWireKey(lazyClaim.wire)]}	
		} else {	
			output_claim.inputPreprocessors = make([]sumcheck.NativeMultilinear, 1) //change this
			output_claim.inputPreprocessors[0] = m.assignment[wireBundle][getInputWireKey(lazyClaim.wire)].Clone()

		}
	}

	for _, lazyClaim := range lazyClaimsInputs {

		input_claim := &eqTimesGateEvalSumcheckClaims{
			wire:               lazyClaim.wire,
			evaluationPoints:   make([][]big.Int, 0, 1),
			claimedEvaluations: make([]big.Int, 1),
			manager:            lazyClaim.manager,
			engine:             engine,
		}

		if !wireBundle.IsOutput() {
			input_claim.claimedEvaluations = lazyClaim.claimedEvaluations
			input_claim.evaluationPoints = lazyClaim.evaluationPoints
		}

		claimsMapInputs[wireKey(lazyClaim.wire)] = input_claim
	}

	res := &eqTimesGateEvalSumcheckClaimsBundle{
		wireBundle:			 wireBundle,
		claimsMapOutputs:    claimsMapOutputs,
		claimsMapInputs: 	 claimsMapInputs,
		claimsManagerBundle: m,
	}

	return res
}

// sews claimsInput to claimsOutput and deletes the claimsInput
func (m *claimsManagerBundle) deleteClaim(wireBundle *WireBundle, previousWireBundle *WireBundle) {
	if !wireBundle.IsInput() {
		sewnClaimsMapOutputs := m.claimsMap[bundleKey(wireBundle)].claimsMapInputsLazy
		m.claimsMap[bundleKey(previousWireBundle)].claimsMapOutputsLazy = sewnClaimsMapOutputs
	}
	delete(m.claimsMap, bundleKey(wireBundle))
}

func (e *claimsManagerBundle) addInput(wireBundle *WireBundle, wire *Wires, evaluationPoint []big.Int, evaluation big.Int) {
	claim := e.claimsMap[bundleKey(wireBundle)].claimsMapInputsLazy[wireKey(wire)]
	i := len(claim.evaluationPoints)
	claim.claimedEvaluations[i] = evaluation
	claim.evaluationPoints = append(claim.evaluationPoints, evaluationPoint)
}

type eqTimesGateEvalSumcheckLazyClaims struct {
	wire               *Wires
	evaluationPoints   [][]big.Int // x in the paper
	claimedEvaluations []big.Int   // y in the paper
	manager            *claimsManager
}

type eqTimesGateEvalSumcheckClaims struct {
	wire               *Wires
	evaluationPoints   [][]big.Int // x in the paper
	claimedEvaluations []big.Int   // y in the paper
	manager            *claimsManager
	engine             *sumcheck.BigIntEngine
	inputPreprocessors []sumcheck.NativeMultilinear // P_u in the paper, so that we don't need to pass along all the circuit's evaluations

	eq sumcheck.NativeMultilinear // ∑_i τ_i eq(x_i, -)
}

func (e *eqTimesGateEvalSumcheckClaims) NbClaims() int {
	return len(e.evaluationPoints)
}

func (e *eqTimesGateEvalSumcheckClaims) NbVars() int {
	return len(e.evaluationPoints[0])
}

func (c *eqTimesGateEvalSumcheckClaims) CombineWithoutComputeGJ(combinationCoeff *big.Int) {
	varsNum := c.NbVars()
	eqLength := 1 << varsNum
	claimsNum := c.NbClaims()

	// initialize the eq tables
	c.eq = make(sumcheck.NativeMultilinear, eqLength)
	for i := 0; i < eqLength; i++ {
		c.eq[i] = new(big.Int)
	}
	c.eq[0] = c.engine.One()
	sumcheck.Eq(c.engine, c.eq, sumcheck.ReferenceBigIntSlice(c.evaluationPoints[0]))
	
	newEq := make(sumcheck.NativeMultilinear, eqLength)
	for i := 0; i < eqLength; i++ {
		newEq[i] = new(big.Int)
	}
	aI := new(big.Int).Set(combinationCoeff)

	for k := 1; k < claimsNum; k++ { // TODO: parallelizable?
		// define eq_k = aᵏ eq(x_k1, ..., x_kn, *, ..., *) where x_ki are the evaluation points
		newEq[0].Set(aI)
		sumcheck.EqAcc(c.engine, c.eq, newEq, sumcheck.ReferenceBigIntSlice(c.evaluationPoints[k]))
		if k+1 < claimsNum {
			aI.Mul(aI, combinationCoeff)
		}
	}
}

type eqTimesGateEvalSumcheckLazyClaimsBundle struct {
	wireBundle         *WireBundle
	claimsMapOutputsLazy   map[string]*eqTimesGateEvalSumcheckLazyClaims
	claimsMapInputsLazy	   map[string]*eqTimesGateEvalSumcheckLazyClaims
}

func (e *eqTimesGateEvalSumcheckLazyClaimsBundle) addOutput(wire *Wires, evaluationPoint []big.Int, evaluation big.Int) {
	claim := e.claimsMapOutputsLazy[wireKey(wire)]
	i := len(claim.evaluationPoints)
	claim.claimedEvaluations[i] = evaluation
	claim.evaluationPoints = append(claim.evaluationPoints, evaluationPoint)
}

type eqTimesGateEvalSumcheckClaimsBundle struct {
	wireBundle         *WireBundle
	claimsMapOutputs   map[string]*eqTimesGateEvalSumcheckClaims
	claimsMapInputs	   map[string]*eqTimesGateEvalSumcheckClaims
	claimsManagerBundle *claimsManagerBundle
}

// assuming each individual wire has a single claim
func (e *eqTimesGateEvalSumcheckClaimsBundle) NbClaims() int {
	return len(e.claimsMapOutputs)
}
// to batch sumchecks in the bundle all claims should have the same number of variables
func (e *eqTimesGateEvalSumcheckClaimsBundle) NbVars() int {
	return len(e.claimsMapOutputs[wireKey(e.wireBundle.Outputs[0])].evaluationPoints[0])
}

func (cB *eqTimesGateEvalSumcheckClaimsBundle) Combine(combinationCoeff *big.Int) sumcheck.NativePolynomial {
	for _, claim := range cB.claimsMapOutputs {
		claim.CombineWithoutComputeGJ(combinationCoeff)
	}

	// from this point on the claims are rather simple : g_i = E(h) × R_v (P_u0(h), ...) where E and the P_u are multilinear and R_v is of low-degree
	// we batch sumchecks for g_i using RLC
	return cB.bundleComputeGJFull()
}

//todo optimise loops
// computeGJ: gⱼ = ∑_{0≤i<2ⁿ⁻ʲ} g(r₁, r₂, ..., rⱼ₋₁, Xⱼ, i...) = ∑_{0≤i<2ⁿ⁻ʲ} E(r₁, ..., X_j, i...) R_v( P_u0(r₁, ..., X_j, i...), ... ) where  E = ∑ eq_k
// the polynomial is represented by the evaluations g_j(1), g_j(2), ..., g_j(deg(g_j)).
// The value g_j(0) is inferred from the equation g_j(0) + g_j(1) = gⱼ₋₁(rⱼ₋₁). By convention, g₀ is a constant polynomial equal to the claimed sum.
func (cB *eqTimesGateEvalSumcheckClaimsBundle) bundleComputeGJFull() sumcheck.NativePolynomial {
	degGJ := 1 + cB.wireBundle.Gate.Degree() // guaranteed to be no smaller than the actual deg(g_j)
	batch := len(cB.claimsMapOutputs)
	s := make([][]sumcheck.NativeMultilinear, batch)
	// Let f ∈ { E(r₁, ..., X_j, d...) } ∪ {P_ul(r₁, ..., X_j, d...) }. It is linear in X_j, so f(m) = m×(f(1) - f(0)) + f(0), and f(0), f(1) are easily computed from the bookkeeping tables
	for i, c := range cB.claimsMapOutputs {
		_, wireIndex := parseWireKey(i)
		s[wireIndex] = make([]sumcheck.NativeMultilinear, len(c.inputPreprocessors)+1)
		s[wireIndex][0] = c.eq
		s[wireIndex][1] = c.inputPreprocessors[0].Clone()
	}
	
	// Perf-TODO: Collate once at claim "combination" time and not again. then, even folding can be done in one operation every time "next" is called
	//nbInner := len(s[0]) // wrt output, which has high nbOuter and low nbInner
	nbOuter := len(s[0][0]) / 2

	challengesRLC := make([]*big.Int, batch)
	for i := range challengesRLC {
		challengesRLC[i] = big.NewInt(int64(i+1))
	}

	// Contains the output of the algo
	evals := make([]*big.Int, degGJ)
	for i := range evals {
		evals[i] = new(big.Int)
	}
	evaluationBuffer := make([][]*big.Int, batch)
	tmpEvals := make([][]*big.Int, nbOuter)
	eqChunk := make([][]*big.Int, nbOuter)
	tmpEqs := make([]*big.Int, nbOuter)
	dEqs := make([]*big.Int, nbOuter)
	for i := range dEqs {
		dEqs[i] = new(big.Int)
	}
	tmpXs := make([][]*big.Int, batch)
	for i := range tmpXs {
		tmpXs[i] = make([]*big.Int, 2*nbOuter)
		for j := range tmpXs[i] {
			tmpXs[i][j] = new(big.Int)
		}
	}
	dXs := make([][]*big.Int, nbOuter)
	for i := range dXs {
		dXs[i] = make([]*big.Int, batch)
		for j := range dXs[i] {
			dXs[i][j] = new(big.Int)
		}
	}

	engine := cB.claimsMapOutputs[wireKey(cB.wireBundle.Outputs[0])].engine
	evalsVec := make([]*big.Int, nbOuter)
	for i := range evalsVec {
		evalsVec[i] = big.NewInt(0)
	}
	evalPtr := big.NewInt(0)
	v := big.NewInt(0)
	
	// for g(0) -- for debuggin
	// for i, _ := range cB.claimsMapOutputs {
	// 	_, wireIndex := parseWireKey(i)
	// 	// Redirect the evaluation table directly to inst
	// 	// So we don't copy into tmpXs
	// 	evaluationBuffer[wireIndex] = s[wireIndex][1][0:nbOuter]
	// 	for i, q := range evaluationBuffer[wireIndex] {
	// 		fmt.Println("evaluationBuffer0[", wireIndex, "][", i, "]", q.String())
	// 	}
	// }

	// // evaluate the gate with inputs pointed to by the evaluation buffer
	// for i := 0; i < nbOuter; i++ {
	// 	inputs := make([]*big.Int, batch)
	// 	tmpEvals[i] = make([]*big.Int, batch)
	// 	for j := 0; j < batch; j++ {
	// 		inputs[j] = evaluationBuffer[j][i]
	// 	}
	// 	tmpEvals[i] = cB.wireBundle.Gate.Evaluate(engine, inputs...)
	// 	//fmt.Println("tmpEvals[", i, "]", tmpEvals[i])
	// }

	// for x := 0; x < nbOuter; x++ {
	// 	eqChunk[x] = make([]*big.Int, batch)
	// 	for i, _ := range cB.claimsMapOutputs {
	// 		_, wireIndex := parseWireKey(i)
	// 		eqChunk[x][wireIndex] = s[wireIndex][0][0:nbOuter][x] 
	// 		v = engine.Mul(eqChunk[x][wireIndex], tmpEvals[x][wireIndex])
	// 		v = engine.Mul(v, challengesRLC[wireIndex])
	// 		evalPtr = engine.Add(evalPtr, v)
	// 	}
	// }
	// //fmt.Println("evalPtr", evalPtr)

	// // Then update the evalsValue
	// evals[0] = evalPtr// 0 because t = 0

	// Second special case : evaluation at t = 1
	evalPtr = big.NewInt(0)	
	for i, _ := range cB.claimsMapOutputs {
		_, wireIndex := parseWireKey(i)
		// Redirect the evaluation table directly to inst
		// So we don't copy into tmpXs
		evaluationBuffer[wireIndex] = s[wireIndex][1][nbOuter:nbOuter*2]
	}

	for x := 0; x < nbOuter; x++ {
		inputs := make([]*big.Int, batch)
		tmpEvals[x] = make([]*big.Int, batch)
		for j := 0; j < batch; j++ {
			inputs[j] = evaluationBuffer[j][x]
		}
		tmpEvals[x] = cB.wireBundle.Gate.Evaluate(engine, inputs...)

		eqChunk[x] = make([]*big.Int, batch)
		for i, _ := range cB.claimsMapOutputs {
			_, wireIndex := parseWireKey(i)
			v = engine.Mul(tmpEvals[x][wireIndex], challengesRLC[wireIndex])
			evalsVec[x] = engine.Add(evalsVec[x], v)
		}
		eqChunk[x][0] = s[0][0][nbOuter:nbOuter*2][x]
		evalsVec[x] = engine.Mul(evalsVec[x], eqChunk[x][0])
		evalPtr = engine.Add(evalPtr, evalsVec[x])
	}		

	// Then update the evalsValue
	evals[0] = evalPtr // 1 because t = 1
		
	// Then regular case t >= 2

	// Initialize the eq and dEq table, at the value for t = 1
	// (We get the next values for t by adding dEqs)
	// Initializes the dXs as P(t=1, x) - P(t=0, x)
	// As for eq, we initialize each input table `X` with the value for t = 1
	// (We get the next values for t by adding dXs)
	for x := 0; x < nbOuter; x++ {
		tmpEqs[x] = s[0][0][nbOuter:nbOuter*2][x]
		dEqs[x] = engine.Sub(s[0][0][nbOuter+x], s[0][0][x])
		for i, _ := range cB.claimsMapOutputs {
			_, wireIndex := parseWireKey(i)
			dXs[x][wireIndex] = engine.Sub(s[wireIndex][1][nbOuter+x], s[wireIndex][1][x])
			tmpXs[wireIndex][0:nbOuter][x] = s[wireIndex][1][nbOuter:nbOuter*2][x]
			evaluationBuffer[wireIndex] = tmpXs[wireIndex][0:nbOuter]
		}
	}

	for t := 1; t < degGJ; t++ {
		evalPtr = big.NewInt(0)
		nInputsSubChunkLen := 1 * nbOuter // assuming single input per claim
		// Update the value of tmpXs : as dXs and tmpXs have the same layout,
		// no need to make a double loop on k : the index of the separate inputs
		// We can do this, because P is multilinear so P(t+1,x) = P(t, x) + dX(x)
		for i, _ := range cB.claimsMapOutputs {
			_, wireIndex := parseWireKey(i)
			for kx := 0; kx < nInputsSubChunkLen; kx++ {
				tmpXs[wireIndex][kx] = engine.Add(tmpXs[wireIndex][kx], dXs[kx][wireIndex])
			}
		}

		for x := 0; x < nbOuter; x++ {
			evalsVec[x] = big.NewInt(0)
			tmpEqs[x] = engine.Add(tmpEqs[x], dEqs[x])

			inputs := make([]*big.Int, batch)
			tmpEvals[x] = make([]*big.Int, batch)
			for j := 0; j < batch; j++ {
				inputs[j] = evaluationBuffer[j][x]
			}
			tmpEvals[x] = cB.wireBundle.Gate.Evaluate(engine, inputs...)

			for i, _ := range cB.claimsMapOutputs {
				_, wireIndex := parseWireKey(i)
				v = engine.Mul(tmpEvals[x][wireIndex], challengesRLC[wireIndex])
				evalsVec[x] = engine.Add(evalsVec[x], v)
			}
			evalsVec[x] = engine.Mul(evalsVec[x], tmpEqs[x])
			evalPtr = engine.Add(evalPtr, evalsVec[x])
		}

		evals[t] = evalPtr

	}

	// Perf-TODO: Separate functions Gate.TotalDegree and Gate.Degree(i) so that we get to use possibly smaller values for degGJ. Won't help with MiMC though
	// for _, eval := range evals {
	// 	fmt.Println("evals", eval.String())
	// }
	return evals
}

// Next first folds the "preprocessing" and "eq" polynomials then compute the new g_j
func (c *eqTimesGateEvalSumcheckClaimsBundle) Next(element *big.Int) sumcheck.NativePolynomial {
	eq := []*big.Int{}
	for j, claim := range c.claimsMapOutputs {
		_, wireIndex := parseWireKey(j)
		for i := 0; i < len(claim.inputPreprocessors); i++ {
			claim.inputPreprocessors[i] = sumcheck.Fold(claim.engine, claim.inputPreprocessors[i], element).Clone()
		}
		if wireIndex == 0 {
			eq = sumcheck.Fold(claim.engine, claim.eq, element).Clone()
		}
		claim.eq = eq
	}

	return c.bundleComputeGJFull()
}

func (c *eqTimesGateEvalSumcheckClaimsBundle) ProverFinalEval(r []*big.Int) sumcheck.NativeEvaluationProof {
	engine := c.claimsMapOutputs[wireKey(c.wireBundle.Outputs[0])].engine
	//defer the proof, return list of claims
	evaluations := make([]*big.Int, 0, len(c.wireBundle.Outputs))
	noMoreClaimsAllowed := make(map[*Wires]struct{}, len(c.claimsMapOutputs))
	for _, claim := range c.claimsMapOutputs {
		noMoreClaimsAllowed[claim.wire] = struct{}{}
	}
	// each claim corresponds to a wireBundle, P_u is folded and added to corresponding claimBundle
	for _, in  := range c.wireBundle.Inputs {
		puI := c.claimsMapOutputs[getOuputWireKey(in)].inputPreprocessors[0] //todo change this - maybe not required
		if _, found := noMoreClaimsAllowed[in]; !found {
			noMoreClaimsAllowed[in] = struct{}{}
			puI = sumcheck.Fold(engine, puI, r[len(r)-1])
			puI0 := new(big.Int).Set(puI[0])
			c.claimsManagerBundle.addInput(c.wireBundle, in, sumcheck.DereferenceBigIntSlice(r), *puI0)
			evaluations = append(evaluations, puI0)
		}
	}

	return evaluations
}

func (e *eqTimesGateEvalSumcheckClaimsBundle) Degree(int) int {
	return 1 + e.wireBundle.Gate.Degree()
}

func setup(current *big.Int, target *big.Int, c CircuitBundle, assignment WireAssignmentBundle, options ...OptionGkr) (settings, error) {
	var o settings
	var err error
	for _, option := range options {
		option(&o)
	}

	o.nbVars = assignment.NumVars()
	nbInstances := assignment.NumInstances()
	if 1<<o.nbVars != nbInstances {
		return o, fmt.Errorf("number of instances must be power of 2")
	}

	if o.sorted == nil {
		o.sorted = topologicalSortBundle(c)
	}

	if o.transcript == nil {

		challengeNames := ChallengeNamesBundle(o.sorted, o.nbVars, o.transcriptPrefix)
		fshash, err := recursion.NewShort(current, target)
		if err != nil {
			return o, fmt.Errorf("new short hash: %w", err)
		}
		o.transcript = cryptofiatshamir.NewTranscript(fshash, challengeNames...)

		// bind challenge from previous round if it is a continuation
		if err = sumcheck.BindChallengeProver(o.transcript, challengeNames[0], o.baseChallenges); err != nil {
			return o, fmt.Errorf("base: %w", err)
		}

	}

	return o, err
}

type settings struct {
	sorted           []*WireBundle
	transcript       *cryptofiatshamir.Transcript
	baseChallenges   []*big.Int
	transcriptPrefix string
	nbVars           int
}

type OptionSet func(*settings)

func WithSortedCircuitSet(sorted []*WireBundle) OptionSet {
	return func(options *settings) {
		options.sorted = sorted
	}
}

type NativeProofs []sumcheck.NativeProof

type OptionGkr func(*settings)

type SettingsEmulated[FR emulated.FieldParams] struct {
	sorted           []*WireBundleEmulated[FR]
	transcript       *fiatshamir.Transcript
	transcriptPrefix string
	nbVars           int
}

type OptionEmulated[FR emulated.FieldParams] func(*SettingsEmulated[FR])

func WithSortedCircuitEmulated[FR emulated.FieldParams](sorted []*WireBundleEmulated[FR]) OptionEmulated[FR] {
	return func(options *SettingsEmulated[FR]) {
		options.sorted = sorted
	}
}

// Verifier allows to check sumcheck proofs. See [NewVerifier] for initializing the instance.
type GKRVerifier[FR emulated.FieldParams] struct {
	api frontend.API
	f   *emulated.Field[FR]
	p   *polynomial.Polynomial[FR]
	*sumcheck.Config
}

// NewVerifier initializes a new sumcheck verifier for the parametric emulated
// field FR. It returns an error if the given options are invalid or when
// initializing emulated arithmetic fails.
func NewGKRVerifier[FR emulated.FieldParams](api frontend.API, opts ...sumcheck.Option) (*GKRVerifier[FR], error) {
	cfg, err := sumcheck.NewConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("new configuration: %w", err)
	}
	f, err := emulated.NewField[FR](api)
	if err != nil {
		return nil, fmt.Errorf("new field: %w", err)
	}
	p, err := polynomial.New[FR](api)
	if err != nil {
		return nil, fmt.Errorf("new polynomial: %w", err)
	}
	return &GKRVerifier[FR]{
		api:    api,
		f:      f,
		p:      p,
		Config: cfg,
	}, nil
}

// bindChallenge binds the values for challengeName using in-circuit Fiat-Shamir transcript.
func (v *GKRVerifier[FR]) bindChallenge(fs *fiatshamir.Transcript, challengeName string, values []emulated.Element[FR]) error {
	for i := range values {
		bts := v.f.ToBits(&values[i])
		slices.Reverse(bts)
		if err := fs.Bind(challengeName, bts); err != nil {
			return fmt.Errorf("bind challenge %s %d: %w", challengeName, i, err)
		}
	}
	return nil
}

func (v *GKRVerifier[FR]) setup(api frontend.API, c CircuitBundleEmulated[FR], assignment WireAssignmentBundleEmulated[FR], transcriptSettings fiatshamir.SettingsEmulated[FR], options ...OptionEmulated[FR]) (SettingsEmulated[FR], error) {
	var fr FR
	var o SettingsEmulated[FR]
	var err error
	for _, option := range options {
		option(&o)
	}

	cfg, err := sumcheck.NewVerificationConfig[FR]()
	if err != nil {
		return o, fmt.Errorf("verification opts: %w", err)
	}

	o.nbVars = assignment.NumVars()
	nbInstances := assignment.NumInstances()
	if 1<<o.nbVars != nbInstances {
		return o, fmt.Errorf("number of instances must be power of 2")
	}

	if o.sorted == nil {
		o.sorted = topologicalSortBundleEmulated(c)
	}

	if transcriptSettings.Transcript == nil {
		challengeNames := ChallengeNamesEmulated(o.sorted, o.nbVars, transcriptSettings.Prefix)
		o.transcript, err = recursion.NewTranscript(api, fr.Modulus(), challengeNames)
		if err != nil {
			return o, fmt.Errorf("new transcript: %w", err)
		}
		// bind challenge from previous round if it is a continuation
		if err = v.bindChallenge(o.transcript, challengeNames[0], cfg.BaseChallenges); err != nil {
			return o, fmt.Errorf("base: %w", err)
		}
	} else {
		o.transcript, o.transcriptPrefix = transcriptSettings.Transcript, transcriptSettings.Prefix
	}

	return o, err
}

// ProofSize computes how large the proof for a circuit would be. It needs nbUniqueOutputs to be set
func ProofSize[FR emulated.FieldParams](c CircuitEmulated[FR], logNbInstances int) int {
	nbUniqueInputs := 0
	nbPartialEvalPolys := 0
	for i := range c {
		nbUniqueInputs += c[i].nbUniqueOutputs // each unique output is manifest in a finalEvalProof entry
		if !c[i].noProof() {
			nbPartialEvalPolys += c[i].Gate.Degree() + 1
		}
	}
	return nbUniqueInputs + nbPartialEvalPolys*logNbInstances
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func ChallengeNames(sorted []*Wire, logNbInstances int, prefix string) []string {

	// Pre-compute the size TODO: Consider not doing this and just grow the list by appending
	size := logNbInstances // first challenge

	for _, w := range sorted {
		if w.noProof() { // no proof, no challenge
			continue
		}
		if w.NbClaims() > 1 { //combine the claims
			size++
		}
		size += logNbInstances // full run of sumcheck on logNbInstances variables
	}

	nums := make([]string, max(len(sorted), logNbInstances))
	for i := range nums {
		nums[i] = strconv.Itoa(i)
	}

	challenges := make([]string, size)

	// output wire claims
	firstChallengePrefix := prefix + "fC."
	for j := 0; j < logNbInstances; j++ {
		challenges[j] = firstChallengePrefix + nums[j]
	}
	j := logNbInstances
	for i := len(sorted) - 1; i >= 0; i-- {
		if sorted[i].noProof() {
			continue
		}
		wirePrefix := prefix + "w" + nums[i] + "."

		if sorted[i].NbClaims() > 1 {
			challenges[j] = wirePrefix + "comb"
			j++
		}

		partialSumPrefix := wirePrefix + "pSP."
		for k := 0; k < logNbInstances; k++ {
			challenges[j] = partialSumPrefix + nums[k]
			j++
		}
	}
	return challenges
}

func ChallengeNamesBundle(sorted []*WireBundle, logNbInstances int, prefix string) []string {

	// Pre-compute the size TODO: Consider not doing this and just grow the list by appending
	size := logNbInstances // first challenge

	for _, w := range sorted {
		if w.noProof() { // no proof, no challenge
			continue
		}
		if w.NbClaims() > 1 { //combine the claims
			size++
		}
		size += logNbInstances // full run of sumcheck on logNbInstances variables
	}

	nums := make([]string, max(len(sorted), logNbInstances))
	for i := range nums {
		nums[i] = strconv.Itoa(i)
	}

	challenges := make([]string, size)

	// output wire claims
	firstChallengePrefix := prefix + "fC."
	for j := 0; j < logNbInstances; j++ {
		challenges[j] = firstChallengePrefix + nums[j]
	}
	j := logNbInstances
	for i := len(sorted) - 1; i >= 0; i-- {
		if sorted[i].noProof() {
			continue
		}
		wirePrefix := prefix + "w" + nums[i] + "."

		if sorted[i].NbClaims() > 1 {
			challenges[j] = wirePrefix + "comb"
			j++
		}

		partialSumPrefix := wirePrefix + "pSP."
		for k := 0; k < logNbInstances; k++ {
			challenges[j] = partialSumPrefix + nums[k]
			j++
		}
	}
	return challenges
}

func ChallengeNamesEmulated[FR emulated.FieldParams](sorted []*WireBundleEmulated[FR], logNbInstances int, prefix string) []string {

	// Pre-compute the size TODO: Consider not doing this and just grow the list by appending
	size := logNbInstances // first challenge

	for _, w := range sorted {
		if w.noProof() { // no proof, no challenge
			continue
		}
		if w.NbClaims() > 1 { //combine the claims
			size++
		}
		size += logNbInstances // full run of sumcheck on logNbInstances variables
	}

	nums := make([]string, max(len(sorted), logNbInstances))
	for i := range nums {
		nums[i] = strconv.Itoa(i)
	}

	challenges := make([]string, size)

	// output wire claims
	firstChallengePrefix := prefix + "fC."
	for j := 0; j < logNbInstances; j++ {
		challenges[j] = firstChallengePrefix + nums[j]
	}
	j := logNbInstances
	for i := len(sorted) - 1; i >= 0; i-- {
		if sorted[i].noProof() {
			continue
		}
		wirePrefix := prefix + "w" + nums[i] + "."

		if sorted[i].NbClaims() > 1 {
			challenges[j] = wirePrefix + "comb"
			j++
		}

		partialSumPrefix := wirePrefix + "pSP."
		for k := 0; k < logNbInstances; k++ {
			challenges[j] = partialSumPrefix + nums[k]
			j++
		}
	}
	return challenges
}

func getFirstChallengeNames(logNbInstances int, prefix string) []string {
	res := make([]string, logNbInstances)
	firstChallengePrefix := prefix + "fC."
	for i := 0; i < logNbInstances; i++ {
		res[i] = firstChallengePrefix + strconv.Itoa(i)
	}
	return res
}

func (v *GKRVerifier[FR]) getChallengesFr(transcript *fiatshamir.Transcript, names []string) (challenges []emulated.Element[FR], err error) {
	challenges = make([]emulated.Element[FR], len(names))
	var challenge emulated.Element[FR]
	var fr FR
	for i, name := range names {
		nativeChallenge, err := transcript.ComputeChallenge(name)
		if err != nil {
			return nil, fmt.Errorf("compute challenge %s: %w", names, err)
		}
		// TODO: when implementing better way (construct from limbs instead of bits) then change
		chBts := bits.ToBinary(v.api, nativeChallenge, bits.WithNbDigits(fr.Modulus().BitLen()))
		challenge = *v.f.FromBits(chBts...)
		challenges[i] = challenge

	}
	return challenges, nil
}

// Prove consistency of the claimed assignment
func Prove(current *big.Int, target *big.Int, c CircuitBundle, assignment WireAssignmentBundle, transcriptSettings fiatshamir.SettingsBigInt, options ...OptionGkr) (NativeProofs, error) {
	be := sumcheck.NewBigIntEngine(target)
	o, err := setup(current, target, c, assignment, options...)
	if err != nil {
		return nil, err
	}

	claimBundle := newClaimsManagerBundle(c, assignment)
	proof := make(NativeProofs, len(c))
	challengeNames := getFirstChallengeNames(o.nbVars, o.transcriptPrefix)
	// firstChallenge called rho in the paper
	firstChallenge := make([]*big.Int, len(challengeNames))
	for i := 0; i < len(challengeNames); i++ {
		firstChallenge[i], _, err = sumcheck.DeriveChallengeProver(o.transcript, challengeNames[i:], nil)
		if err != nil {
			return nil, err
		}
	}

	var baseChallenge []*big.Int
	for i := len(c) - 1; i >= 0; i-- {
		wireBundle := o.sorted[i]
		var previousWireBundle *WireBundle
		if !wireBundle.IsInput() {
			previousWireBundle = o.sorted[i-1]
		}
		claimBundleMap := claimBundle.claimsMap[bundleKey(wireBundle)]

		if wireBundle.IsOutput() {
			for _ , outputs := range wireBundle.Outputs {
				evaluation := sumcheck.Eval(be, assignment[wireBundle][wireKey(outputs)], firstChallenge)
				claimBundleMap.addOutput(outputs, sumcheck.DereferenceBigIntSlice(firstChallenge), *evaluation)
			}
		}

		claimBundleSumcheck := claimBundle.getClaim(be, wireBundle)
		var finalEvalProofLen int

		if wireBundle.noProof() { // input wires with one claim only
			proof[i] = sumcheck.NativeProof{
				RoundPolyEvaluations: []sumcheck.NativePolynomial{},
				FinalEvalProof:       sumcheck.NativeDeferredEvalProof([]big.Int{}),
			}
		} else {
			proof[i], err = sumcheck.Prove(
				current, target, claimBundleSumcheck,
			)
			if err != nil {
				return proof, err
			}

			finalEvalProof := proof[i].FinalEvalProof
			switch finalEvalProof := finalEvalProof.(type) {
			case nil:
				finalEvalProofCasted := sumcheck.NativeDeferredEvalProof([]big.Int{})
				proof[i].FinalEvalProof = finalEvalProofCasted
			case []*big.Int:
				finalEvalProofLen = len(finalEvalProof)
				finalEvalProofCasted := sumcheck.NativeDeferredEvalProof(sumcheck.DereferenceBigIntSlice(finalEvalProof))
				proof[i].FinalEvalProof = finalEvalProofCasted
			default:
				return nil, fmt.Errorf("finalEvalProof is not of type DeferredEvalProof")
			}

			baseChallenge = make([]*big.Int, finalEvalProofLen)
			for i := 0; i < finalEvalProofLen; i++ {
				baseChallenge[i] = finalEvalProof.([]*big.Int)[i]
			}
		}
		// the verifier checks a single claim about input wires itself
		claimBundle.deleteClaim(wireBundle, previousWireBundle)
	}

	return proof, nil
}

// Verify the consistency of the claimed output with the claimed input
// Unlike in Prove, the assignment argument need not be complete,
// Use valueOfProof[FR](proof) to convert nativeproof by prover into nonnativeproof used by in-circuit verifier
func (v *GKRVerifier[FR]) Verify(api frontend.API, c CircuitBundleEmulated[FR], assignment WireAssignmentBundleEmulated[FR], proof Proofs[FR], transcriptSettings fiatshamir.SettingsEmulated[FR], options ...OptionEmulated[FR]) error {
	o, err := v.setup(api, c, assignment, transcriptSettings, options...)
	if err != nil {
		return err
	}
	sumcheck_verifier, err := sumcheck.NewVerifier[FR](api)
	if err != nil {
		return err
	}

	claimBundle := newClaimsManagerBundleEmulated[FR](c, assignment, *v)
	var firstChallenge []emulated.Element[FR]
	firstChallenge, err = v.getChallengesFr(o.transcript, getFirstChallengeNames(o.nbVars, o.transcriptPrefix))
	if err != nil {
		return err
	}

	var baseChallenge []emulated.Element[FR]
	for i := len(c) - 1; i >= 0; i-- {
		wireBundle := o.sorted[i]
		var previousWireBundle *WireBundleEmulated[FR]
		if !wireBundle.IsInput() {
			previousWireBundle = o.sorted[i-1]
		}
		claimBundleMap := claimBundle.claimsMap[bundleKeyEmulated(wireBundle)]
		if wireBundle.IsOutput() {
			for _, outputs := range wireBundle.Outputs {
				var evaluation emulated.Element[FR]
				evaluationPtr, err := v.p.EvalMultilinear(polynomial.FromSlice(firstChallenge), assignment[wireBundle][wireKey(outputs)])
				if err != nil {
					return err
				}
				evaluation = *evaluationPtr
				claimBundleMap.addOutput(outputs, firstChallenge, evaluation)
			}
		}

		proofW := proof[i]
		finalEvalProof := proofW.FinalEvalProof
		claim := claimBundle.getLazyClaim(wireBundle)

		if wireBundle.noProof() { // input wires with one claim only
			// make sure the proof is empty
			// make sure finalevalproof is of type deferred for gkr
			var proofLen int
			switch proof := finalEvalProof.(type) {
			case nil: //todo check this
				proofLen = 0
			case []emulated.Element[FR]:
				proofLen = len(sumcheck.DeferredEvalProof[FR](proof))
			default:
				return fmt.Errorf("finalEvalProof is not of type DeferredEvalProof")
			}

			if (finalEvalProof != nil && proofLen != 0) || len(proofW.RoundPolyEvaluations) != 0 {
				return fmt.Errorf("no proof allowed for input wire with a single claim")
			}

			if wireBundle.NbClaims() == len(wireBundle.Inputs) { // input wire // todo fix this
				// simply evaluate and see if it matches
				for _, output := range wireBundle.Outputs {
					var evaluation emulated.Element[FR]
					evaluationPtr, err := v.p.EvalMultilinear(polynomial.FromSlice(claim.claimsMapOutputsLazy[wireKey(output)].evaluationPoints[0]), assignment[wireBundle][getInputWireKey(output)])
					if err != nil {
						return err
					}
					evaluation = *evaluationPtr
					v.f.AssertIsEqual(&claim.claimsMapOutputsLazy[wireKey(output)].claimedEvaluations[0], &evaluation)
				}
				//todo input actual scalrbits from input testing only
				scalarbits := v.f.ToBits(v.f.Modulus())
				nBInstances := 1 << o.nbVars
				scalarbitsEmulatedAssignement := make([]emulated.Element[FR], nBInstances)
				for i := range scalarbitsEmulatedAssignement {
					scalarbitsEmulatedAssignement[i] = *v.f.NewElement(scalarbits[0])
				}

				challengesEval := make([]emulated.Element[FR], o.nbVars)
				for i := 0; i < o.nbVars; i++ {
					challengesEval[i] = *v.f.NewElement(uint64(i))
				}
				for range scalarbits{
					_, err := v.p.EvalMultilinear(polynomial.FromSlice(challengesEval), polynomial.Multilinear[FR](scalarbitsEmulatedAssignement))
					if err != nil {
						return err
					}
				}

			}
		} else if err = sumcheck_verifier.Verify(
			claim, proof[i],
		); err == nil {
			switch proof := finalEvalProof.(type) {
			case []emulated.Element[FR]:
				baseChallenge = sumcheck.DeferredEvalProof[FR](proof)
			default:
				return fmt.Errorf("finalEvalProof is not of type DeferredEvalProof")
			}
			_ = baseChallenge
		} else {
			return err
		}
		claimBundle.deleteClaim(wireBundle, previousWireBundle)
	}
	return nil
}

//todo reimplement for wireBundle - outputsList also sets the nbUniqueOutputs fields. It also sets the wire metadata.
func outputsList(c CircuitBundle, indexes map[*WireBundle]map[*Wires]int) [][][]int {
	res := make([][][]int, len(c))
	for i := range c {
		res[i] = make([][]int, len(c[i].Inputs))
		c[i].nbUniqueOutputs = 0
	}
	ins := make(map[int]struct{}, len(c))
	for i := range c {
			for k := range ins { // clear map
				delete(ins, k)
			}
			for _, in := range c[i].Inputs {
				inI := indexes[&c[i]][in]
				res[i][inI] = append(res[i][inI], len(c[i].Inputs))
				if _, ok := ins[inI]; !ok {
					in.nbUniqueOutputs++
					ins[inI] = struct{}{}
				}
			}
	}
	return res
}

type topSortData struct {
	outputs    [][][]int
	status     [][]int // status > 0 indicates number of inputs left to be ready. status = 0 means ready. status = -1 means done
	index      map[*WireBundle]map[*Wires]int
	leastReady int
}

func (d *topSortData) markDone(i int, j int) {
	d.status[i][j] = -1
	for _, outI := range d.outputs[i][j] {
		d.status[j][outI]--
		if d.status[j][outI] == 0 && outI < d.leastReady {
			d.leastReady = outI
		}
	}

	for d.leastReady < len(d.status) && d.status[i][d.leastReady] != 0 {
		d.leastReady++
	}
}

func indexMap(c CircuitBundle) map[*WireBundle]map[*Wires]int {
	res := make(map[*WireBundle]map[*Wires]int, len(c))
	for i := range c {
		res[&c[i]] = make(map[*Wires]int, len(c[i].Inputs))
		for j := range c[i].Inputs {
			res[&c[i]][c[i].Inputs[j]] = j
		}
	}
	return res
}

func statusList(c CircuitBundle) [][]int {
	res := make([][]int, len(c))
	for i := range c {
		res[i] = make([]int, len(c[i].Inputs))
		for j := range c[i].Inputs {
			if c[i].IsInput() {
				res[i][j] = 0
			} else {
				res[i][j] = len(c[i].Inputs)
			}
		}

		for range c[i].Outputs {
			res[i] = append(res[i], len(c[i].Outputs))
		}
	}
	return res
}

type IdentityGate[AE sumcheck.ArithEngine[E], E element] struct{
	Arity int
}

func (gate IdentityGate[AE, E]) NbOutputs() int {
	return gate.Arity
}

func (IdentityGate[AE, E]) Evaluate(api AE, input ...E) []E {
	return input
}

func (IdentityGate[AE, E]) Degree() int {
	return 1
}

func (gate IdentityGate[AE, E]) NbInputs() int {
	return gate.Arity
}

func (gate IdentityGate[AE, E]) GetName() string {
	return "identity"
}

// outputsList also sets the nbUniqueOutputs fields. It also sets the wire metadata.
func outputsListEmulated[FR emulated.FieldParams](c CircuitEmulated[FR], indexes map[*WireEmulated[FR]]int) [][]int {
	res := make([][]int, len(c))
	for i := range c {
		res[i] = make([]int, 0)
		c[i].nbUniqueOutputs = 0
		if c[i].IsInput() {
			c[i].Gate = IdentityGate[*sumcheck.EmuEngine[FR], *emulated.Element[FR]]{}
		}
	}
	ins := make(map[int]struct{}, len(c))
	for i := range c {
		for k := range ins { // clear map
			delete(ins, k)
		}
		for _, in := range c[i].Inputs {
			inI := indexes[in]
			res[inI] = append(res[inI], i)
			if _, ok := ins[inI]; !ok {
				in.nbUniqueOutputs++
				ins[inI] = struct{}{}
			}
		}
	}
	return res
}

type topSortDataEmulated[FR emulated.FieldParams] struct {
	outputs    [][]int
	status     []int // status > 0 indicates number of inputs left to be ready. status = 0 means ready. status = -1 means done
	index      map[*WireEmulated[FR]]int
	leastReady int
}

func (d *topSortDataEmulated[FR]) markDone(i int) {

	d.status[i] = -1

	for _, outI := range d.outputs[i] {
		d.status[outI]--
		if d.status[outI] == 0 && outI < d.leastReady {
			d.leastReady = outI
		}
	}

	for d.leastReady < len(d.status) && d.status[d.leastReady] != 0 {
		d.leastReady++
	}
}

func indexMapEmulated[FR emulated.FieldParams](c CircuitEmulated[FR]) map[*WireEmulated[FR]]int {
	res := make(map[*WireEmulated[FR]]int, len(c))
	for i := range c {
		res[&c[i]] = i
	}
	return res
}

func statusListEmulated[FR emulated.FieldParams](c CircuitEmulated[FR]) []int {
	res := make([]int, len(c))
	for i := range c {
		res[i] = len(c[i].Inputs)
	}
	return res
}

// TODO: reimplement this for wirebundle, Have this use algo_utils.TopologicalSort underneath

// topologicalSort sorts the wires in order of dependence. Such that for any wire, any one it depends on
// occurs before it. It tries to stick to the input order as much as possible. An already sorted list will remain unchanged.
// It also sets the nbOutput flags, and a dummy IdentityGate for input wires.
// Worst-case inefficient O(n^2), but that probably won't matter since the circuits are small.
// Furthermore, it is efficient with already-close-to-sorted lists, which are the expected input
func topologicalSortBundle(c CircuitBundle) []*WireBundle {
	// var data topSortDataBundle
	// data.index = indexMapBundle(c)
	// data.outputs = outputsListBundle(c, data.index)
	// data.status = statusListBundle(c)
	// fmt.Println("data.status", data.status)
	// sorted := make([]*WireBundle, len(c))

	// data.leastReady = 0
	// for i := range c {
	// 	fmt.Println("data.status[", i, "][", data.leastReady, "]", data.status[i][data.leastReady])
	// 	for data.leastReady < len(data.status[i]) - 1 && data.status[i][data.leastReady] != 0 {
	// 		data.leastReady++
	// 	}
	// 	fmt.Println("data.leastReady", data.leastReady)
	// }
	// 	// if data.leastReady < len(data.status[i]) - 1 && data.status[i][data.leastReady] != 0 {
	// 	// 	break
	// // }

	// for i := range c {
	// 	fmt.Println("data.leastReady", data.leastReady)
	// 	fmt.Println("i", i)
	// 	sorted[i] = &c[i] // .wires[data.leastReady]
	// 	data.markDone(i, data.leastReady)
	// }

	//return sorted

	sorted := make([]*WireBundle, len(c))
	for i := range c {
		sorted[i] = &c[i]
	}
	return sorted
}

// Complete the circuit evaluation from input values
func (a WireAssignmentBundle) Complete(c CircuitBundle, target *big.Int) WireAssignmentBundle {

	engine := sumcheck.NewBigIntEngine(target)
	sortedWires := topologicalSortBundle(c)
	nbInstances := a.NumInstances()
	maxNbIns := 0

	for _, w := range sortedWires {
		maxNbIns = utils.Max(maxNbIns, len(w.Inputs))
		for _, output := range w.Outputs {
			if a[w][wireKey(output)] == nil {
				a[w][wireKey(output)] = make(sumcheck.NativeMultilinear, nbInstances)
			}
		}
		for _, input := range w.Inputs {
			if a[w][wireKey(input)] == nil {
				a[w][wireKey(input)] = make(sumcheck.NativeMultilinear, nbInstances)
			}
		}
	}

	parallel.Execute(nbInstances, func(start, end int) {
		ins := make([]*big.Int, maxNbIns)
		sewWireOutputs := make([][]*big.Int, nbInstances) // assuming inputs outputs same
		for i := start; i < end; i++ {
			sewWireOutputs[i] = make([]*big.Int, len(sortedWires[0].Inputs))
			for _, w := range sortedWires {
				if !w.IsInput() {
					for inI, in := range w.Inputs {
						a[w][wireKey(in)][i] = sewWireOutputs[i][inI]
					}
				}
				for inI, in := range w.Inputs {
					ins[inI] = a[w][wireKey(in)][i]
				}
				if !w.IsOutput() {
					res := w.Gate.Evaluate(engine, ins[:len(w.Inputs)]...)
					for outputI, output := range w.Outputs {
						a[w][wireKey(output)][i] = res[outputI]
						sewWireOutputs[i][outputI] = a[w][wireKey(output)][i]
					}
				}
			}
		}
	})
	return a
}

func (a WireAssignment) NumInstances() int {
	for _, aW := range a {
		if aW != nil {
			return len(aW)
		}
	}
	panic("empty assignment")
}

func (a WireAssignment) NumVars() int {
	for _, aW := range a {
		if aW != nil {
			return aW.NumVars()
		}
	}
	panic("empty assignment")
}

func (a WireAssignmentBundle) NumInstances() int {
	for _, aWBundle := range a {
		for _, aW := range aWBundle {
			if aW != nil {
				return len(aW)
			}
		}
	}
	panic("empty assignment")
}

func (a WireAssignmentBundle) NumVars() int {
	for _, aW := range a {
		if aW != nil {
			return aW.NumVars()
		}
	}
	panic("empty assignment")
}

//todo complete this for wirebundle
func topologicalSortBundleEmulated[FR emulated.FieldParams](c CircuitBundleEmulated[FR]) []*WireBundleEmulated[FR] {
	// var data topSortDataEmulated[FR]
	// data.index = indexMapEmulated(c)
	// data.outputs = outputsListEmulated(c, data.index)
	// data.status = statusListEmulated(c)
	// sorted := make([]*WireBundleEmulated[FR], len(c))

	// for data.leastReady = 0; data.status[data.leastReady] != 0; data.leastReady++ {
	// }

	// for i := range c {
	// 	sorted[i] = &c[data.leastReady]
	// 	data.markDone(data.leastReady)
	// }

	sorted := make([]*WireBundleEmulated[FR], len(c))
	for i := range c {
		sorted[i] = &c[i]
	}
	return sorted
}

func (a WireAssignmentEmulated[FR]) NumInstances() int {
	for _, aW := range a {
		if aW != nil {
			return len(aW)
		}
	}
	panic("empty assignment")
}

func (a WireAssignmentEmulated[FR]) NumVars() int {
	for _, aW := range a {
		if aW != nil {
			return aW.NumVars()
		}
	}
	panic("empty assignment")
}

func (a WireAssignmentBundleEmulated[FR]) NumInstances() int {
	for _, aWBundle := range a {
		for _, aW := range aWBundle {
			if aW != nil {
				return len(aW)
			}
		}
	}
	panic("empty assignment")
}

func (a WireAssignmentBundleEmulated[FR]) NumVars() int {
	for _, aW := range a {
		if aW != nil {
			return aW.NumVars()
		}
	}
	panic("empty assignment")
}

func (p Proofs[FR]) Serialize() []emulated.Element[FR] {
	size := 0
	for i := range p {
		for j := range p[i].RoundPolyEvaluations {
			size += len(p[i].RoundPolyEvaluations[j])
		}
		switch v := p[i].FinalEvalProof.(type) {
		case sumcheck.DeferredEvalProof[FR]:
			size += len(v)
		}
	}

	res := make([]emulated.Element[FR], 0, size)
	for i := range p {
		for j := range p[i].RoundPolyEvaluations {
			res = append(res, p[i].RoundPolyEvaluations[j]...)
		}
		switch v := p[i].FinalEvalProof.(type) {
		case sumcheck.DeferredEvalProof[FR]:
			res = append(res, v...)
		}
	}
	if len(res) != size {
		panic("bug") // TODO: Remove
	}
	return res
}

func computeLogNbInstancesBundle[FR emulated.FieldParams](wires []*WireBundleEmulated[FR], serializedProofLen int) int {
	partialEvalElemsPerVar := 0
	for _, w := range wires {
		if !w.noProof() {
			partialEvalElemsPerVar += w.Gate.Degree() + 1
			serializedProofLen -= 1 //w.nbUniqueOutputs
		} 
	}
	return serializedProofLen / partialEvalElemsPerVar
}

type variablesReader[FR emulated.FieldParams] []emulated.Element[FR]

func (r *variablesReader[FR]) nextN(n int) []emulated.Element[FR] {
	res := (*r)[:n]
	*r = (*r)[n:]
	return res
}

func (r *variablesReader[FR]) hasNextN(n int) bool {
	return len(*r) >= n
}

func DeserializeProofBundle[FR emulated.FieldParams](sorted []*WireBundleEmulated[FR], serializedProof []emulated.Element[FR]) (Proofs[FR], error) {
	proof := make(Proofs[FR], len(sorted))
	logNbInstances := computeLogNbInstancesBundle(sorted, len(serializedProof))

	reader := variablesReader[FR](serializedProof)
	for i, wI := range sorted {
		if !wI.noProof() {
			proof[i].RoundPolyEvaluations = make([]polynomial.Univariate[FR], logNbInstances)
			for j := range proof[i].RoundPolyEvaluations {
				proof[i].RoundPolyEvaluations[j] = reader.nextN(wI.Gate.Degree() + 1)
			}
			proof[i].FinalEvalProof = reader.nextN(wI.nbUniqueInputs())
		}

	}
	if reader.hasNextN(1) {
		return nil, fmt.Errorf("proof too long: expected %d encountered %d", len(serializedProof)-len(reader), len(serializedProof))
	}
	return proof, nil
}

type element any

type MulGate[AE sumcheck.ArithEngine[E], E element] struct{}

func (g MulGate[AE, E]) NbOutputs() int {
	return 1
}

func (g MulGate[AE, E]) Evaluate(api AE, x ...E) []E {
	if len(x) != 2 {
		panic("mul has fan-in 2")
	}
	return []E{api.Mul(x[0], x[1])}
}

// TODO: Degree must take nbInputs as an argument and return degree = nbInputs
func (g MulGate[AE, E]) Degree() int {
	return 2
}

func (g MulGate[AE, E]) NbInputs() int {
	return 2
}

func (g MulGate[AE, E]) GetName() string {
	return "mul"
}

type AddGate[AE sumcheck.ArithEngine[E], E element] struct{}

func (a AddGate[AE, E]) Evaluate(api AE, v ...E) []E {
	switch len(v) {
	case 0:
		return []E{api.Const(big.NewInt(0))}
	case 1:
		return []E{v[0]}
	}
	rest := v[2:]
	res := api.Add(v[0], v[1])
	for _, e := range rest {
		res = api.Add(res, e)
	}
	return []E{res}
}

func (a AddGate[AE, E]) Degree() int {
	return 1
}

func (a AddGate[AE, E]) NbInputs() int {
	return 2
}

func (a AddGate[AE, E]) NbOutputs() int {
	return 1
}

func (a AddGate[AE, E]) GetName() string {
	return "add"
}