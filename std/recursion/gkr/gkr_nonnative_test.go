package sumcheck

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/emulated"
	mathpoly "github.com/consensys/gnark/std/math/polynomial"
	"github.com/consensys/gnark/std/recursion"
	"github.com/consensys/gnark/std/recursion/sumcheck"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
)

type FR = emulated.BN254Fr

var Gates = map[string]GateEmulated[FR]{
	"identity": IdentityGate[*sumcheck.EmuEngine[FR], *emulated.Element[FR]]{},
	"add":      AddGate[*sumcheck.EmuEngine[FR], *emulated.Element[FR]]{},
	"mul":      MulGate[*sumcheck.EmuEngine[FR], *emulated.Element[FR]]{},
}

func TestGkrVectorsFr(t *testing.T) {

	testDirPath := "./test_vectors"
	dirEntries, err := os.ReadDir(testDirPath)
	if err != nil {
		t.Error(err)
	}
	for _, dirEntry := range dirEntries {
		if !dirEntry.IsDir() && filepath.Ext(dirEntry.Name()) == ".json" {
			path := filepath.Join(testDirPath, dirEntry.Name())
			noExt := dirEntry.Name()[:len(dirEntry.Name())-len(".json")]

			t.Run(noExt, generateTestVerifier(path))
		}
	}
}

type _options struct {
	noSuccess bool
	noFail    bool
}

type option func(*_options)

func noSuccess(o *_options) {
	o.noSuccess = true
}

func generateTestVerifier(path string, options ...option) func(t *testing.T) {
	var opts _options
	for _, opt := range options {
		opt(&opts)
	}

	return func(t *testing.T) {

		testCase, err := getTestCase(path)
		assert := test.NewAssert(t)
		assert.NoError(err)

		assignment := &GkrVerifierCircuitFr{
			Input:           testCase.Input,
			Output:          testCase.Output,
			SerializedProof: testCase.Proof.Serialize(),
			ToFail:          false,
			TestCaseName:    path,
		}

		validCircuit := &GkrVerifierCircuitFr{
			Input:           make([][]emulated.Element[FR], len(testCase.Input)),
			Output:          make([][]emulated.Element[FR], len(testCase.Output)),
			SerializedProof: make([]emulated.Element[FR], len(assignment.SerializedProof)),
			ToFail:          false,
			TestCaseName:    path,
		}

		p := profile.Start()
		frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, validCircuit)
		p.Stop()

		fmt.Println(p.NbConstraints())
		fmt.Println(p.Top())
		//r1cs.CheckUnconstrainedWires()

		invalidCircuit := &GkrVerifierCircuitFr{
			Input:           make([][]emulated.Element[FR], len(testCase.Input)),
			Output:          make([][]emulated.Element[FR], len(testCase.Output)),
			SerializedProof: make([]emulated.Element[FR], len(assignment.SerializedProof)),
			ToFail:          true,
			TestCaseName:    path,
		}

		fillWithBlanks(validCircuit.Input, len(testCase.Input[0]))
		fillWithBlanks(validCircuit.Output, len(testCase.Input[0]))
		fillWithBlanks(invalidCircuit.Input, len(testCase.Input[0]))
		fillWithBlanks(invalidCircuit.Output, len(testCase.Input[0]))

		if !opts.noSuccess {
			assert.CheckCircuit(validCircuit, test.WithBackends(backend.GROTH16), test.WithValidAssignment(assignment))
		}

		if !opts.noFail {
			assert.CheckCircuit(invalidCircuit, test.WithBackends(backend.GROTH16), test.WithInvalidAssignment(assignment))
		}
	}
}

type GkrVerifierCircuitFr struct {
	Input           [][]emulated.Element[FR]
	Output          [][]emulated.Element[FR] `gnark:",public"`
	SerializedProof []emulated.Element[FR]
	ToFail          bool
	TestCaseName    string
}

func (c *GkrVerifierCircuitFr) Define(api frontend.API) error {
	var fr FR
	var testCase *TestCase[FR]
	var proof Proofs[FR]
	var err error

	v, err := NewGKRVerifier[FR](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}

	//var proofRef Proof
	if testCase, err = getTestCase(c.TestCaseName); err != nil {
		return err
	}
	sorted := topologicalSortEmulated(testCase.Circuit)

	if proof, err = DeserializeProof(sorted, c.SerializedProof); err != nil {
		return err
	}
	assignment := makeInOutAssignment(testCase.Circuit, c.Input, c.Output)

	// initiating hash in bitmode, remove and do it with hashdescription instead
	h, err := recursion.NewHash(api, fr.Modulus(), true)
	if err != nil {
		return err
	}
	// var hsh hash.FieldHasher
	// if c.ToFail {
	// 	hsh = NewMessageCounter(api, 1, 1)
	// } else {
	// 	if hsh, err = HashFromDescription(api, testCase.Hash); err != nil {
	// 		return err
	// 	}
	// }

	return v.Verify(api, testCase.Circuit, assignment, proof, fiatshamir.WithHashFr[FR](h))
}

func makeInOutAssignment[FR emulated.FieldParams](c CircuitEmulated[FR], inputValues [][]emulated.Element[FR], outputValues [][]emulated.Element[FR]) WireAssignmentEmulated[FR] {
	sorted := topologicalSortEmulated(c)
	res := make(WireAssignmentEmulated[FR], len(inputValues)+len(outputValues))
	inI, outI := 0, 0
	for _, w := range sorted {
		if w.IsInput() {
			res[w] = inputValues[inI]
			inI++
		} else if w.IsOutput() {
			res[w] = outputValues[outI]
			outI++
		}
	}
	return res
}

func fillWithBlanks[FR emulated.FieldParams](slice [][]emulated.Element[FR], size int) {
	for i := range slice {
		slice[i] = make([]emulated.Element[FR], size)
	}
}

type TestCase[FR emulated.FieldParams] struct {
	Circuit CircuitEmulated[FR]
	Hash    HashDescription
	Proof   Proofs[FR]
	Input   [][]emulated.Element[FR]
	Output  [][]emulated.Element[FR]
	Name    string
}
type TestCaseInfo struct {
	Hash    HashDescription `json:"hash"`
	Circuit string          `json:"circuit"`
	Input   [][]interface{} `json:"input"`
	Output  [][]interface{} `json:"output"`
	Proof   PrintableProof  `json:"proof"`
}

// var testCases = make(map[string]*TestCase[emulated.FieldParams])
var testCases = make(map[string]interface{})

func getTestCase(path string) (*TestCase[FR], error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)

	cse, ok := testCases[path].(*TestCase[FR])
	if !ok {
		var bytes []byte
		cse = &TestCase[FR]{}
		if bytes, err = os.ReadFile(path); err == nil {
			var info TestCaseInfo
			err = json.Unmarshal(bytes, &info)
			if err != nil {
				return nil, err
			}

			if cse.Circuit, err = getCircuit(filepath.Join(dir, info.Circuit)); err != nil {
				return nil, err
			}

			cse.Proof = unmarshalProof(info.Proof)

			cse.Input = ToVariableSliceSliceFr[FR](info.Input)
			cse.Output = ToVariableSliceSliceFr[FR](info.Output)
			cse.Hash = info.Hash
			cse.Name = path
			testCases[path] = cse
		} else {
			return nil, err
		}
	}

	return cse, nil
}

type WireInfo struct {
	Gate   string `json:"gate"`
	Inputs []int  `json:"inputs"`
}

type CircuitInfo []WireInfo

// var circuitCache = make(map[string]CircuitFr[emulated.FieldParams])
var circuitCache = make(map[string]interface{})

func getCircuit(path string) (circuit CircuitEmulated[FR], err error) {
	path, err = filepath.Abs(path)
	if err != nil {
		return
	}
	var ok bool
	if circuit, ok = circuitCache[path].(CircuitEmulated[FR]); ok {
		return
	}
	var bytes []byte
	if bytes, err = os.ReadFile(path); err == nil {
		var circuitInfo CircuitInfo
		if err = json.Unmarshal(bytes, &circuitInfo); err == nil {
			circuit, err = toCircuitFr(circuitInfo)
			if err == nil {
				circuitCache[path] = circuit
			}
		}
	}
	return
}

func toCircuitFr(c CircuitInfo) (circuit CircuitEmulated[FR], err error) {
	circuit = make(CircuitEmulated[FR], len(c))
	for i, wireInfo := range c {
		circuit[i].Inputs = make([]*WireEmulated[FR], len(wireInfo.Inputs))
		for iAsInput, iAsWire := range wireInfo.Inputs {
			input := &circuit[iAsWire]
			circuit[i].Inputs[iAsInput] = input
		}

		var found bool
		if circuit[i].Gate, found = Gates[wireInfo.Gate]; !found && wireInfo.Gate != "" {
			err = fmt.Errorf("undefined gate \"%s\"", wireInfo.Gate)
		}
	}

	return
}

type _select int

func init() {
	Gates["select-input-3"] = _select(2)
}

func (g _select) Evaluate(_ *sumcheck.EmuEngine[FR], in ...*emulated.Element[FR]) *emulated.Element[FR] {
	return in[g]
}

func (g _select) Degree() int {
	return 1
}

type PrintableProof []PrintableSumcheckProof

type PrintableSumcheckProof struct {
	FinalEvalProof       interface{}     `json:"finalEvalProof"`
	RoundPolyEvaluations [][]interface{} `json:"partialSumPolys"`
}

func unmarshalProof(printable PrintableProof) (proof Proofs[FR]) {

	proof = make(Proofs[FR], len(printable))
	for i := range printable {

		if printable[i].FinalEvalProof != nil {
			finalEvalSlice := reflect.ValueOf(printable[i].FinalEvalProof)
			finalEvalProof := make(sumcheck.DeferredEvalProof[FR], finalEvalSlice.Len())
			for k := range finalEvalProof {
				finalEvalProof[k] = ToVariableFr[FR](finalEvalSlice.Index(k).Interface())
			}
			proof[i].FinalEvalProof = finalEvalProof
		} else {
			proof[i].FinalEvalProof = nil
		}

		proof[i].RoundPolyEvaluations = make([]mathpoly.Univariate[FR], len(printable[i].RoundPolyEvaluations))
		for k := range printable[i].RoundPolyEvaluations {
			proof[i].RoundPolyEvaluations[k] = ToVariableSliceFr[FR](printable[i].RoundPolyEvaluations[k])
		}
	}
	return
}

func TestLogNbInstances(t *testing.T) {

	testLogNbInstances := func(path string) func(t *testing.T) {
		return func(t *testing.T) {
			testCase, err := getTestCase(path)
			assert.NoError(t, err)
			wires := topologicalSortEmulated(testCase.Circuit)
			serializedProof := testCase.Proof.Serialize()
			logNbInstances := computeLogNbInstances(wires, len(serializedProof))
			assert.Equal(t, 1, logNbInstances)
		}
	}

	cases := []string{"two_inputs_select-input-3_gate_two_instances", "two_identity_gates_composed_single_input_two_instances"}

	for _, caseName := range cases {
		t.Run("log_nb_instances:"+caseName, testLogNbInstances("test_vectors/"+caseName+".json"))
	}
}

func TestLoadCircuit(t *testing.T) {
	c, err := getCircuit("test_vectors/resources/two_identity_gates_composed_single_input.json")
	assert.NoError(t, err)
	assert.Equal(t, []*WireEmulated[FR]{}, c[0].Inputs)
	assert.Equal(t, []*WireEmulated[FR]{&c[0]}, c[1].Inputs)
	assert.Equal(t, []*WireEmulated[FR]{&c[1]}, c[2].Inputs)
}

func TestTopSortTrivial(t *testing.T) {
	c := make(CircuitEmulated[FR], 2)
	c[0].Inputs = []*WireEmulated[FR]{&c[1]}
	sorted := topologicalSortEmulated(c)
	assert.Equal(t, []*WireEmulated[FR]{&c[1], &c[0]}, sorted)
}

func TestTopSortSingleGate(t *testing.T) {
	c := make(CircuitEmulated[FR], 3)
	c[0].Inputs = []*WireEmulated[FR]{&c[1], &c[2]}
	sorted := topologicalSortEmulated(c)
	expected := []*WireEmulated[FR]{&c[1], &c[2], &c[0]}
	assert.True(t, SliceEqual(sorted, expected)) //TODO: Remove
	AssertSliceEqual(t, sorted, expected)
	assert.Equal(t, c[0].nbUniqueOutputs, 0)
	assert.Equal(t, c[1].nbUniqueOutputs, 1)
	assert.Equal(t, c[2].nbUniqueOutputs, 1)
}

func TestTopSortDeep(t *testing.T) {
	c := make(CircuitEmulated[FR], 4)
	c[0].Inputs = []*WireEmulated[FR]{&c[2]}
	c[1].Inputs = []*WireEmulated[FR]{&c[3]}
	c[2].Inputs = []*WireEmulated[FR]{}
	c[3].Inputs = []*WireEmulated[FR]{&c[0]}
	sorted := topologicalSortEmulated(c)
	assert.Equal(t, []*WireEmulated[FR]{&c[2], &c[0], &c[3], &c[1]}, sorted)
}

func TestTopSortWide(t *testing.T) {
	c := make(CircuitEmulated[FR], 10)
	c[0].Inputs = []*WireEmulated[FR]{&c[3], &c[8]}
	c[1].Inputs = []*WireEmulated[FR]{&c[6]}
	c[2].Inputs = []*WireEmulated[FR]{&c[4]}
	c[3].Inputs = []*WireEmulated[FR]{}
	c[4].Inputs = []*WireEmulated[FR]{}
	c[5].Inputs = []*WireEmulated[FR]{&c[9]}
	c[6].Inputs = []*WireEmulated[FR]{&c[9]}
	c[7].Inputs = []*WireEmulated[FR]{&c[9], &c[5], &c[2]}
	c[8].Inputs = []*WireEmulated[FR]{&c[4], &c[3]}
	c[9].Inputs = []*WireEmulated[FR]{}

	sorted := topologicalSortEmulated(c)
	sortedExpected := []*WireEmulated[FR]{&c[3], &c[4], &c[2], &c[8], &c[0], &c[9], &c[5], &c[6], &c[1], &c[7]}

	assert.Equal(t, sortedExpected, sorted)
}

func ToVariableFr[FR emulated.FieldParams](v interface{}) emulated.Element[FR] {
	switch vT := v.(type) {
	case float64:
		return *new(emulated.Field[FR]).NewElement(int(vT))
	default:
		return *new(emulated.Field[FR]).NewElement(v)
	}
}

func ToVariableSliceFr[FR emulated.FieldParams, V any](slice []V) (variableSlice []emulated.Element[FR]) {
	variableSlice = make([]emulated.Element[FR], len(slice))
	for i := range slice {
		variableSlice[i] = ToVariableFr[FR](slice[i])
	}
	return
}

func ToVariableSliceSliceFr[FR emulated.FieldParams, V any](sliceSlice [][]V) (variableSliceSlice [][]emulated.Element[FR]) {
	variableSliceSlice = make([][]emulated.Element[FR], len(sliceSlice))
	for i := range sliceSlice {
		variableSliceSlice[i] = ToVariableSliceFr[FR](sliceSlice[i])
	}
	return
}

func AssertSliceEqual[T comparable](t *testing.T, expected, seen []T) {
	assert.Equal(t, len(expected), len(seen))
	for i := range seen {
		assert.True(t, expected[i] == seen[i], "@%d: %v != %v", i, expected[i], seen[i]) // assert.Equal is not strict enough when comparing pointers, i.e. it compares what they refer to
	}
}

func SliceEqual[T comparable](expected, seen []T) bool {
	if len(expected) != len(seen) {
		return false
	}
	for i := range seen {
		if expected[i] != seen[i] {
			return false
		}
	}
	return true
}

type HashDescription map[string]interface{}

func HashFromDescription(api frontend.API, d HashDescription) (hash.FieldHasher, error) {
	if _type, ok := d["type"]; ok {
		switch _type {
		case "const":
			startState := int64(d["val"].(float64))
			return &MessageCounter{startState: startState, step: 0, state: startState, api: api}, nil
		default:
			return nil, fmt.Errorf("unknown fake hash type \"%s\"", _type)
		}
	}
	return nil, fmt.Errorf("hash description missing type")
}

type MessageCounter struct {
	startState int64
	state      int64
	step       int64

	// cheap trick to avoid unconstrained input errors
	api  frontend.API
	zero frontend.Variable
}

func (m *MessageCounter) Write(data ...frontend.Variable) {

	for i := range data {
		sq1, sq2 := m.api.Mul(data[i], data[i]), m.api.Mul(data[i], data[i])
		m.zero = m.api.Sub(sq1, sq2, m.zero)
	}

	m.state += int64(len(data)) * m.step
}

func (m *MessageCounter) Sum() frontend.Variable {
	return m.api.Add(m.state, m.zero)
}

func (m *MessageCounter) Reset() {
	m.zero = 0
	m.state = m.startState
}

func NewMessageCounter(api frontend.API, startState, step int) hash.FieldHasher {
	transcript := &MessageCounter{startState: int64(startState), state: int64(startState), step: int64(step), api: api}
	return transcript
}

func NewMessageCounterGenerator(startState, step int) func(frontend.API) hash.FieldHasher {
	return func(api frontend.API) hash.FieldHasher {
		return NewMessageCounter(api, startState, step)
	}
}

type constHashCircuit struct {
	X frontend.Variable
}

func (c *constHashCircuit) Define(api frontend.API) error {
	hsh := NewMessageCounter(api, 0, 0)
	hsh.Reset()
	hsh.Write(c.X)
	sum := hsh.Sum()
	api.AssertIsEqual(sum, 0)
	api.AssertIsEqual(api.Mul(c.X, c.X), 1) // ensure we have at least 2 constraints
	return nil
}

func TestConstHash(t *testing.T) {
	test.NewAssert(t).CheckCircuit(
		&constHashCircuit{},

		test.WithValidAssignment(&constHashCircuit{X: 1}),
	)
}

var mimcSnarkTotalCalls = 0

type MiMCCipherGate struct {
	Ark frontend.Variable
}

func (m MiMCCipherGate) Evaluate(api frontend.API, input ...frontend.Variable) frontend.Variable {
	mimcSnarkTotalCalls++

	if len(input) != 2 {
		panic("mimc has fan-in 2")
	}
	sum := api.Add(input[0], input[1], m.Ark)

	sumCubed := api.Mul(sum, sum, sum) // sum^3
	return api.Mul(sumCubed, sumCubed, sum)
}

func (m MiMCCipherGate) Degree() int {
	return 7
}

// type PrintableProof []PrintableSumcheckProof

// type PrintableSumcheckProof struct {
// 	FinalEvalProof  interface{}     `json:"finalEvalProof"`
// 	PartialSumPolys [][]interface{} `json:"partialSumPolys"`
// }

// func unmarshalProof(printable PrintableProof) (Proof, error) {
// 	proof := make(Proof, len(printable))
// 	for i := range printable {
// 		finalEvalProof := []fr.Element(nil)

// 		if printable[i].FinalEvalProof != nil {
// 			finalEvalSlice := reflect.ValueOf(printable[i].FinalEvalProof)
// 			finalEvalProof = make([]fr.Element, finalEvalSlice.Len())
// 			for k := range finalEvalProof {
// 				if _, err := test_vector_utils.SetElement(&finalEvalProof[k], finalEvalSlice.Index(k).Interface()); err != nil {
// 					return nil, err
// 				}
// 			}
// 		}

// 		proof[i] = sumcheck.Proof{
// 			PartialSumPolys: make([]polynomial.Polynomial, len(printable[i].PartialSumPolys)),
// 			FinalEvalProof:  finalEvalProof,
// 		}
// 		for k := range printable[i].PartialSumPolys {
// 			var err error
// 			if proof[i].PartialSumPolys[k], err = test_vector_utils.SliceToElementSlice(printable[i].PartialSumPolys[k]); err != nil {
// 				return nil, err
// 			}
// 		}
// 	}
// 	return proof, nil
// }

// type TestCase struct {
// 	Circuit         Circuit
// 	Hash            hash.Hash
// 	Proof           Proof
// 	FullAssignment  WireAssignment
// 	InOutAssignment WireAssignment
// }

// type TestCaseInfo struct {
// 	Hash    test_vector_utils.HashDescription `json:"hash"`
// 	Circuit string                            `json:"circuit"`
// 	Input   [][]interface{}                   `json:"input"`
// 	Output  [][]interface{}                   `json:"output"`
// 	Proof   PrintableProof                    `json:"proof"`
// }

// var testCases = make(map[string]*TestCase)

// func newTestCase(path string) (*TestCase, error) {
// 	path, err := filepath.Abs(path)
// 	if err != nil {
// 		return nil, err
// 	}
// 	dir := filepath.Dir(path)

// 	tCase, ok := testCases[path]
// 	if !ok {
// 		var bytes []byte
// 		if bytes, err = os.ReadFile(path); err == nil {
// 			var info TestCaseInfo
// 			err = json.Unmarshal(bytes, &info)
// 			if err != nil {
// 				return nil, err
// 			}

// 			var circuit Circuit
// 			if circuit, err = getCircuit(filepath.Join(dir, info.Circuit)); err != nil {
// 				return nil, err
// 			}
// 			var _hash hash.Hash
// 			if _hash, err = test_vector_utils.HashFromDescription(info.Hash); err != nil {
// 				return nil, err
// 			}
// 			var proof Proof
// 			if proof, err = unmarshalProof(info.Proof); err != nil {
// 				return nil, err
// 			}

// 			fullAssignment := make(WireAssignment)
// 			inOutAssignment := make(WireAssignment)

// 			sorted := topologicalSort(circuit)

// 			inI, outI := 0, 0
// 			for _, w := range sorted {
// 				var assignmentRaw []interface{}
// 				if w.IsInput() {
// 					if inI == len(info.Input) {
// 						return nil, fmt.Errorf("fewer input in vector than in circuit")
// 					}
// 					assignmentRaw = info.Input[inI]
// 					inI++
// 				} else if w.IsOutput() {
// 					if outI == len(info.Output) {
// 						return nil, fmt.Errorf("fewer output in vector than in circuit")
// 					}
// 					assignmentRaw = info.Output[outI]
// 					outI++
// 				}
// 				if assignmentRaw != nil {
// 					var wireAssignment []fr.Element
// 					if wireAssignment, err = test_vector_utils.SliceToElementSlice(assignmentRaw); err != nil {
// 						return nil, err
// 					}

// 					fullAssignment[w] = wireAssignment
// 					inOutAssignment[w] = wireAssignment
// 				}
// 			}

// 			fullAssignment.Complete(circuit)

// 			for _, w := range sorted {
// 				if w.IsOutput() {

// 					if err = test_vector_utils.SliceEquals(inOutAssignment[w], fullAssignment[w]); err != nil {
// 						return nil, fmt.Errorf("assignment mismatch: %v", err)
// 					}

// 				}
// 			}

// 			tCase = &TestCase{
// 				FullAssignment:  fullAssignment,
// 				InOutAssignment: inOutAssignment,
// 				Proof:           proof,
// 				Hash:            _hash,
// 				Circuit:         circuit,
// 			}

// 			testCases[path] = tCase
// 		} else {
// 			return nil, err
// 		}
// 	}

// 	return tCase, nil
// }

// type _select int

// func (g _select) Evaluate(in ...fr.Element) fr.Element {
// 	return in[g]
// }

// func (g _select) Degree() int {
// 	return 1
// }
