package gkr

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/polynomial"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"

	"github.com/consensys/gnark/std/hash"
)

func TestGkrVectors(t *testing.T) {

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

		assignment := &GkrVerifierCircuit{
			Input:           testCase.Input,
			Output:          testCase.Output,
			SerializedProof: testCase.Proof.Serialize(),
			ToFail:          false,
			TestCaseName:    path,
		}

		validCircuit := &GkrVerifierCircuit{
			Input:           make([][]frontend.Variable, len(testCase.Input)),
			Output:          make([][]frontend.Variable, len(testCase.Output)),
			SerializedProof: make([]frontend.Variable, len(assignment.SerializedProof)),
			ToFail:          false,
			TestCaseName:    path,
		}

		invalidCircuit := &GkrVerifierCircuit{
			Input:           make([][]frontend.Variable, len(testCase.Input)),
			Output:          make([][]frontend.Variable, len(testCase.Output)),
			SerializedProof: make([]frontend.Variable, len(assignment.SerializedProof)),
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

type GkrVerifierCircuit struct {
	Input           [][]frontend.Variable
	Output          [][]frontend.Variable `gnark:",public"`
	SerializedProof []frontend.Variable
	ToFail          bool
	TestCaseName    string
}

func (c *GkrVerifierCircuit) Define(api frontend.API) error {
	var testCase *TestCase
	var proof Proof
	var err error
	//var proofRef Proof
	if testCase, err = getTestCase(c.TestCaseName); err != nil {
		return err
	}
	sorted := topologicalSort(testCase.Circuit)

	if proof, err = DeserializeProof(sorted, c.SerializedProof); err != nil {
		return err
	}
	assignment := makeInOutAssignment(testCase.Circuit, c.Input, c.Output)

	var hsh hash.FieldHasher
	if c.ToFail {
		hsh = NewMessageCounter(api, 1, 1)
	} else {
		if hsh, err = HashFromDescription(api, testCase.Hash); err != nil {
			return err
		}
	}

	return Verify(api, testCase.Circuit, assignment, proof, fiatshamir.WithHash(hsh))
}

func makeInOutAssignment(c Circuit, inputValues [][]frontend.Variable, outputValues [][]frontend.Variable) WireAssignment {
	sorted := topologicalSort(c)
	res := make(WireAssignment, len(inputValues)+len(outputValues))
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

func fillWithBlanks(slice [][]frontend.Variable, size int) {
	for i := range slice {
		slice[i] = make([]frontend.Variable, size)
	}
}

type TestCase struct {
	Circuit Circuit
	Hash    HashDescription
	Proof   Proof
	Input   [][]frontend.Variable
	Output  [][]frontend.Variable
	Name    string
}
type TestCaseInfo struct {
	Hash    HashDescription `json:"hash"`
	Circuit string          `json:"circuit"`
	Input   [][]interface{} `json:"input"`
	Output  [][]interface{} `json:"output"`
	Proof   PrintableProof  `json:"proof"`
}

var testCases = make(map[string]*TestCase)

func getTestCase(path string) (*TestCase, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)

	cse, ok := testCases[path]
	if !ok {
		var bytes []byte
		cse = &TestCase{}
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

			cse.Input = ToVariableSliceSlice(info.Input)
			cse.Output = ToVariableSliceSlice(info.Output)
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

var circuitCache = make(map[string]Circuit)

func getCircuit(path string) (circuit Circuit, err error) {
	path, err = filepath.Abs(path)
	if err != nil {
		return
	}
	var ok bool
	if circuit, ok = circuitCache[path]; ok {
		return
	}
	var bytes []byte
	if bytes, err = os.ReadFile(path); err == nil {
		var circuitInfo CircuitInfo
		if err = json.Unmarshal(bytes, &circuitInfo); err == nil {
			circuit, err = circuitInfo.toCircuit()
			if err == nil {
				circuitCache[path] = circuit
			}
		}
	}
	return
}

func (c CircuitInfo) toCircuit() (circuit Circuit, err error) {
	circuit = make(Circuit, len(c))
	for i, wireInfo := range c {
		circuit[i].Inputs = make([]*Wire, len(wireInfo.Inputs))
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

func (g _select) Evaluate(_ frontend.API, in ...frontend.Variable) frontend.Variable {
	return in[g]
}

func (g _select) Degree() int {
	return 1
}

type PrintableProof []PrintableSumcheckProof

type PrintableSumcheckProof struct {
	FinalEvalProof  interface{}     `json:"finalEvalProof"`
	PartialSumPolys [][]interface{} `json:"partialSumPolys"`
}

func unmarshalProof(printable PrintableProof) (proof Proof) {
	proof = make(Proof, len(printable))
	for i := range printable {

		if printable[i].FinalEvalProof != nil {
			finalEvalSlice := reflect.ValueOf(printable[i].FinalEvalProof)
			finalEvalProof := make([]frontend.Variable, finalEvalSlice.Len())
			for k := range finalEvalProof {
				finalEvalProof[k] = ToVariable(finalEvalSlice.Index(k).Interface())
			}
			proof[i].FinalEvalProof = finalEvalProof
		} else {
			proof[i].FinalEvalProof = nil
		}

		proof[i].PartialSumPolys = make([]polynomial.Polynomial, len(printable[i].PartialSumPolys))
		for k := range printable[i].PartialSumPolys {
			proof[i].PartialSumPolys[k] = ToVariableSlice(printable[i].PartialSumPolys[k])
		}
	}
	return
}

func TestLogNbInstances(t *testing.T) {
	testLogNbInstances := func(path string) func(t *testing.T) {
		return func(t *testing.T) {
			testCase, err := getTestCase(path)
			assert.NoError(t, err)
			wires := topologicalSort(testCase.Circuit)
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
	assert.Equal(t, []*Wire{}, c[0].Inputs)
	assert.Equal(t, []*Wire{&c[0]}, c[1].Inputs)
	assert.Equal(t, []*Wire{&c[1]}, c[2].Inputs)

}

func TestTopSortTrivial(t *testing.T) {
	c := make(Circuit, 2)
	c[0].Inputs = []*Wire{&c[1]}
	sorted := topologicalSort(c)
	assert.Equal(t, []*Wire{&c[1], &c[0]}, sorted)
}

func TestTopSortSingleGate(t *testing.T) {
	c := make(Circuit, 3)
	c[0].Inputs = []*Wire{&c[1], &c[2]}
	sorted := topologicalSort(c)
	expected := []*Wire{&c[1], &c[2], &c[0]}
	assert.True(t, SliceEqual(sorted, expected)) //TODO: Remove
	AssertSliceEqual(t, sorted, expected)
	assert.Equal(t, c[0].nbUniqueOutputs, 0)
	assert.Equal(t, c[1].nbUniqueOutputs, 1)
	assert.Equal(t, c[2].nbUniqueOutputs, 1)
}

func TestTopSortDeep(t *testing.T) {
	c := make(Circuit, 4)
	c[0].Inputs = []*Wire{&c[2]}
	c[1].Inputs = []*Wire{&c[3]}
	c[2].Inputs = []*Wire{}
	c[3].Inputs = []*Wire{&c[0]}
	sorted := topologicalSort(c)
	assert.Equal(t, []*Wire{&c[2], &c[0], &c[3], &c[1]}, sorted)
}

func TestTopSortWide(t *testing.T) {
	c := make(Circuit, 10)
	c[0].Inputs = []*Wire{&c[3], &c[8]}
	c[1].Inputs = []*Wire{&c[6]}
	c[2].Inputs = []*Wire{&c[4]}
	c[3].Inputs = []*Wire{}
	c[4].Inputs = []*Wire{}
	c[5].Inputs = []*Wire{&c[9]}
	c[6].Inputs = []*Wire{&c[9]}
	c[7].Inputs = []*Wire{&c[9], &c[5], &c[2]}
	c[8].Inputs = []*Wire{&c[4], &c[3]}
	c[9].Inputs = []*Wire{}

	sorted := topologicalSort(c)
	sortedExpected := []*Wire{&c[3], &c[4], &c[2], &c[8], &c[0], &c[9], &c[5], &c[6], &c[1], &c[7]}

	assert.Equal(t, sortedExpected, sorted)
}

func ToVariable(v interface{}) frontend.Variable {
	switch vT := v.(type) {
	case float64:
		return int(vT)
	default:
		return v
	}
}

func ToVariableSlice[V any](slice []V) (variableSlice []frontend.Variable) {
	variableSlice = make([]frontend.Variable, len(slice))
	for i := range slice {
		variableSlice[i] = ToVariable(slice[i])
	}
	return
}

func ToVariableSliceSlice[V any](sliceSlice [][]V) (variableSliceSlice [][]frontend.Variable) {
	variableSliceSlice = make([][]frontend.Variable, len(sliceSlice))
	for i := range sliceSlice {
		variableSliceSlice[i] = ToVariableSlice(sliceSlice[i])
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
