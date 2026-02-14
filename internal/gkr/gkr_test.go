package gkr

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
	"github.com/consensys/gnark/internal/gkr/gkrtesting"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/polynomial"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
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
	if testCase, err = getTestCase(c.TestCaseName); err != nil {
		return err
	}

	if proof, err = DeserializeProof(testCase.Circuit, c.SerializedProof); err != nil {
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
	sorted := c.TopologicalSort()
	res := make(WireAssignment, len(c))
	inI, outI := 0, 0
	for wI, w := range sorted {
		if w.IsInput() {
			res[wI] = inputValues[inI]
			inI++
		} else if w.IsOutput() {
			res[wI] = outputValues[outI]
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

			_, cse.Circuit = cache.GetCircuit(filepath.Join(dir, info.Circuit))

			cse.Proof = unmarshalProof(info.Proof)

			cse.Input = toVariableSliceSlice(info.Input)
			cse.Output = toVariableSliceSlice(info.Output)
			cse.Hash = info.Hash
			cse.Name = path
			testCases[path] = cse
		} else {
			return nil, err
		}
	}

	return cse, nil
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
				finalEvalProof[k] = toVariable(finalEvalSlice.Index(k).Interface())
			}
			proof[i].FinalEvalProof = finalEvalProof
		} else {
			proof[i].FinalEvalProof = nil
		}

		proof[i].PartialSumPolys = make([]polynomial.Polynomial, len(printable[i].PartialSumPolys))
		for k := range printable[i].PartialSumPolys {
			proof[i].PartialSumPolys[k] = toVariableSlice(printable[i].PartialSumPolys[k])
		}
	}
	return
}

func TestLogNbInstances(t *testing.T) {
	testLogNbInstances := func(path string) func(t *testing.T) {
		return func(t *testing.T) {
			testCase, err := getTestCase(path)
			assert.NoError(t, err)
			serializedProof := testCase.Proof.Serialize()
			logNbInstances := ComputeLogNbInstances(testCase.Circuit, len(serializedProof))
			assert.Equal(t, 1, logNbInstances)
		}
	}

	cases := []string{"two_inputs_select-input-3_gate_two_instances", "two_identity_gates_composed_single_input_two_instances"}

	for _, caseName := range cases {
		t.Run("log_nb_instances:"+caseName, testLogNbInstances("test_vectors/"+caseName+".json"))
	}
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

var cache = gkrtesting.NewCache(ecc.BN254.ScalarField())
