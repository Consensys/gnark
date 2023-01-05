package gkr

import (
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/polynomial"
	"github.com/consensys/gnark/std/test_vector_utils"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"reflect"
	"testing"
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
		assert.NoError(t, err)

		assignment := &GkrVerifierCircuit{
			Input:           testCase.Input,
			Output:          testCase.Output,
			SerializedProof: testCase.Proof.Serialize(),
			PerturbHash:     false,
			TestCaseName:    path,
		}

		circuit := &GkrVerifierCircuit{
			Input:           make([][]frontend.Variable, len(testCase.Input)),
			Output:          make([][]frontend.Variable, len(testCase.Output)),
			SerializedProof: make([]frontend.Variable, len(assignment.SerializedProof)),
			PerturbHash:     false,
			TestCaseName:    path,
		}

		fillWithBlanks(circuit.Input, len(testCase.Input[0]))
		fillWithBlanks(circuit.Output, len(testCase.Input[0]))

		if !opts.noSuccess {
			test.NewAssert(t).SolvingSucceeded(circuit, assignment, test.WithBackends(backend.GROTH16))
		}

		if !opts.noFail {
			assignment.PerturbHash = true // TODO: This one doesn't matter right?
			circuit.PerturbHash = true
			test.NewAssert(t).SolvingFailed(circuit, assignment, test.WithBackends(backend.GROTH16))
		}
	}
}

type GkrVerifierCircuit struct {
	Input           [][]frontend.Variable
	Output          [][]frontend.Variable `gnark:",public"`
	SerializedProof []frontend.Variable
	PerturbHash     bool
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

	var baseChallenge []frontend.Variable
	if c.PerturbHash {
		baseChallenge = []frontend.Variable{1}
	}

	return Verify(api, testCase.Circuit, assignment, proof, fiatshamir.WithHash(&test_vector_utils.MapHash{Map: testCase.ElementMap, API: api}, baseChallenge...))
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
	Circuit    Circuit
	ElementMap test_vector_utils.ElementMap
	Proof      Proof
	Input      [][]frontend.Variable
	Output     [][]frontend.Variable
	Name       string
}
type TestCaseInfo struct {
	Hash    string          `json:"hash"`
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

			if cse.ElementMap, err = test_vector_utils.ElementMapFromFile(filepath.Join(dir, info.Hash)); err != nil {
				return nil, err
			}

			cse.Proof = unmarshalProof(info.Proof)

			cse.Input = test_vector_utils.ToVariableSliceSlice(info.Input)
			cse.Output = test_vector_utils.ToVariableSliceSlice(info.Output)

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
		if circuit[i].Gate, found = gates[wireInfo.Gate]; !found && wireInfo.Gate != "" {
			err = fmt.Errorf("undefined gate \"%s\"", wireInfo.Gate)
		}
	}

	return
}

var gates map[string]Gate

func init() {
	gates = make(map[string]Gate)
	gates["identity"] = IdentityGate{}
	gates["mul"] = MulGate{}
	gates["mimc"] = mimcCipherGate{ark: 0} //TODO: Add ark
	gates["select-input-3"] = _select(2)
}

type mimcCipherGate struct {
	ark frontend.Variable
}

func (m mimcCipherGate) Evaluate(api frontend.API, input ...frontend.Variable) frontend.Variable {
	if len(input) != 2 {
		panic("mimc has fan-in 2")
	}
	sum := api.Add(input[0], input[1], m.ark)

	sumCubed := api.Mul(sum, sum, sum) // sum^3
	return api.Mul(sumCubed, sumCubed, sum)
}

func (m mimcCipherGate) Degree() int {
	return 7
}

type _select int

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
				finalEvalProof[k] = test_vector_utils.ToVariable(finalEvalSlice.Index(k).Interface())
			}
			proof[i].FinalEvalProof = finalEvalProof
		} else {
			proof[i].FinalEvalProof = nil
		}

		proof[i].PartialSumPolys = make([]polynomial.Polynomial, len(printable[i].PartialSumPolys))
		for k := range printable[i].PartialSumPolys {
			proof[i].PartialSumPolys[k] = test_vector_utils.ToVariableSlice(printable[i].PartialSumPolys[k])
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
	assert.True(t, test_vector_utils.SliceEqual(sorted, expected)) //TODO: Remove
	test_vector_utils.AssertSliceEqual(t, sorted, expected)
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
