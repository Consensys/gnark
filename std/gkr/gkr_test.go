package gkr

import (
	"encoding/json"
	"github.com/consensys/gnark-crypto/ecc"
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

func TestSingleIdentityGateTwoInstances(t *testing.T) { // TODO: Remove
	generateTestVerifier("./test_vectors/single_identity_gate_two_instances.json")(t)
}

func TestSingleInputTwoIdentityGatesTwoInstances(t *testing.T) { //TODO: Remove
	generateTestVerifier("./test_vectors/single_input_two_identity_gates_two_instances.json")(t)
}

func TestGkrVectors(t *testing.T) {

	testDirPath := "./test_vectors"
	dirEntries, err := os.ReadDir(testDirPath)
	if err != nil {
		t.Error(err)
	}
	for _, dirEntry := range dirEntries {
		if !dirEntry.IsDir() && filepath.Ext(dirEntry.Name()) == ".json" {

			if dirEntry.Name() == "two_input_single_identity_gate_two_instances.json" {
				continue
			}

			path := filepath.Join(testDirPath, dirEntry.Name())
			noExt := dirEntry.Name()[:len(dirEntry.Name())-len(".json")]

			t.Run(noExt, generateTestVerifier(path))

		}
	}
}

func generateTestVerifier(path string) func(t *testing.T) {
	return func(t *testing.T) {

		testCase, err := getTestCase(path)
		assert.NoError(t, err)

		assignment := &GkrVerifierCircuit{
			Input:           testCase.Input,
			Output:          testCase.Output,
			SerializedProof: testCase.Proof.Serialize(),
			ProofNoise:      0,
			TestCaseName:    path,
		}

		circuit := &GkrVerifierCircuit{
			Input:           make([][]frontend.Variable, len(testCase.Input)),
			Output:          make([][]frontend.Variable, len(testCase.Output)),
			SerializedProof: make([]frontend.Variable, len(assignment.SerializedProof)),
			TestCaseName:    path,
		}

		fillWithBlanks(circuit.Input, len(testCase.Input[0]))
		fillWithBlanks(circuit.Output, len(testCase.Input[0]))

		test.NewAssert(t).ProverSucceeded(circuit, assignment, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))

		assignment.ProofNoise = 1
		test.NewAssert(t).ProverFailed(circuit, assignment, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
	}
}

type GkrVerifierCircuit struct {
	Input           [][]frontend.Variable
	Output          [][]frontend.Variable `gnark:",public"`
	SerializedProof []frontend.Variable
	ProofNoise      frontend.Variable
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

	serializedProof := make([]frontend.Variable, len(c.SerializedProof))
	copy(serializedProof[1:], c.SerializedProof[1:])
	serializedProof[0] = api.Add(c.SerializedProof[0], c.ProofNoise)
	if proof, err = DeserializeProof(sorted, serializedProof); err != nil {
		return err
	}
	assignment := makeInOutAssignment(testCase.Circuit, c.Input, c.Output)

	return Verify(api, testCase.Circuit, assignment, proof, fiatshamir.WithHash(&test_vector_utils.MapHash{Map: testCase.ElementMap, API: api}))
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

func (a WireAssignment) at(w ...*Wire) [][]frontend.Variable {
	res := make([][]frontend.Variable, len(w))

	for i, wI := range w {
		res[i] = a[wI]
	}

	return res
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

func getCircuit(path string) (Circuit, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if circuit, ok := circuitCache[path]; ok {
		return circuit, nil
	}
	var bytes []byte
	if bytes, err = os.ReadFile(path); err == nil {
		var circuitInfo CircuitInfo
		if err = json.Unmarshal(bytes, &circuitInfo); err == nil {
			circuit := circuitInfo.toCircuit()
			circuitCache[path] = circuit
			return circuit, nil
		} else {
			return nil, err
		}
	} else {
		return nil, err
	}
}

func (c CircuitInfo) toCircuit() (circuit Circuit) {
	circuit = make(Circuit, len(c))
	for i, wireInfo := range c {
		circuit[i].Gate = gates[wireInfo.Gate]
		circuit[i].Inputs = make([]*Wire, len(wireInfo.Inputs))
		for iAsInput, iAsWire := range wireInfo.Inputs {
			input := &circuit[iAsWire]
			circuit[i].Inputs[iAsInput] = input
		}
	}

	return
}

var gates map[string]Gate

func init() {
	gates = make(map[string]Gate)
	gates["identity"] = IdentityGate{}
	gates["mul"] = mulGate{}
	gates["mimc"] = mimcCipherGate{ark: 0} //TODO: Add ark
}

type mulGate struct{}

func (g mulGate) Evaluate(api frontend.API, x ...frontend.Variable) frontend.Variable {
	if len(x) != 2 {
		panic("mul has fan-in 2")
	}
	return api.Mul(x[0], x[1])
}

func (g mulGate) Degree() int {
	return 2
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
	testCase, err := getTestCase("test_vectors/two_identity_gates_composed_single_input_two_instances.json")
	assert.NoError(t, err)
	wires := topologicalSort(testCase.Circuit)
	serializedProof := testCase.Proof.Serialize()
	logNbInstances := computeLogNbInstances(wires, len(serializedProof))
	assert.Equal(t, 1, logNbInstances)
}

func TestLoadCircuit(t *testing.T) {
	c, err := getCircuit("test_vectors/resources/two_identity_gates_composed_single_input.json")
	assert.NoError(t, err)
	assert.Equal(t, []*Wire{}, c[0].Inputs)
	assert.Equal(t, []*Wire{&c[0]}, c[1].Inputs)
	assert.Equal(t, []*Wire{&c[1]}, c[2].Inputs)

}
