package gkr

import (
	"encoding/json"
	"fmt"
	gohash "hash"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/std/recursion"
	"github.com/consensys/gnark/std/recursion/gkr/utils"
	"github.com/consensys/gnark/std/recursion/sumcheck"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
)

var Gates = map[string]Gate{
	"identity": IdentityGate[*sumcheck.BigIntEngine, *big.Int]{},
	"add":      AddGate[*sumcheck.BigIntEngine, *big.Int]{},
	"mul":      MulGate[*sumcheck.BigIntEngine, *big.Int]{},
}

func TestGkrVectorsEmulated(t *testing.T) {
	current := ecc.BN254.ScalarField()
	var fr emparams.BN254Fp
	testDirPath := "./test_vectors"
	dirEntries, err := os.ReadDir(testDirPath)
	if err != nil {
		t.Error(err)
	}
	for _, dirEntry := range dirEntries {
		if !dirEntry.IsDir() && filepath.Ext(dirEntry.Name()) == ".json" {
			path := filepath.Join(testDirPath, dirEntry.Name())
			noExt := dirEntry.Name()[:len(dirEntry.Name())-len(".json")]

			t.Run(noExt+"_prover", generateTestProver(path, *current, *fr.Modulus()))
			t.Run(noExt+"_verifier", generateTestVerifier[emparams.BN254Fp](path))
		}
	}
}

func proofEquals(expected NativeProofs, seen NativeProofs) error {
	if len(expected) != len(seen) {
		return fmt.Errorf("length mismatch %d ≠ %d", len(expected), len(seen))
	}
	for i, x := range expected {
		xSeen := seen[i]

		xfinalEvalProofSeen := xSeen.FinalEvalProof
		switch finalEvalProof := xfinalEvalProofSeen.(type) {
		case nil:
			xfinalEvalProofSeen = sumcheck.NativeDeferredEvalProof([]big.Int{})
		case []big.Int:
			xfinalEvalProofSeen = sumcheck.NativeDeferredEvalProof(finalEvalProof)
		default:
			return fmt.Errorf("finalEvalProof is not of type DeferredEvalProof")
		}

		if xSeen.FinalEvalProof == nil {
			if seenFinalEval := x.FinalEvalProof.(sumcheck.NativeDeferredEvalProof); len(seenFinalEval) != 0 {
				return fmt.Errorf("length mismatch %d ≠ %d", 0, len(seenFinalEval))
			}
		} else {
			if err := utils.SliceEqualsBigInt(x.FinalEvalProof.(sumcheck.NativeDeferredEvalProof),
				xfinalEvalProofSeen.(sumcheck.NativeDeferredEvalProof)); err != nil {
				return fmt.Errorf("final evaluation proof mismatch")
			}
		}

		roundPolyEvals := make([]sumcheck.NativePolynomial, len(x.RoundPolyEvaluations))
		copy(roundPolyEvals, x.RoundPolyEvaluations)

		roundPolyEvalsSeen := make([]sumcheck.NativePolynomial, len(xSeen.RoundPolyEvaluations))
		copy(roundPolyEvalsSeen, xSeen.RoundPolyEvaluations)

		for i, poly := range roundPolyEvals {
			if err := utils.SliceEqualsBigInt(sumcheck.DereferenceBigIntSlice(poly), sumcheck.DereferenceBigIntSlice(roundPolyEvalsSeen[i])); err != nil {
				return err
			}
		}
	}
	return nil
}

func generateTestProver(path string, current big.Int, target big.Int) func(t *testing.T) {
	return func(t *testing.T) {
		testCase, err := newTestCase(path, target)
		assert.NoError(t, err)
		proof, err := Prove(&current, &target, testCase.Circuit, testCase.FullAssignment, fiatshamir.WithHashBigInt(testCase.Hash))
		assert.NoError(t, err)
		assert.NoError(t, proofEquals(testCase.Proof, proof))
	}
}

func generateTestVerifier[FR emulated.FieldParams](path string) func(t *testing.T) {

	return func(t *testing.T) {

		testCase, err := getTestCase[FR](path)
		assert := test.NewAssert(t)
		assert.NoError(err)

		assignment := &GkrVerifierCircuitEmulated[FR]{
			Input:           testCase.Input,
			Output:          testCase.Output,
			SerializedProof: testCase.Proof.Serialize(),
			ToFail:          false,
			TestCaseName:    path,
		}

		validCircuit := &GkrVerifierCircuitEmulated[FR]{
			Input:           make([][]emulated.Element[FR], len(testCase.Input)),
			Output:          make([][]emulated.Element[FR], len(testCase.Output)),
			SerializedProof: make([]emulated.Element[FR], len(assignment.SerializedProof)),
			ToFail:          false,
			TestCaseName:    path,
		}

		fillWithBlanks(validCircuit.Input, len(testCase.Input[0]))
		fillWithBlanks(validCircuit.Output, len(testCase.Input[0]))

		assert.CheckCircuit(validCircuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.WithValidAssignment(assignment))
	}
}

type GkrVerifierCircuitEmulated[FR emulated.FieldParams] struct {
	Input           [][]emulated.Element[FR]
	Output          [][]emulated.Element[FR] `gnark:",public"`
	SerializedProof []emulated.Element[FR]
	ToFail          bool
	TestCaseName    string
}

func (c *GkrVerifierCircuitEmulated[FR]) Define(api frontend.API) error {
	var fr FR
	var testCase *TestCaseVerifier[FR]
	var proof Proofs[FR]
	var err error

	v, err := NewGKRVerifier[FR](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}

	if testCase, err = getTestCase[FR](c.TestCaseName); err != nil {
		return err
	}
	sorted := topologicalSortEmulated(testCase.Circuit)

	if proof, err = DeserializeProof(sorted, c.SerializedProof); err != nil {
		return err
	}
	assignment := makeInOutAssignment(testCase.Circuit, c.Input, c.Output)

	// initiating hash in bitmode
	hsh, err := recursion.NewHash(api, fr.Modulus(), true)
	if err != nil {
		return err
	}

	return v.Verify(api, testCase.Circuit, assignment, proof, fiatshamir.WithHashFr[FR](hsh))
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

type TestCaseVerifier[FR emulated.FieldParams] struct {
	Circuit CircuitEmulated[FR]
	Hash    utils.HashDescription
	Proof   Proofs[FR]
	Input   [][]emulated.Element[FR]
	Output  [][]emulated.Element[FR]
	Name    string
}
type TestCaseInfo struct {
	Hash    utils.HashDescription `json:"hash"`
	Circuit string                `json:"circuit"`
	Input   [][]interface{}       `json:"input"`
	Output  [][]interface{}       `json:"output"`
	Proof   PrintableProof        `json:"proof"`
}

var testCases = make(map[string]interface{})

func getTestCase[FR emulated.FieldParams](path string) (*TestCaseVerifier[FR], error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)

	cse, ok := testCases[path].(*TestCaseVerifier[FR])
	if !ok {
		var bytes []byte
		cse = &TestCaseVerifier[FR]{}
		if bytes, err = os.ReadFile(path); err == nil {
			var info TestCaseInfo
			err = json.Unmarshal(bytes, &info)
			if err != nil {
				return nil, err
			}

			if cse.Circuit, err = getCircuitEmulated[FR](filepath.Join(dir, info.Circuit)); err != nil {
				return nil, err
			}

			nativeProofs := unmarshalProof(info.Proof)
			proofs := make(Proofs[FR], len(nativeProofs))
			for i, proof := range nativeProofs {
				proofs[i] = sumcheck.ValueOfProof[FR](proof)
			}
			cse.Proof = proofs

			cse.Input = utils.ToVariableSliceSliceFr[FR](info.Input)
			cse.Output = utils.ToVariableSliceSliceFr[FR](info.Output)
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

var circuitCache = make(map[string]interface{})

func getCircuit(path string) (circuit Circuit, err error) {
	path, err = filepath.Abs(path)
	if err != nil {
		return
	}
	var ok bool
	if circuit, ok = circuitCache[path].(Circuit); ok {
		return
	}
	var bytes []byte
	if bytes, err = os.ReadFile(path); err == nil {
		var circuitInfo CircuitInfo
		if err = json.Unmarshal(bytes, &circuitInfo); err == nil {
			circuit, err = toCircuit(circuitInfo)
			if err == nil {
				circuitCache[path] = circuit
			}
		}
	}
	return
}

func getCircuitEmulated[FR emulated.FieldParams](path string) (circuit CircuitEmulated[FR], err error) {
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
			circuit, err = ToCircuitEmulated[FR](circuitInfo)
			if err == nil {
				circuitCache[path] = circuit
			}
		}
	}
	return
}

func ToCircuitEmulated[FR emulated.FieldParams](c CircuitInfo) (circuit CircuitEmulated[FR], err error) {
	var GatesEmulated = map[string]GateEmulated[FR]{
		"identity": IdentityGate[*sumcheck.EmuEngine[FR], *emulated.Element[FR]]{},
		"add":      AddGate[*sumcheck.EmuEngine[FR], *emulated.Element[FR]]{},
		"mul":      MulGate[*sumcheck.EmuEngine[FR], *emulated.Element[FR]]{},
	}

	circuit = make(CircuitEmulated[FR], len(c))
	for i, wireInfo := range c {
		circuit[i].Inputs = make([]*WireEmulated[FR], len(wireInfo.Inputs))
		for iAsInput, iAsWire := range wireInfo.Inputs {
			input := &circuit[iAsWire]
			circuit[i].Inputs[iAsInput] = input
		}

		var found bool
		if circuit[i].Gate, found = GatesEmulated[wireInfo.Gate]; !found && wireInfo.Gate != "" {
			err = fmt.Errorf("undefined gate \"%s\"", wireInfo.Gate)
		}
	}

	return
}

func toCircuit(c CircuitInfo) (circuit Circuit, err error) {

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

type PrintableProof []PrintableSumcheckProof

type PrintableSumcheckProof struct {
	FinalEvalProof       [][]uint64   `json:"finalEvalProof"`
	RoundPolyEvaluations [][][]uint64 `json:"roundPolyEvaluations"`
}

func unmarshalProof(printable []PrintableSumcheckProof) (proof NativeProofs) {
	proof = make(NativeProofs, len(printable))

	for i := range printable {
		if printable[i].FinalEvalProof != nil {
			finalEvalProof := make(sumcheck.NativeDeferredEvalProof, len(printable[i].FinalEvalProof))
			for k, val := range printable[i].FinalEvalProof {
				var temp big.Int
				temp.SetUint64(val[0])
				for _, v := range val[1:] {
					temp.Lsh(&temp, 64).Add(&temp, new(big.Int).SetUint64(v))
				}
				finalEvalProof[k] = temp
			}
			proof[i].FinalEvalProof = finalEvalProof
		} else {
			proof[i].FinalEvalProof = nil
		}

		proof[i].RoundPolyEvaluations = make([]sumcheck.NativePolynomial, len(printable[i].RoundPolyEvaluations))
		for k, evals := range printable[i].RoundPolyEvaluations {
			proof[i].RoundPolyEvaluations[k] = make(sumcheck.NativePolynomial, len(evals))
			for j, eval := range evals {
				var temp big.Int
				temp.SetUint64(eval[0])
				for _, v := range eval[1:] {
					temp.Lsh(&temp, 64).Add(&temp, new(big.Int).SetUint64(v))
				}
				proof[i].RoundPolyEvaluations[k][j] = &temp
			}
		}
	}
	return proof
}

func TestLogNbInstances(t *testing.T) {
	type FR = emulated.BN254Fp
	testLogNbInstances := func(path string) func(t *testing.T) {
		return func(t *testing.T) {
			testCase, err := getTestCase[FR](path)
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
	type FR = emulated.BN254Fp
	c, err := getCircuitEmulated[FR]("test_vectors/resources/two_identity_gates_composed_single_input.json")
	assert.NoError(t, err)
	assert.Equal(t, []*WireEmulated[FR]{}, c[0].Inputs)
	assert.Equal(t, []*WireEmulated[FR]{&c[0]}, c[1].Inputs)
	assert.Equal(t, []*WireEmulated[FR]{&c[1]}, c[2].Inputs)
}

func TestTopSortTrivial(t *testing.T) {
	type FR = emulated.BN254Fp
	c := make(CircuitEmulated[FR], 2)
	c[0].Inputs = []*WireEmulated[FR]{&c[1]}
	sorted := topologicalSortEmulated(c)
	assert.Equal(t, []*WireEmulated[FR]{&c[1], &c[0]}, sorted)
}

func TestTopSortSingleGate(t *testing.T) {
	type FR = emulated.BN254Fp
	c := make(CircuitEmulated[FR], 3)
	c[0].Inputs = []*WireEmulated[FR]{&c[1], &c[2]}
	sorted := topologicalSortEmulated(c)
	expected := []*WireEmulated[FR]{&c[1], &c[2], &c[0]}
	assert.True(t, utils.SliceEqual(sorted, expected)) //TODO: Remove
	utils.AssertSliceEqual(t, sorted, expected)
	assert.Equal(t, c[0].nbUniqueOutputs, 0)
	assert.Equal(t, c[1].nbUniqueOutputs, 1)
	assert.Equal(t, c[2].nbUniqueOutputs, 1)
}

func TestTopSortDeep(t *testing.T) {
	type FR = emulated.BN254Fp
	c := make(CircuitEmulated[FR], 4)
	c[0].Inputs = []*WireEmulated[FR]{&c[2]}
	c[1].Inputs = []*WireEmulated[FR]{&c[3]}
	c[2].Inputs = []*WireEmulated[FR]{}
	c[3].Inputs = []*WireEmulated[FR]{&c[0]}
	sorted := topologicalSortEmulated(c)
	assert.Equal(t, []*WireEmulated[FR]{&c[2], &c[0], &c[3], &c[1]}, sorted)
}

func TestTopSortWide(t *testing.T) {
	type FR = emulated.BN254Fp
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

var mimcSnarkTotalCalls = 0

// todo add ark
type MiMCCipherGate struct {
}

func (m MiMCCipherGate) Evaluate(api *sumcheck.BigIntEngine, input ...*big.Int) *big.Int {
	mimcSnarkTotalCalls++

	if len(input) != 2 {
		panic("mimc has fan-in 2")
	}
	sum := api.Add(input[0], input[1])
	sumSquared := api.Mul(sum, sum)
	sumCubed := api.Mul(sumSquared, sum)
	return api.Mul(sumCubed, sum)
}

func (m MiMCCipherGate) Degree() int {
	return 7
}

type _select int

func init() {
	Gates["mimc"] = MiMCCipherGate{}
	Gates["select-input-3"] = _select(2)
}

func (g _select) Evaluate(_ *sumcheck.BigIntEngine, in ...*big.Int) *big.Int {
	return in[g]
}

func (g _select) Degree() int {
	return 1
}

type TestCase struct {
	Current         big.Int
	Target          big.Int
	Circuit         Circuit
	Hash            gohash.Hash
	Proof           NativeProofs
	FullAssignment  WireAssignment
	InOutAssignment WireAssignment
}

func (p *PrintableSumcheckProof) UnmarshalJSON(data []byte) error {
	var temp struct {
		FinalEvalProof       [][]uint64   `json:"finalEvalProof"`
		RoundPolyEvaluations [][][]uint64 `json:"roundPolyEvaluations"`
	}

	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	p.FinalEvalProof = temp.FinalEvalProof

	p.RoundPolyEvaluations = make([][][]uint64, len(temp.RoundPolyEvaluations))
	for i, arr2D := range temp.RoundPolyEvaluations {
		p.RoundPolyEvaluations[i] = make([][]uint64, len(arr2D))
		for j, arr1D := range arr2D {
			p.RoundPolyEvaluations[i][j] = make([]uint64, len(arr1D))
			for k, v := range arr1D {
				p.RoundPolyEvaluations[i][j][k] = uint64(v)
			}
		}
	}
	return nil
}

func newTestCase(path string, target big.Int) (*TestCase, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)

	tCase, ok := testCases[path]
	if !ok {
		var bytes []byte
		if bytes, err = os.ReadFile(path); err == nil {
			var info TestCaseInfo
			err = json.Unmarshal(bytes, &info)
			if err != nil {
				return nil, err
			}

			var circuit Circuit
			if circuit, err = getCircuit(filepath.Join(dir, info.Circuit)); err != nil {
				return nil, err
			}
			var _hash gohash.Hash
			if _hash, err = utils.HashFromDescription(info.Hash); err != nil {
				return nil, err
			}

			proof := unmarshalProof(info.Proof)

			fullAssignment := make(WireAssignment)
			inOutAssignment := make(WireAssignment)

			sorted := topologicalSort(circuit)

			inI, outI := 0, 0
			for _, w := range sorted {
				var assignmentRaw []interface{}
				if w.IsInput() {
					if inI == len(info.Input) {
						return nil, fmt.Errorf("fewer input in vector than in circuit")
					}
					assignmentRaw = info.Input[inI]
					inI++
				} else if w.IsOutput() {
					if outI == len(info.Output) {
						return nil, fmt.Errorf("fewer output in vector than in circuit")
					}
					assignmentRaw = info.Output[outI]
					outI++
				}
				if assignmentRaw != nil {
					var wireAssignment []big.Int
					if wireAssignment, err = utils.SliceToBigIntSlice(assignmentRaw); err != nil {
						return nil, err
					}
					fullAssignment[w] = sumcheck.NativeMultilinear(utils.ConvertToBigIntSlice(wireAssignment))
					inOutAssignment[w] = sumcheck.NativeMultilinear(utils.ConvertToBigIntSlice(wireAssignment))
				}
			}

			fullAssignment.Complete(circuit, &target)

			for _, w := range sorted {
				if w.IsOutput() {

					if err = utils.SliceEqualsBigInt(sumcheck.DereferenceBigIntSlice(inOutAssignment[w]), sumcheck.DereferenceBigIntSlice(fullAssignment[w])); err != nil {
						return nil, fmt.Errorf("assignment mismatch: %v", err)
					}

				}
			}

			tCase = &TestCase{
				FullAssignment:  fullAssignment,
				InOutAssignment: inOutAssignment,
				Proof:           proof,
				Hash:            _hash,
				Circuit:         circuit,
			}

			testCases[path] = tCase
		} else {
			return nil, err
		}
	}

	return tCase.(*TestCase), nil
}
