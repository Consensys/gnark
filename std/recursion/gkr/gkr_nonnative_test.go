package gkrnonative

import (
	"encoding/json"
	"fmt"
	gohash "hash"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	fpbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	frbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	//"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	// "github.com/consensys/gnark/frontend/cs/scs"
	// "github.com/consensys/gnark/profile"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	//"github.com/consensys/gnark/std/math/polynomial"
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
	// current := ecc.BN254.ScalarField()
	// var fp emparams.BN254Fp
	testDirPath := "./test_vectors"
	dirEntries, err := os.ReadDir(testDirPath)
	if err != nil {
		t.Error(err)
	}
	for _, dirEntry := range dirEntries {
		if !dirEntry.IsDir() && filepath.Ext(dirEntry.Name()) == ".json" {
			// path := filepath.Join(testDirPath, dirEntry.Name())
			// noExt := dirEntry.Name()[:len(dirEntry.Name())-len(".json")]

			//t.Run(noExt+"_prover", generateTestProver(path, *current, *fp.Modulus()))
			//t.Run(noExt+"_verifier", generateTestVerifier[emparams.BN254Fp](path))
		}
	}
}

func proofEquals(expected NativeProofs, seen NativeProofs) error {
	if len(expected) != len(seen) {
		return fmt.Errorf("length mismatch %d ≠ %d", len(expected), len(seen))
	}
	for i, x := range expected {
		xSeen := seen[i]
		// todo: REMOVE GKR PROOF ABSTRACTION FROM PROOFEQUALS
		xfinalEvalProofSeen := xSeen.FinalEvalProof
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

// func generateTestProver(path string, current big.Int, target big.Int) func(t *testing.T) {
// 	return func(t *testing.T) {
// 		testCase, err := newTestCase(path, target)
// 		assert.NoError(t, err)
// 		proof, err := Prove(&current, &target, testCase.Circuit, testCase.FullAssignment, fiatshamir.WithHashBigInt(testCase.Hash))
// 		assert.NoError(t, err)
// 		assert.NoError(t, proofEquals(testCase.Proof, proof))
// 	}
// }

// func generateTestVerifier[FR emulated.FieldParams](path string) func(t *testing.T) {

// 	return func(t *testing.T) {

// 		testCase, err := getTestCase[FR](path)
// 		assert := test.NewAssert(t)
// 		assert.NoError(err)

// 		assignment := &GkrVerifierCircuitEmulated[FR]{
// 			Input:           testCase.Input,
// 			Output:          testCase.Output,
// 			SerializedProof: testCase.Proof.Serialize(),
// 			ToFail:          false,
// 			TestCaseName:    path,
// 		}

// 		validCircuit := &GkrVerifierCircuitEmulated[FR]{
// 			Input:           make([][]emulated.Element[FR], len(testCase.Input)),
// 			Output:          make([][]emulated.Element[FR], len(testCase.Output)),
// 			SerializedProof: make([]emulated.Element[FR], len(assignment.SerializedProof)),
// 			ToFail:          false,
// 			TestCaseName:    path,
// 		}

// 		fillWithBlanks(validCircuit.Input, len(testCase.Input[0]))
// 		fillWithBlanks(validCircuit.Output, len(testCase.Input[0]))

// 		assert.CheckCircuit(validCircuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.WithValidAssignment(assignment))
// 	}
// }

type GkrVerifierCircuitEmulated[FR emulated.FieldParams] struct {
	Input           [][]emulated.Element[FR]
	Output          [][]emulated.Element[FR] `gnark:",public"`
	SerializedProof []emulated.Element[FR]
	ToFail          bool
	TestCaseName    string
}

// func (c *GkrVerifierCircuitEmulated[FR]) Define(api frontend.API) error {
// 	var fr FR
// 	var testCase *TestCaseVerifier[FR]
// 	var proof Proofs[FR]
// 	var err error

// 	v, err := NewGKRVerifier[FR](api)
// 	if err != nil {
// 		return fmt.Errorf("new verifier: %w", err)
// 	}

// 	if testCase, err = getTestCase[FR](c.TestCaseName); err != nil {
// 		return err
// 	}
// 	sorted := topologicalSortEmulated(testCase.Circuit)

// 	if proof, err = DeserializeProof(sorted, c.SerializedProof); err != nil {
// 		return err
// 	}
// 	assignment := makeInOutAssignment(testCase.Circuit, c.Input, c.Output)

// 	// initiating hash in bitmode
// 	hsh, err := recursion.NewHash(api, fr.Modulus(), true)
// 	if err != nil {
// 		return err
// 	}

// 	return v.Verify(api, testCase.Circuit, assignment, proof, fiatshamir.WithHashFr[FR](hsh))
// }

// func makeInOutAssignment[FR emulated.FieldParams](c CircuitEmulated[FR], inputValues [][]emulated.Element[FR], outputValues [][]emulated.Element[FR]) WireAssignmentEmulated[FR] {
// 	sorted := topologicalSortEmulated(c)
// 	res := make(WireAssignmentEmulated[FR], len(inputValues)+len(outputValues))
// 	inI, outI := 0, 0
// 	for _, w := range sorted {
// 		if w.IsInput() {
// 			res[w] = inputValues[inI]
// 			inI++
// 		} else if w.IsOutput() {
// 			res[w] = outputValues[outI]
// 			outI++
// 		}
// 	}
// 	return res
// }

func makeInOutAssignmentBundle[FR emulated.FieldParams](c CircuitBundleEmulated[FR], inputValues [][]emulated.Element[FR], outputValues [][]emulated.Element[FR]) WireAssignmentBundleEmulated[FR] {
	sorted := topologicalSortBundleEmulated(c)
	res := make(WireAssignmentBundleEmulated[FR], len(sorted))
	for _, w := range sorted {
		if w.IsInput() {
			res[w] = make(WireAssignmentEmulated[FR], len(w.Inputs))
			for _, wire := range w.Inputs {
				res[w][wire] = inputValues[wire.WireIndex]
			}
		} else if w.IsOutput() {
			res[w] = make(WireAssignmentEmulated[FR], len(w.Outputs))
			for _, wire := range w.Outputs {
				res[w][wire] = outputValues[wire.WireIndex]
			}
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

//TODO FIX THIS
func ToCircuitBundleEmulated[FR emulated.FieldParams](c CircuitBundle) (CircuitBundleEmulated[FR], error) {
	var GatesEmulated = map[string]GateEmulated[FR]{
		"identity": IdentityGate[*sumcheck.EmuEngine[FR], *emulated.Element[FR]]{},
		"add":      AddGate[*sumcheck.EmuEngine[FR], *emulated.Element[FR]]{},
		"mul":      MulGate[*sumcheck.EmuEngine[FR], *emulated.Element[FR]]{},
		"dbl_add_select_full_output": sumcheck.DblAddSelectGateFullOutput[*sumcheck.EmuEngine[FR], *emulated.Element[FR]]{},
	}

	// Log the contents of the GatesEmulated map
	fmt.Println("Contents of GatesEmulated map:")
	for name, gate := range GatesEmulated {
		fmt.Printf("Gate name: %s, Gate: %v\n", name, gate)
	}

	var err error
	circuit := make(CircuitBundleEmulated[FR], len(c))
	for i, wireBundle := range c {
		var found bool
		gateName := wireBundle.Gate.GetName()
		if circuit[i].Gate, found = GatesEmulated[gateName]; !found && gateName != "" {
			err = fmt.Errorf("undefined gate \"%s\"", wireBundle.Gate.GetName())
			fmt.Println("err", err)
			panic(err)
		}
		if circuit[i].Gate == nil {
			fmt.Printf("Warning: circuit[%d].Gate is nil for gate name: %s\n", i, gateName)
		} else {
			fmt.Printf("Assigned gate for circuit[%d]: %v\n", i, circuit[i].Gate)
		}
	}

	return circuit, err
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

func TestLoadCircuit(t *testing.T) {
	type FR = emulated.BN254Fp
	c, err := getCircuitEmulated[FR]("test_vectors/resources/two_identity_gates_composed_single_input.json")
	assert.NoError(t, err)
	assert.Equal(t, []*WireEmulated[FR]{}, c[0].Inputs)
	assert.Equal(t, []*WireEmulated[FR]{&c[0]}, c[1].Inputs)
	assert.Equal(t, []*WireEmulated[FR]{&c[1]}, c[2].Inputs)
}

// func TestTopSortTrivial(t *testing.T) {
// 	type FR = emulated.BN254Fp
// 	c := make(CircuitEmulated[FR], 2)
// 	c[0].Inputs = []*WireEmulated[FR]{&c[1]}
// 	sorted := topologicalSortEmulated(c)
// 	assert.Equal(t, []*WireEmulated[FR]{&c[1], &c[0]}, sorted)
// }

// func TestTopSortSingleGate(t *testing.T) {
// 	type FR = emulated.BN254Fp
// 	c := make(CircuitEmulated[FR], 3)
// 	c[0].Inputs = []*WireEmulated[FR]{&c[1], &c[2]}
// 	sorted := topologicalSortEmulated(c)
// 	expected := []*WireEmulated[FR]{&c[1], &c[2], &c[0]}
// 	assert.True(t, utils.SliceEqual(sorted, expected)) //TODO: Remove
// 	utils.AssertSliceEqual(t, sorted, expected)
// 	assert.Equal(t, c[0].nbUniqueOutputs, 0)
// 	assert.Equal(t, c[1].nbUniqueOutputs, 1)
// 	assert.Equal(t, c[2].nbUniqueOutputs, 1)
// }

// func TestTopSortDeep(t *testing.T) {
// 	type FR = emulated.BN254Fp
// 	c := make(CircuitEmulated[FR], 4)
// 	c[0].Inputs = []*WireEmulated[FR]{&c[2]}
// 	c[1].Inputs = []*WireEmulated[FR]{&c[3]}
// 	c[2].Inputs = []*WireEmulated[FR]{}
// 	c[3].Inputs = []*WireEmulated[FR]{&c[0]}
// 	sorted := topologicalSortEmulated(c)
// 	assert.Equal(t, []*WireEmulated[FR]{&c[2], &c[0], &c[3], &c[1]}, sorted)
// }

// func TestTopSortWide(t *testing.T) {
// 	type FR = emulated.BN254Fp
// 	c := make(CircuitEmulated[FR], 10)
// 	c[0].Inputs = []*WireEmulated[FR]{&c[3], &c[8]}
// 	c[1].Inputs = []*WireEmulated[FR]{&c[6]}
// 	c[2].Inputs = []*WireEmulated[FR]{&c[4]}
// 	c[3].Inputs = []*WireEmulated[FR]{}
// 	c[4].Inputs = []*WireEmulated[FR]{}
// 	c[5].Inputs = []*WireEmulated[FR]{&c[9]}
// 	c[6].Inputs = []*WireEmulated[FR]{&c[9]}
// 	c[7].Inputs = []*WireEmulated[FR]{&c[9], &c[5], &c[2]}
// 	c[8].Inputs = []*WireEmulated[FR]{&c[4], &c[3]}
// 	c[9].Inputs = []*WireEmulated[FR]{}

// 	sorted := topologicalSortEmulated(c)
// 	sortedExpected := []*WireEmulated[FR]{&c[3], &c[4], &c[2], &c[8], &c[0], &c[9], &c[5], &c[6], &c[1], &c[7]}

// 	assert.Equal(t, sortedExpected, sorted)
// }

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

// func init() {
// 	Gates["mimc"] = MiMCCipherGate{}
// 	Gates["select-input-3"] = _select(2)
// }

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


// func newTestCase(path string, target big.Int) (*TestCase, error) {
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
// 			var _hash gohash.Hash
// 			if _hash, err = utils.HashFromDescription(info.Hash); err != nil {
// 				return nil, err
// 			}

// 			proof := unmarshalProof(info.Proof)

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
// 					var wireAssignment []big.Int
// 					if wireAssignment, err = utils.SliceToBigIntSlice(assignmentRaw); err != nil {
// 						return nil, err
// 					}
// 					fullAssignment[w] = sumcheck.NativeMultilinear(utils.ConvertToBigIntSlice(wireAssignment))
// 					inOutAssignment[w] = sumcheck.NativeMultilinear(utils.ConvertToBigIntSlice(wireAssignment))
// 				}
// 			}

// 			fullAssignment.Complete(circuit, &target)

// 			for _, w := range sorted {
// 				if w.IsOutput() {

// 					if err = utils.SliceEqualsBigInt(sumcheck.DereferenceBigIntSlice(inOutAssignment[w]), sumcheck.DereferenceBigIntSlice(fullAssignment[w])); err != nil {
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

// 	return tCase.(*TestCase), nil
// }

// type ProjAddGkrVerifierCircuit[FR emulated.FieldParams] struct {
// 	Circuit         CircuitEmulated[FR]
// 	Input           [][]emulated.Element[FR]
// 	Output          [][]emulated.Element[FR] `gnark:",public"`
// 	SerializedProof []emulated.Element[FR]
// }

// func (c *ProjAddGkrVerifierCircuit[FR]) Define(api frontend.API) error {
// 	var fr FR
// 	var proof Proofs[FR]
// 	var err error

// 	v, err := NewGKRVerifier[FR](api)
// 	if err != nil {
// 		return fmt.Errorf("new verifier: %w", err)
// 	}

// 	sorted := topologicalSortEmulated(c.Circuit)

// 	if proof, err = DeserializeProof(sorted, c.SerializedProof); err != nil {
// 		return err
// 	}
// 	assignment := makeInOutAssignment(c.Circuit, c.Input, c.Output)

// 	// initiating hash in bitmode, since bn254 basefield is bigger than scalarfield
// 	hsh, err := recursion.NewHash(api, fr.Modulus(), true)
// 	if err != nil {
// 		return err
// 	}

// 	return v.Verify(api, c.Circuit, assignment, proof, fiatshamir.WithHashFr[FR](hsh))
// }

type ProjAddGkrVerifierCircuit[FR emulated.FieldParams] struct {
	Circuit         CircuitBundleEmulated[FR]
	Input           [][]emulated.Element[FR]
	Output          [][]emulated.Element[FR] `gnark:",public"`
	SerializedProof []emulated.Element[FR]
}

func (c *ProjAddGkrVerifierCircuit[FR]) Define(api frontend.API) error {
	var fr FR
	var proof Proofs[FR]
	var err error

	v, err := NewGKRVerifier[FR](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}

	sorted := topologicalSortBundleEmulated(c.Circuit)

	if proof, err = DeserializeProofBundle(api, sorted, c.SerializedProof); err != nil {
		return err
	}
	assignment := makeInOutAssignmentBundle(c.Circuit, c.Input, c.Output)
	// initiating hash in bitmode, since bn254 basefield is bigger than scalarfield
	hsh, err := recursion.NewHash(api, fr.Modulus(), true)
	if err != nil {
		return err
	}

	return v.Verify(api, c.Circuit, assignment, proof, fiatshamir.WithHashFr[FR](hsh))
}

func ElementToBigInt(element fpbn254.Element) *big.Int {
	var temp big.Int
	return element.BigInt(&temp)
}

func testMultipleDblAddSelectGKRInstance[FR emulated.FieldParams](t *testing.T, current *big.Int, target *big.Int, inputs [][]*big.Int, outputs [][]*big.Int) {
	selector := []*big.Int{big.NewInt(1)}
	c := make(CircuitBundle, 2)
	fmt.Println("inputs", inputs)
	fmt.Println("outputs", outputs)
	c[0] = InitFirstWireBundle(len(inputs))
	c[1] = NewWireBundle(
		sumcheck.DblAddSelectGateFullOutput[*sumcheck.BigIntEngine, *big.Int]{Selector: selector[0]},
		c[0].Outputs,
		1,
	)
	// c[2] = NewWireBundle(
	// 	sumcheck.DblAddSelectGateFullOutput[*sumcheck.BigIntEngine, *big.Int]{Selector: selector[0]},
	// 	c[1].Outputs,
	// 	2,
	// )
	

	selectorEmulated := make([]emulated.Element[FR], len(selector))
	for i, f := range selector {
		selectorEmulated[i] = emulated.ValueOf[FR](f)
	}
	//cEmulated, err := ToCircuitBundleEmulated[FR](c)
	// if err != nil {
	// 	t.Errorf("ToCircuitBundleEmulated: %v", err)
	// 	return
	// }

	cEmulated := make(CircuitBundleEmulated[FR], len(c))
	cEmulated[0] = InitFirstWireBundleEmulated[FR](len(inputs))
	cEmulated[1] = NewWireBundleEmulated(
		sumcheck.DblAddSelectGateFullOutput[*sumcheck.EmuEngine[FR], *emulated.Element[FR]]{Selector: &selectorEmulated[0]},
		c[0].Outputs,
		1,
	)

	assert := test.NewAssert(t)

	hash, err := recursion.NewShort(current, target)
	if err != nil {
		t.Errorf("new short hash: %v", err)
		return
	}
	t.Log("Evaluating all circuit wires")

	fullAssignment := make(WireAssignmentBundle)
	inOutAssignment := make(WireAssignmentBundle)

	sorted := topologicalSortBundle(c)

	inI, outI := 0, 0
	for _, w := range sorted {
		assignmentRaw := make([][]*big.Int, len(w.Inputs))
		fullAssignment[w] = make(WireAssignment, len(w.Inputs))
		inOutAssignment[w] = make(WireAssignment, len(w.Inputs))

		if w.IsInput() {
			if inI == len(inputs) {
				t.Errorf("fewer input in vector than in circuit")
				return
			}
			copy(assignmentRaw, inputs)
			for i, assignment := range assignmentRaw {
				wireAssignment, err := utils.SliceToBigIntSlice(assignment)
				assert.NoError(err)
				fullAssignment[w][wireKey(w.Inputs[i])] = sumcheck.NativeMultilinear(utils.ConvertToBigIntSlice(wireAssignment))
				inOutAssignment[w][wireKey(w.Inputs[i])] = sumcheck.NativeMultilinear(utils.ConvertToBigIntSlice(wireAssignment))
			}
		} else if w.IsOutput() {
			if outI == len(outputs) {
				t.Errorf("fewer output in vector than in circuit")
				return
			}
			copy(assignmentRaw, outputs)
			for i, assignment := range assignmentRaw {
				wireAssignment, err := utils.SliceToBigIntSlice(assignment)
				assert.NoError(err)
				fullAssignment[w][wireKey(w.Outputs[i])] = sumcheck.NativeMultilinear(utils.ConvertToBigIntSlice(wireAssignment))
				inOutAssignment[w][wireKey(w.Outputs[i])] = sumcheck.NativeMultilinear(utils.ConvertToBigIntSlice(wireAssignment))
			}
		}
	}

	fullAssignment.Complete(c, target)

	for _, w := range sorted {
		fmt.Println("w", w.Layer)
		for _, wire := range w.Inputs {
			fmt.Println("inputs fullAssignment[w][", wire, "]", fullAssignment[w][wireKey(wire)])
		}
		for _, wire := range w.Outputs {
			fmt.Println("outputs fullAssignment[w][", wire, "]", fullAssignment[w][wireKey(wire)])
		}
	}

	t.Log("Circuit evaluation complete")
	proof, err := Prove(current, target, c, fullAssignment, fiatshamir.WithHashBigInt(hash))
	assert.NoError(err)
	t.Log("Proof complete")
	fmt.Println("proof", proof)
	
	proofEmulated := make(Proofs[FR], len(proof))
	for i, proof := range proof {
		proofEmulated[i] = sumcheck.ValueOfProof[FR](proof)
	}
	
	validCircuit := &ProjAddGkrVerifierCircuit[FR]{
		Circuit: cEmulated,
		Input:   make([][]emulated.Element[FR], len(inputs)),
		Output:  make([][]emulated.Element[FR], len(outputs)),
		SerializedProof: proofEmulated.Serialize(),
	}

	validAssignment := &ProjAddGkrVerifierCircuit[FR]{
		Circuit: cEmulated,
		Input:   make([][]emulated.Element[FR], len(inputs)),
		Output:  make([][]emulated.Element[FR], len(outputs)),
		SerializedProof: proofEmulated.Serialize(),
	}

	for i := range inputs {
		validCircuit.Input[i] = make([]emulated.Element[FR], len(inputs[i]))
		validAssignment.Input[i] = make([]emulated.Element[FR], len(inputs[i]))
		for j := range inputs[i] {
			validAssignment.Input[i][j] = emulated.ValueOf[FR](inputs[i][j])
		}
	}

	for i := range outputs {
		validCircuit.Output[i] = make([]emulated.Element[FR], len(outputs[i]))
		validAssignment.Output[i] = make([]emulated.Element[FR], len(outputs[i]))
		for j := range outputs[i] {
			validAssignment.Output[i][j] = emulated.ValueOf[FR](outputs[i][j])
		}
	}

	err = test.IsSolved(validCircuit, validAssignment, current)
	assert.NoError(err)
}

func TestMultipleDblAddSelectGKR(t *testing.T) {
	var P1 bn254.G1Affine
	var P2 bn254.G1Affine
	var U1 bn254.G1Affine
	var U2 bn254.G1Affine

	var one fpbn254.Element
	one.SetOne()
	var zero fpbn254.Element
	zero.SetZero()

	var s1 frbn254.Element
	s1.SetOne() //s1.SetRandom()
	var r1 frbn254.Element
	r1.SetOne()	//r1.SetRandom()
	var s2 frbn254.Element
	s2.SetOne() //s2.SetRandom()
	var r2 frbn254.Element
	r2.SetOne() //r2.SetRandom()

	P1.ScalarMultiplicationBase(s1.BigInt(new(big.Int)))
	P2.ScalarMultiplicationBase(r1.BigInt(new(big.Int)))
	U1.ScalarMultiplication(&P1, r2.BigInt(new(big.Int)))
	U2.ScalarMultiplication(&P2, s2.BigInt(new(big.Int)))

	fmt.Println("P1X", P1.X.String())
	fmt.Println("P1Y", P1.Y.String())

	// result, err := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226206973", 10)
	// if !err {
	// 	panic("error result")
	// }

	var fp emparams.BN254Fp
	be := sumcheck.NewBigIntEngine(fp.Modulus())
	gate := sumcheck.DblAddSelectGateFullOutput[*sumcheck.BigIntEngine, *big.Int]{Selector: big.NewInt(1)}
	res1 := gate.Evaluate(be, ElementToBigInt(P1.X), ElementToBigInt(P1.Y), ElementToBigInt(one), big.NewInt(0), big.NewInt(1), big.NewInt(0))
	res2 := gate.Evaluate(be, ElementToBigInt(P2.X), ElementToBigInt(P2.Y), ElementToBigInt(one), big.NewInt(0), big.NewInt(1), big.NewInt(0))
	testMultipleDblAddSelectGKRInstance[emparams.BN254Fp](t, ecc.BN254.ScalarField(), fp.Modulus(), [][]*big.Int{{ElementToBigInt(P1.X), ElementToBigInt(P2.X)}, {ElementToBigInt(P1.Y), ElementToBigInt(P2.Y)}, {ElementToBigInt(one), ElementToBigInt(one)}, {ElementToBigInt(zero), ElementToBigInt(zero)}, {ElementToBigInt(one), ElementToBigInt(one)}, {ElementToBigInt(zero), ElementToBigInt(zero)}}, [][]*big.Int{{res1[0], res2[0]}, {res1[1], res2[1]}, {res1[2], res2[2]}, {res1[3], res2[3]}, {res1[4], res2[4]}, {res1[5], res2[5]}})
}