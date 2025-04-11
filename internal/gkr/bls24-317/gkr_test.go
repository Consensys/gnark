// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Code generated by gnark DO NOT EDIT

package gkr

import (
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bls24-317/fr"
	"github.com/consensys/gnark-crypto/ecc/bls24-317/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bls24-317/fr/polynomial"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/utils"
	"github.com/consensys/gnark/internal/gkr/bls24-317/sumcheck"
	"github.com/consensys/gnark/internal/gkr/bls24-317/test_vector_utils"
	"github.com/stretchr/testify/assert"
	"hash"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestNoGateTwoInstances(t *testing.T) {
	// Testing a single instance is not possible because the sumcheck implementation doesn't cover the trivial 0-variate case
	testNoGate(t, []fr.Element{four, three})
}

func TestNoGate(t *testing.T) {
	testManyInstances(t, 1, testNoGate)
}

func TestSingleAddGateTwoInstances(t *testing.T) {
	testSingleAddGate(t, []fr.Element{four, three}, []fr.Element{two, three})
}

func TestSingleAddGate(t *testing.T) {
	testManyInstances(t, 2, testSingleAddGate)
}

func TestSingleMulGateTwoInstances(t *testing.T) {
	testSingleMulGate(t, []fr.Element{four, three}, []fr.Element{two, three})
}

func TestSingleMulGate(t *testing.T) {
	testManyInstances(t, 2, testSingleMulGate)
}

func TestSingleInputTwoIdentityGatesTwoInstances(t *testing.T) {

	testSingleInputTwoIdentityGates(t, []fr.Element{two, three})
}

func TestSingleInputTwoIdentityGates(t *testing.T) {

	testManyInstances(t, 2, testSingleInputTwoIdentityGates)
}

func TestSingleInputTwoIdentityGatesComposedTwoInstances(t *testing.T) {
	testSingleInputTwoIdentityGatesComposed(t, []fr.Element{two, one})
}

func TestSingleInputTwoIdentityGatesComposed(t *testing.T) {
	testManyInstances(t, 1, testSingleInputTwoIdentityGatesComposed)
}

func TestSingleMimcCipherGateTwoInstances(t *testing.T) {
	testSingleMimcCipherGate(t, []fr.Element{one, one}, []fr.Element{one, two})
}

func TestSingleMimcCipherGate(t *testing.T) {
	testManyInstances(t, 2, testSingleMimcCipherGate)
}

func TestATimesBSquaredTwoInstances(t *testing.T) {
	testATimesBSquared(t, 2, []fr.Element{one, one}, []fr.Element{one, two})
}

func TestShallowMimcTwoInstances(t *testing.T) {
	testMimc(t, 2, []fr.Element{one, one}, []fr.Element{one, two})
}

func TestMimcTwoInstances(t *testing.T) {
	testMimc(t, 93, []fr.Element{one, one}, []fr.Element{one, two})
}

func TestMimc(t *testing.T) {
	testManyInstances(t, 2, generateTestMimc(93))
}

func generateTestMimc(numRounds int) func(*testing.T, ...[]fr.Element) {
	return func(t *testing.T, inputAssignments ...[]fr.Element) {
		testMimc(t, numRounds, inputAssignments...)
	}
}

func TestSumcheckFromSingleInputTwoIdentityGatesGateTwoInstances(t *testing.T) {
	circuit := Circuit{Wire{
		Gate:            GetGate(Identity),
		Inputs:          []*Wire{},
		nbUniqueOutputs: 2,
	}}

	wire := &circuit[0]

	assignment := WireAssignment{&circuit[0]: []fr.Element{two, three}}
	var o settings
	pool := polynomial.NewPool(256, 1<<11)
	workers := utils.NewWorkerPool()
	o.pool = &pool
	o.workers = workers

	claimsManagerGen := func() *claimsManager {
		manager := newClaimsManager(circuit, assignment, o)
		manager.add(wire, []fr.Element{three}, five)
		manager.add(wire, []fr.Element{four}, six)
		return &manager
	}

	transcriptGen := test_vector_utils.NewMessageCounterGenerator(4, 1)

	proof, err := sumcheck.Prove(claimsManagerGen().getClaim(wire), fiatshamir.WithHash(transcriptGen(), nil))
	assert.NoError(t, err)
	err = sumcheck.Verify(claimsManagerGen().getLazyClaim(wire), proof, fiatshamir.WithHash(transcriptGen(), nil))
	assert.NoError(t, err)
}

var one, two, three, four, five, six fr.Element

func init() {
	one.SetOne()
	two.Double(&one)
	three.Add(&two, &one)
	four.Double(&two)
	five.Add(&three, &two)
	six.Double(&three)
}

var testManyInstancesLogMaxInstances = -1

func getLogMaxInstances(t *testing.T) int {
	if testManyInstancesLogMaxInstances == -1 {

		s := os.Getenv("GKR_LOG_INSTANCES")
		if s == "" {
			testManyInstancesLogMaxInstances = 5
		} else {
			var err error
			testManyInstancesLogMaxInstances, err = strconv.Atoi(s)
			if err != nil {
				t.Error(err)
			}
		}

	}
	return testManyInstancesLogMaxInstances
}

func testManyInstances(t *testing.T, numInput int, test func(*testing.T, ...[]fr.Element)) {
	fullAssignments := make([][]fr.Element, numInput)
	maxSize := 1 << getLogMaxInstances(t)

	t.Log("Entered test orchestrator, assigning and randomizing inputs")

	for i := range fullAssignments {
		fullAssignments[i] = make([]fr.Element, maxSize)
		setRandomSlice(fullAssignments[i])
	}

	inputAssignments := make([][]fr.Element, numInput)
	for numEvals := maxSize; numEvals <= maxSize; numEvals *= 2 {
		for i, fullAssignment := range fullAssignments {
			inputAssignments[i] = fullAssignment[:numEvals]
		}

		t.Log("Selected inputs for test")
		test(t, inputAssignments...)
	}
}

func testNoGate(t *testing.T, inputAssignments ...[]fr.Element) {
	c := Circuit{
		{
			Inputs: []*Wire{},
			Gate:   nil,
		},
	}

	assignment := WireAssignment{&c[0]: inputAssignments[0]}

	proof, err := Prove(c, assignment, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(1, 1)))
	assert.NoError(t, err)

	// Even though a hash is called here, the proof is empty

	err = Verify(c, assignment, proof, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(1, 1)))
	assert.NoError(t, err, "proof rejected")
}

func testSingleAddGate(t *testing.T, inputAssignments ...[]fr.Element) {
	c := make(Circuit, 3)
	c[2] = Wire{
		Gate:   GetGate(Add2),
		Inputs: []*Wire{&c[0], &c[1]},
	}

	assignment := WireAssignment{&c[0]: inputAssignments[0], &c[1]: inputAssignments[1]}.Complete(c)

	proof, err := Prove(c, assignment, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(1, 1)))
	assert.NoError(t, err)

	err = Verify(c, assignment, proof, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(1, 1)))
	assert.NoError(t, err, "proof rejected")

	err = Verify(c, assignment, proof, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(0, 1)))
	assert.NotNil(t, err, "bad proof accepted")
}

func testSingleMulGate(t *testing.T, inputAssignments ...[]fr.Element) {

	c := make(Circuit, 3)
	c[2] = Wire{
		Gate:   GetGate(Mul2),
		Inputs: []*Wire{&c[0], &c[1]},
	}

	assignment := WireAssignment{&c[0]: inputAssignments[0], &c[1]: inputAssignments[1]}.Complete(c)

	proof, err := Prove(c, assignment, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(1, 1)))
	assert.NoError(t, err)

	err = Verify(c, assignment, proof, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(1, 1)))
	assert.NoError(t, err, "proof rejected")

	err = Verify(c, assignment, proof, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(0, 1)))
	assert.NotNil(t, err, "bad proof accepted")
}

func testSingleInputTwoIdentityGates(t *testing.T, inputAssignments ...[]fr.Element) {
	c := make(Circuit, 3)

	c[1] = Wire{
		Gate:   GetGate(Identity),
		Inputs: []*Wire{&c[0]},
	}

	c[2] = Wire{
		Gate:   GetGate(Identity),
		Inputs: []*Wire{&c[0]},
	}

	assignment := WireAssignment{&c[0]: inputAssignments[0]}.Complete(c)

	proof, err := Prove(c, assignment, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(0, 1)))
	assert.NoError(t, err)

	err = Verify(c, assignment, proof, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(0, 1)))
	assert.NoError(t, err, "proof rejected")

	err = Verify(c, assignment, proof, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(1, 1)))
	assert.NotNil(t, err, "bad proof accepted")
}

func testSingleMimcCipherGate(t *testing.T, inputAssignments ...[]fr.Element) {
	c := make(Circuit, 3)

	c[2] = Wire{
		Gate:   GetGate("mimc"),
		Inputs: []*Wire{&c[0], &c[1]},
	}

	t.Log("Evaluating all circuit wires")
	assignment := WireAssignment{&c[0]: inputAssignments[0], &c[1]: inputAssignments[1]}.Complete(c)
	t.Log("Circuit evaluation complete")
	proof, err := Prove(c, assignment, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(0, 1)))
	assert.NoError(t, err)
	t.Log("Proof complete")
	err = Verify(c, assignment, proof, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(0, 1)))
	assert.NoError(t, err, "proof rejected")

	t.Log("Successful verification complete")
	err = Verify(c, assignment, proof, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(1, 1)))
	assert.NotNil(t, err, "bad proof accepted")
	t.Log("Unsuccessful verification complete")
}

func testSingleInputTwoIdentityGatesComposed(t *testing.T, inputAssignments ...[]fr.Element) {
	c := make(Circuit, 3)

	c[1] = Wire{
		Gate:   GetGate(Identity),
		Inputs: []*Wire{&c[0]},
	}
	c[2] = Wire{
		Gate:   GetGate(Identity),
		Inputs: []*Wire{&c[1]},
	}

	assignment := WireAssignment{&c[0]: inputAssignments[0]}.Complete(c)

	proof, err := Prove(c, assignment, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(0, 1)))
	assert.NoError(t, err)

	err = Verify(c, assignment, proof, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(0, 1)))
	assert.NoError(t, err, "proof rejected")

	err = Verify(c, assignment, proof, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(1, 1)))
	assert.NotNil(t, err, "bad proof accepted")
}

func mimcCircuit(numRounds int) Circuit {
	c := make(Circuit, numRounds+2)

	for i := 2; i < len(c); i++ {
		c[i] = Wire{
			Gate:   GetGate("mimc"),
			Inputs: []*Wire{&c[i-1], &c[0]},
		}
	}
	return c
}

func testMimc(t *testing.T, numRounds int, inputAssignments ...[]fr.Element) {
	//TODO: Implement mimc correctly. Currently, the computation is mimc(a,b) = cipher( cipher( ... cipher(a, b), b) ..., b)
	// @AlexandreBelling: Please explain the extra layers in https://github.com/Consensys/gkr-mimc/blob/81eada039ab4ed403b7726b535adb63026e8011f/examples/mimc.go#L10

	c := mimcCircuit(numRounds)

	t.Log("Evaluating all circuit wires")
	assignment := WireAssignment{&c[0]: inputAssignments[0], &c[1]: inputAssignments[1]}.Complete(c)
	t.Log("Circuit evaluation complete")

	proof, err := Prove(c, assignment, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(0, 1)))
	assert.NoError(t, err)

	t.Log("Proof finished")
	err = Verify(c, assignment, proof, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(0, 1)))
	assert.NoError(t, err, "proof rejected")

	t.Log("Successful verification finished")
	err = Verify(c, assignment, proof, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(1, 1)))
	assert.NotNil(t, err, "bad proof accepted")
	t.Log("Unsuccessful verification finished")
}

func testATimesBSquared(t *testing.T, numRounds int, inputAssignments ...[]fr.Element) {
	// This imitates the MiMC circuit

	c := make(Circuit, numRounds+2)

	for i := 2; i < len(c); i++ {
		c[i] = Wire{
			Gate:   GetGate(Mul2),
			Inputs: []*Wire{&c[i-1], &c[0]},
		}
	}

	assignment := WireAssignment{&c[0]: inputAssignments[0], &c[1]: inputAssignments[1]}.Complete(c)

	proof, err := Prove(c, assignment, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(0, 1)))
	assert.NoError(t, err)

	err = Verify(c, assignment, proof, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(0, 1)))
	assert.NoError(t, err, "proof rejected")

	err = Verify(c, assignment, proof, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(1, 1)))
	assert.NotNil(t, err, "bad proof accepted")
}

func setRandomSlice(slice []fr.Element) {
	for i := range slice {
		slice[i].MustSetRandom()
	}
}

func generateTestProver(path string) func(t *testing.T) {
	return func(t *testing.T) {
		testCase, err := newTestCase(path)
		assert.NoError(t, err)
		proof, err := Prove(testCase.Circuit, testCase.FullAssignment, fiatshamir.WithHash(testCase.Hash))
		assert.NoError(t, err)
		assert.NoError(t, proofEquals(testCase.Proof, proof))
	}
}

func generateTestVerifier(path string) func(t *testing.T) {
	return func(t *testing.T) {
		testCase, err := newTestCase(path)
		assert.NoError(t, err)
		err = Verify(testCase.Circuit, testCase.InOutAssignment, testCase.Proof, fiatshamir.WithHash(testCase.Hash))
		assert.NoError(t, err, "proof rejected")
		testCase, err = newTestCase(path)
		assert.NoError(t, err)
		err = Verify(testCase.Circuit, testCase.InOutAssignment, testCase.Proof, fiatshamir.WithHash(test_vector_utils.NewMessageCounter(2, 0)))
		assert.NotNil(t, err, "bad proof accepted")
	}
}

func TestGkrVectors(t *testing.T) {

	const testDirPath = "../test_vectors/gkr"
	dirEntries, err := os.ReadDir(testDirPath)
	assert.NoError(t, err)
	for _, dirEntry := range dirEntries {
		if !dirEntry.IsDir() {

			if filepath.Ext(dirEntry.Name()) == ".json" {
				path := filepath.Join(testDirPath, dirEntry.Name())
				noExt := dirEntry.Name()[:len(dirEntry.Name())-len(".json")]

				t.Run(noExt+"_prover", generateTestProver(path))
				t.Run(noExt+"_verifier", generateTestVerifier(path))

			}
		}
	}
}

func proofEquals(expected Proof, seen Proof) error {
	if len(expected) != len(seen) {
		return fmt.Errorf("length mismatch %d ≠ %d", len(expected), len(seen))
	}
	for i, x := range expected {
		xSeen := seen[i]

		if xSeen.FinalEvalProof == nil {
			if seenFinalEval := x.FinalEvalProof; len(seenFinalEval) != 0 {
				return fmt.Errorf("length mismatch %d ≠ %d", 0, len(seenFinalEval))
			}
		} else {
			if err := test_vector_utils.SliceEquals(x.FinalEvalProof, xSeen.FinalEvalProof); err != nil {
				return fmt.Errorf("final evaluation proof mismatch")
			}
		}
		if err := test_vector_utils.PolynomialSliceEquals(x.PartialSumPolys, xSeen.PartialSumPolys); err != nil {
			return err
		}
	}
	return nil
}

func benchmarkGkrMiMC(b *testing.B, nbInstances, mimcDepth int) {
	fmt.Println("creating circuit structure")
	c := mimcCircuit(mimcDepth)

	in0 := make([]fr.Element, nbInstances)
	in1 := make([]fr.Element, nbInstances)
	setRandomSlice(in0)
	setRandomSlice(in1)

	fmt.Println("evaluating circuit")
	start := time.Now().UnixMicro()
	assignment := WireAssignment{&c[0]: in0, &c[1]: in1}.Complete(c)
	solved := time.Now().UnixMicro() - start
	fmt.Println("solved in", solved, "μs")

	//b.ResetTimer()
	fmt.Println("constructing proof")
	start = time.Now().UnixMicro()
	_, err := Prove(c, assignment, fiatshamir.WithHash(mimc.NewMiMC()))
	proved := time.Now().UnixMicro() - start
	fmt.Println("proved in", proved, "μs")
	assert.NoError(b, err)
}

func BenchmarkGkrMimc19(b *testing.B) {
	benchmarkGkrMiMC(b, 1<<19, 91)
}

func BenchmarkGkrMimc17(b *testing.B) {
	benchmarkGkrMiMC(b, 1<<17, 91)
}

func TestTopSortTrivial(t *testing.T) {
	c := make(Circuit, 2)
	c[0].Inputs = []*Wire{&c[1]}
	sorted := topologicalSort(c)
	assert.Equal(t, []*Wire{&c[1], &c[0]}, sorted)
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

type WireInfo struct {
	Gate   GateName `json:"gate"`
	Inputs []int    `json:"inputs"`
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
	for i := range c {
		circuit[i].Gate = GetGate(c[i].Gate)
		circuit[i].Inputs = make([]*Wire, len(c[i].Inputs))
		for k, inputCoord := range c[i].Inputs {
			input := &circuit[inputCoord]
			circuit[i].Inputs[k] = input
		}
	}
	return
}

func mimcRound(input ...fr.Element) (res fr.Element) {
	var sum fr.Element

	sum.
		Add(&input[0], &input[1]) //.Add(&sum, &m.ark)  TODO: add ark
	res.Square(&sum)    // sum^2
	res.Mul(&res, &sum) // sum^3
	res.Square(&res)    //sum^6
	res.Mul(&res, &sum) //sum^7

	return
}

const (
	MiMC         GateName = "mimc"
	SelectInput3 GateName = "select-input-3"
)

func init() {
	if err := RegisterGate(MiMC, mimcRound, 2, WithUnverifiedDegree(7)); err != nil {
		panic(err)
	}

	if err := RegisterGate(SelectInput3, func(input ...fr.Element) fr.Element {
		return input[2]
	}, 3, WithUnverifiedDegree(1)); err != nil {
		panic(err)
	}
}

type PrintableProof []PrintableSumcheckProof

type PrintableSumcheckProof struct {
	FinalEvalProof  interface{}     `json:"finalEvalProof"`
	PartialSumPolys [][]interface{} `json:"partialSumPolys"`
}

func unmarshalProof(printable PrintableProof) (Proof, error) {
	proof := make(Proof, len(printable))
	for i := range printable {
		finalEvalProof := []fr.Element(nil)

		if printable[i].FinalEvalProof != nil {
			finalEvalSlice := reflect.ValueOf(printable[i].FinalEvalProof)
			finalEvalProof = make([]fr.Element, finalEvalSlice.Len())
			for k := range finalEvalProof {
				if _, err := SetElement(&finalEvalProof[k], finalEvalSlice.Index(k).Interface()); err != nil {
					return nil, err
				}
			}
		}

		proof[i] = sumcheckProof{
			partialSumPolys: make([]polynomial.Polynomial, len(printable[i].PartialSumPolys)),
			finalEvalProof:  finalEvalProof,
		}
		for k := range printable[i].PartialSumPolys {
			var err error
			if proof[i].partialSumPolys[k], err = SliceToElementSlice(printable[i].PartialSumPolys[k]); err != nil {
				return nil, err
			}
		}
	}
	return proof, nil
}

type TestCase struct {
	Circuit         Circuit
	Hash            hash.Hash
	Proof           Proof
	FullAssignment  WireAssignment
	InOutAssignment WireAssignment
}

type TestCaseInfo struct {
	Hash    HashDescription `json:"hash"`
	Circuit string          `json:"circuit"`
	Input   [][]interface{} `json:"input"`
	Output  [][]interface{} `json:"output"`
	Proof   PrintableProof  `json:"proof"`
}

var testCases = make(map[string]*TestCase)

func newTestCase(path string) (*TestCase, error) {
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
			var _hash hash.Hash
			if _hash, err = HashFromDescription(info.Hash); err != nil {
				return nil, err
			}
			var proof Proof
			if proof, err = unmarshalProof(info.Proof); err != nil {
				return nil, err
			}

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
					var wireAssignment []fr.Element
					if wireAssignment, err = SliceToElementSlice(assignmentRaw); err != nil {
						return nil, err
					}

					fullAssignment[w] = wireAssignment
					inOutAssignment[w] = wireAssignment
				}
			}

			fullAssignment.Complete(circuit)

			for _, w := range sorted {
				if w.IsOutput() {

					if err = SliceEquals(inOutAssignment[w], fullAssignment[w]); err != nil {
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

	return tCase, nil
}

func TestRegisterGateDegreeDetection(t *testing.T) {
	testGate := func(name GateName, f func(...fr.Element) fr.Element, nbIn, degree int) {
		t.Run(string(name), func(t *testing.T) {
			name = name + "-register-gate-test"

			assert.NoError(t, RegisterGate(name, f, nbIn, WithDegree(degree)), "given degree must be accepted")

			assert.Error(t, RegisterGate(name, f, nbIn, WithDegree(degree-1)), "lower degree must be rejected")

			assert.Error(t, RegisterGate(name, f, nbIn, WithDegree(degree+1)), "higher degree must be rejected")

			assert.NoError(t, RegisterGate(name, f, nbIn), "no degree must be accepted")

			assert.Equal(t, degree, GetGate(name).Degree(), "degree must be detected correctly")
		})
	}

	testGate("select", func(x ...fr.Element) fr.Element {
		return x[0]
	}, 3, 1)

	testGate("add2", func(x ...fr.Element) fr.Element {
		var res fr.Element
		res.Add(&x[0], &x[1])
		res.Add(&res, &x[2])
		return res
	}, 3, 1)

	testGate("mul2", func(x ...fr.Element) fr.Element {
		var res fr.Element
		res.Mul(&x[0], &x[1])
		return res
	}, 2, 2)

	testGate("mimc", mimcRound, 2, 7)

	testGate("sub2PlusOne", func(x ...fr.Element) fr.Element {
		var res fr.Element
		res.
			SetOne().
			Add(&res, &x[0]).
			Sub(&res, &x[1])
		return res
	}, 2, 1)

	// zero polynomial must not be accepted
	t.Run("zero", func(t *testing.T) {
		const gateName GateName = "zero-register-gate-test"
		expectedError := fmt.Errorf("for gate %s: %v", gateName, errZeroFunction)
		zeroGate := func(x ...fr.Element) fr.Element {
			var res fr.Element
			return res
		}
		assert.Equal(t, expectedError, RegisterGate(gateName, zeroGate, 1))

		assert.Equal(t, expectedError, RegisterGate(gateName, zeroGate, 1, WithDegree(2)))
	})
}

func TestIsAdditive(t *testing.T) {

	// f: x,y -> x² + xy
	f := func(x ...fr.Element) fr.Element {
		if len(x) != 2 {
			panic("bivariate input needed")
		}
		var res fr.Element
		res.Add(&x[0], &x[1])
		res.Mul(&res, &x[0])
		return res
	}

	// g: x,y -> x² + 3y
	g := func(x ...fr.Element) fr.Element {
		var res, y3 fr.Element
		res.Square(&x[0])
		y3.Mul(&x[1], &three)
		res.Add(&res, &y3)
		return res
	}

	// h: x -> 2x
	// but it edits it input
	h := func(x ...fr.Element) fr.Element {
		x[0].Double(&x[0])
		return x[0]
	}

	assert.False(t, GateFunction(f).isAdditive(1, 2))
	assert.False(t, GateFunction(f).isAdditive(0, 2))

	assert.False(t, GateFunction(g).isAdditive(0, 2))
	assert.True(t, GateFunction(g).isAdditive(1, 2))

	assert.True(t, GateFunction(h).isAdditive(0, 1))
}
