package sumcheck

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	gohash "hash"
	"math"
	"os"
	"path/filepath"
	"reflect"

	//"strconv"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/std/recursion/gkr/utils"

	// "github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/recursion"
	"github.com/consensys/gnark/std/recursion/sumcheck"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
)

// type FR = emulated.BN254Fp

var Gates = map[string]Gate{
	"identity": IdentityGate[*sumcheck.BigIntEngine, *big.Int]{},
	"add":      AddGate[*sumcheck.BigIntEngine, *big.Int]{},
	"mul":      MulGate[*sumcheck.BigIntEngine, *big.Int]{},
}

// func TestNoGateTwoInstances(t *testing.T) {
// 	// Testing a single instance is not possible because the sumcheck implementation doesn't cover the trivial 0-variate case
// 	testNoGate(t, []emulated.Element[FR]{four, three})
// }

// func TestNoGate(t *testing.T) {
// 	testManyInstances(t, 1, testNoGate)
// }


// func TestSingleAddGate(t *testing.T) {
// 	testManyInstances(t, 2, testSingleAddGate)
// }

// func TestSingleMulGateTwoInstances(t *testing.T) {
// 	testSingleMulGate(t, []emulated.Element[FR]{four, three}, []emulated.Element[FR]{two, three})
// }

// func TestSingleMulGate(t *testing.T) {
// 	testManyInstances(t, 2, testSingleMulGate)
// }

// func TestSingleInputTwoIdentityGatesTwoInstances(t *testing.T) {

// 	testSingleInputTwoIdentityGates(t, []fr.Element{two, three})
// }

// func TestSingleInputTwoIdentityGates(t *testing.T) {

// 	testManyInstances(t, 2, testSingleInputTwoIdentityGates)
// }

// func TestSingleInputTwoIdentityGatesComposedTwoInstances(t *testing.T) {
// 	testSingleInputTwoIdentityGatesComposed(t, []fr.Element{two, one})
// }

// func TestSingleInputTwoIdentityGatesComposed(t *testing.T) {
// 	testManyInstances(t, 1, testSingleInputTwoIdentityGatesComposed)
// }

// func TestSingleMimcCipherGateTwoInstances(t *testing.T) {
// 	testSingleMimcCipherGate(t, []fr.Element{one, one}, []fr.Element{one, two})
// }

// func TestSingleMimcCipherGate(t *testing.T) {
// 	testManyInstances(t, 2, testSingleMimcCipherGate)
// }

// func TestATimesBSquaredTwoInstances(t *testing.T) {
// 	testATimesBSquared(t, 2, []fr.Element{one, one}, []fr.Element{one, two})
// }

// func TestShallowMimcTwoInstances(t *testing.T) {
// 	testMimc(t, 2, []fr.Element{one, one}, []fr.Element{one, two})
// }
// func TestMimcTwoInstances(t *testing.T) {
// 	testMimc(t, 93, []fr.Element{one, one}, []fr.Element{one, two})
// }

// func TestMimc(t *testing.T) {
// 	testManyInstances(t, 2, generateTestMimc(93))
// }

// func generateTestMimc(numRounds int) func(*testing.T, ...[]fr.Element) {
// 	return func(t *testing.T, inputAssignments ...[]fr.Element) {
// 		testMimc(t, numRounds, inputAssignments...)
// 	}
// }

// func TestSumcheckFromSingleInputTwoIdentityGatesGateTwoInstances(t *testing.T) {
// 	circuit := Circuit{Wire{
// 		Gate:            IdentityGate{},
// 		Inputs:          []*Wire{},
// 		nbUniqueOutputs: 2,
// 	}}

// 	wire := &circuit[0]

// 	assignment := WireAssignment{&circuit[0]: []fr.Element{two, three}}
// 	var o settings
// 	pool := polynomial.NewPool(256, 1<<11)
// 	workers := utils.NewWorkerPool()
// 	o.pool = &pool
// 	o.workers = workers

// 	claimsManagerGen := func() *claimsManager {
// 		manager := newClaimsManager(circuit, assignment, o)
// 		manager.add(wire, []fr.Element{three}, five)
// 		manager.add(wire, []fr.Element{four}, six)
// 		return &manager
// 	}

// 	transcriptGen := utils.NewMessageCounterGenerator(4, 1)

// 	proof, err := sumcheck.Prove(claimsManagerGen().getClaim(wire), fiatshamir.WithHash(transcriptGen(), nil))
// 	assert.NoError(t, err)
// 	err = sumcheck.Verify(claimsManagerGen().getLazyClaim(wire), proof, fiatshamir.WithHash(transcriptGen(), nil))
// 	assert.NoError(t, err)
// }

var one, two, three, four, five, six big.Int

// func init() {
// 	one.SetOne()
// 	two.Double(&one)
// 	three.Add(&two, &one)
// 	four.Double(&two)
// 	five.Add(&three, &two)
// 	six.Double(&three)
// }

// var testManyInstancesLogMaxInstances = -1

// func getLogMaxInstances(t *testing.T) int {
// 	if testManyInstancesLogMaxInstances == -1 {

// 		s := os.Getenv("GKR_LOG_INSTANCES")
// 		if s == "" {
// 			testManyInstancesLogMaxInstances = 5
// 		} else {
// 			var err error
// 			testManyInstancesLogMaxInstances, err = strconv.Atoi(s)
// 			if err != nil {
// 				t.Error(err)
// 			}
// 		}

// 	}
// 	return testManyInstancesLogMaxInstances
// }

// func testManyInstances(t *testing.T, numInput int, test func(*testing.T, ...[]emulated.Element[FR])) {
// 	fullAssignments := make([][]emulated.Element[FR], numInput)
// 	maxSize := 1 << getLogMaxInstances(t)

// 	t.Log("Entered test orchestrator, assigning and randomizing inputs")

// 	for i := range fullAssignments {
// 		fullAssignments[i] = make([]emulated.Element[FR], maxSize)
// 		setRandom(fullAssignments[i])
// 	}

// 	inputAssignments := make([][]emulated.Element[FR], numInput)
// 	for numEvals := maxSize; numEvals <= maxSize; numEvals *= 2 {
// 		for i, fullAssignment := range fullAssignments {
// 			inputAssignments[i] = fullAssignment[:numEvals]
// 		}

// 		t.Log("Selected inputs for test")
// 		test(t, inputAssignments...)
// 	}
// }

// func testNoGate(t *testing.T, inputAssignments ...[]*big.Int) {
// 	c := Circuit{
// 		{
// 			Inputs: []*Wire{},
// 			Gate:   nil,
// 		},
// 	}

// 	assignment := WireAssignment{&c[0]: sumcheck.NativeMultilinear(inputAssignments[0])}
// 	assignmentEmulated := WireAssignmentEmulated[FR]{&c[0]: sumcheck.NativeMultilinear(inputAssignments[0])}

// 	proof, err := Prove(c, assignment, fiatshamir.WithHash(utils.NewMessageCounter(1, 1)))
// 	assert.NoError(t, err)

// 	// Even though a hash is called here, the proof is empty

// 	err = Verify(c, assignment, proof, fiatshamir.WithHash(utils.NewMessageCounter(1, 1)))
// 	assert.NoError(t, err, "proof rejected")
// }

func toEmulated[FR emulated.FieldParams](input [][]*big.Int) [][]emulated.Element[FR] {
	output := make([][]emulated.Element[FR], len(input))
	for i, in := range input {
		output[i] = make([]emulated.Element[FR], len(in))
		for j, in2 := range in {
			output[i][j] = emulated.ValueOf[FR](*in2)
		}
	}
	return output
}

func TestSingleAddGateTwoInstances(t *testing.T) {
	current := ecc.BN254.ScalarField()
	type FR = emulated.BN254Fp
	var fr FR
	testSingleAddGate[FR](t, current, fr.Modulus(), []*big.Int{&four, &three}, []*big.Int{&two, &three})
}

func testSingleAddGate[FR emulated.FieldParams](t *testing.T, current *big.Int, target *big.Int, inputAssignments ...[]*big.Int) {
	c := make(Circuit, 3)
	c[2] = Wire{
		Gate:   Gates["add"],
		Inputs: []*Wire{&c[0], &c[1]},
	}

	be := sumcheck.NewBigIntEngine(current)
	output := make([][]*big.Int, len(inputAssignments))
	for i, in := range inputAssignments {
		output[i] = make([]*big.Int, len(in))
		for j, in2 := range in {
			output[i][j] = Gates["add"].Evaluate(be, in2)
		}
	}

	assignment := WireAssignment{&c[0]: inputAssignments[0], &c[1]: inputAssignments[1]}.Complete(c, target)

	proof, err := Prove(current, target, c, assignment, fiatshamir.WithHashBigInt(utils.NewMessageCounter(1, 1)))
	assert.NoError(t, err)
 
	proofEmulated := make(Proofs[FR], len(proof))
	for i, proof := range proof {
		proofEmulated[i] = sumcheck.ValueOfProof[FR](proof)
	}

	assignmentGkr := &GkrVerifierCircuitEmulated[FR]{
		Input:           toEmulated[FR](inputAssignments),
		Output:          toEmulated[FR](output),
		SerializedProof: proofEmulated.Serialize(),
		ToFail:          false,
	}

	validCircuit := &GkrVerifierCircuitEmulated[FR]{
		Input:           make([][]emulated.Element[FR], len(toEmulated[FR](inputAssignments))),
		Output:          make([][]emulated.Element[FR], len(toEmulated[FR](output))),
		SerializedProof: make([]emulated.Element[FR], len(proofEmulated)),
		ToFail:          false,
	}	

	err = test.IsSolved(validCircuit, assignmentGkr, current)
	assert.NoError(t, err)

	_, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, validCircuit)
	assert.NoError(t, err)


	//t.Run("testSingleAddGate", generateVerifier(toEmulated(inputAssignments), toEmulated(output), proofEmulated))

	// err = Verify(c, assignment, proof, fiatshamir.WithHash(utils.NewMessageCounter(1, 1)))
	// assert.NoError(t, err, "proof rejected")

	// err = Verify(c, assignment, proof, fiatshamir.WithHash(utils.NewMessageCounter(0, 1)))
	// assert.NotNil(t, err, "bad proof accepted")
}

// func TestMulGate1Sumcheck(t *testing.T) {
// 	testMulGate1SumcheckInstance[emparams.BN254Fr](t, ecc.BN254.ScalarField(), [][]int{{4, 3}, {2, 3}})
// 	testMulGate1SumcheckInstance[emparams.BN254Fr](t, ecc.BN254.ScalarField(), [][]int{{1, 2, 3, 4}, {5, 6, 7, 8}})
// 	testMulGate1SumcheckInstance[emparams.BN254Fr](t, ecc.BN254.ScalarField(), [][]int{{1, 2, 3, 4, 5, 6, 7, 8}, {11, 12, 13, 14, 15, 16, 17, 18}})
// 	inputs := [][]int{{1}, {2}}
// 	for i := 1; i < (1 << 10); i++ {
// 		inputs[0] = append(inputs[0], inputs[0][i-1]+1)
// 		inputs[1] = append(inputs[1], inputs[1][i-1]+2)
// 	}
// 	testMulGate1SumcheckInstance[emparams.BN254Fr](t, ecc.BN254.ScalarField(), inputs)
// }

// func testSingleMulGate(t *testing.T, inputAssignments ...[]fr.Element) {

// 	c := make(Circuit, 3)
// 	c[2] = Wire{
// 		Gate:   Gates["mul"],
// 		Inputs: []*Wire{&c[0], &c[1]},
// 	}

// 	assignment := WireAssignment{&c[0]: inputAssignments[0], &c[1]: inputAssignments[1]}.Complete(c)

// 	proof, err := Prove(c, assignment, fiatshamir.WithHash(utils.NewMessageCounter(1, 1)))
// 	assert.NoError(t, err)

// 	err = Verify(c, assignment, proof, fiatshamir.WithHash(utils.NewMessageCounter(1, 1)))
// 	assert.NoError(t, err, "proof rejected")

// 	err = Verify(c, assignment, proof, fiatshamir.WithHash(utils.NewMessageCounter(0, 1)))
// 	assert.NotNil(t, err, "bad proof accepted")
// }

// func testSingleInputTwoIdentityGates(t *testing.T, inputAssignments ...[]fr.Element) {
// 	c := make(Circuit, 3)

// 	c[1] = Wire{
// 		Gate:   IdentityGate{},
// 		Inputs: []*Wire{&c[0]},
// 	}

// 	c[2] = Wire{
// 		Gate:   IdentityGate{},
// 		Inputs: []*Wire{&c[0]},
// 	}

// 	assignment := WireAssignment{&c[0]: inputAssignments[0]}.Complete(c)

// 	proof, err := Prove(c, assignment, fiatshamir.WithHash(utils.NewMessageCounter(0, 1)))
// 	assert.NoError(t, err)

// 	err = Verify(c, assignment, proof, fiatshamir.WithHash(utils.NewMessageCounter(0, 1)))
// 	assert.NoError(t, err, "proof rejected")

// 	err = Verify(c, assignment, proof, fiatshamir.WithHash(utils.NewMessageCounter(1, 1)))
// 	assert.NotNil(t, err, "bad proof accepted")
// }

// func testSingleMimcCipherGate(t *testing.T, inputAssignments ...[]fr.Element) {
// 	c := make(Circuit, 3)

// 	c[2] = Wire{
// 		Gate:   mimcCipherGate{},
// 		Inputs: []*Wire{&c[0], &c[1]},
// 	}

// 	t.Log("Evaluating all circuit wires")
// 	assignment := WireAssignment{&c[0]: inputAssignments[0], &c[1]: inputAssignments[1]}.Complete(c)
// 	t.Log("Circuit evaluation complete")
// 	proof, err := Prove(c, assignment, fiatshamir.WithHash(utils.NewMessageCounter(0, 1)))
// 	assert.NoError(t, err)
// 	t.Log("Proof complete")
// 	err = Verify(c, assignment, proof, fiatshamir.WithHash(utils.NewMessageCounter(0, 1)))
// 	assert.NoError(t, err, "proof rejected")

// 	t.Log("Successful verification complete")
// 	err = Verify(c, assignment, proof, fiatshamir.WithHash(utils.NewMessageCounter(1, 1)))
// 	assert.NotNil(t, err, "bad proof accepted")
// 	t.Log("Unsuccessful verification complete")
// }

// func testSingleInputTwoIdentityGatesComposed(t *testing.T, inputAssignments ...[]fr.Element) {
// 	c := make(Circuit, 3)

// 	c[1] = Wire{
// 		Gate:   IdentityGate{},
// 		Inputs: []*Wire{&c[0]},
// 	}
// 	c[2] = Wire{
// 		Gate:   IdentityGate{},
// 		Inputs: []*Wire{&c[1]},
// 	}

// 	assignment := WireAssignment{&c[0]: inputAssignments[0]}.Complete(c)

// 	proof, err := Prove(c, assignment, fiatshamir.WithHash(utils.NewMessageCounter(0, 1)))
// 	assert.NoError(t, err)

// 	err = Verify(c, assignment, proof, fiatshamir.WithHash(utils.NewMessageCounter(0, 1)))
// 	assert.NoError(t, err, "proof rejected")

// 	err = Verify(c, assignment, proof, fiatshamir.WithHash(utils.NewMessageCounter(1, 1)))
// 	assert.NotNil(t, err, "bad proof accepted")
// }

// func mimcCircuit(numRounds int) Circuit {
// 	c := make(Circuit, numRounds+2)

// 	for i := 2; i < len(c); i++ {
// 		c[i] = Wire{
// 			Gate:   mimcCipherGate{},
// 			Inputs: []*Wire{&c[i-1], &c[0]},
// 		}
// 	}
// 	return c
// }

// func testMimc(t *testing.T, numRounds int, inputAssignments ...[]fr.Element) {
// 	// TODO: Implement mimc correctly. Currently, the computation is mimc(a,b) = cipher( cipher( ... cipher(a, b), b) ..., b)
// 	// @AlexandreBelling: Please explain the extra layers in https://github.com/ConsenSys/gkr-mimc/blob/81eada039ab4ed403b7726b535adb63026e8011f/examples/mimc.go#L10

// 	c := mimcCircuit(numRounds)

// 	t.Log("Evaluating all circuit wires")
// 	assignment := WireAssignment{&c[0]: inputAssignments[0], &c[1]: inputAssignments[1]}.Complete(c)
// 	t.Log("Circuit evaluation complete")

// 	proof, err := Prove(c, assignment, fiatshamir.WithHash(utils.NewMessageCounter(0, 1)))
// 	assert.NoError(t, err)

// 	t.Log("Proof finished")
// 	err = Verify(c, assignment, proof, fiatshamir.WithHash(utils.NewMessageCounter(0, 1)))
// 	assert.NoError(t, err, "proof rejected")

// 	t.Log("Successful verification finished")
// 	err = Verify(c, assignment, proof, fiatshamir.WithHash(utils.NewMessageCounter(1, 1)))
// 	assert.NotNil(t, err, "bad proof accepted")
// 	t.Log("Unsuccessful verification finished")
// }

// func testATimesBSquared(t *testing.T, numRounds int, inputAssignments ...[]fr.Element) {
// 	// This imitates the MiMC circuit

// 	c := make(Circuit, numRounds+2)

// 	for i := 2; i < len(c); i++ {
// 		c[i] = Wire{
// 			Gate:   Gates["mul"],
// 			Inputs: []*Wire{&c[i-1], &c[0]},
// 		}
// 	}

// 	assignment := WireAssignment{&c[0]: inputAssignments[0], &c[1]: inputAssignments[1]}.Complete(c)

// 	proof, err := Prove(c, assignment, fiatshamir.WithHash(utils.NewMessageCounter(0, 1)))
// 	assert.NoError(t, err)

// 	err = Verify(c, assignment, proof, fiatshamir.WithHash(utils.NewMessageCounter(0, 1)))
// 	assert.NoError(t, err, "proof rejected")

// 	err = Verify(c, assignment, proof, fiatshamir.WithHash(utils.NewMessageCounter(1, 1)))
// 	assert.NotNil(t, err, "bad proof accepted")
// }

// func setRandom(slice []fr.Element) {
// 	for i := range slice {
// 		slice[i].SetRandom()
// 	}
// }
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

			t.Run(noExt, generateTestProver(path, *current, *fr.Modulus()))
			t.Run(noExt, generateTestVerifier[emparams.BN254Fp](path))
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

func generateVerifier[FR emulated.FieldParams](Input [][]emulated.Element[FR], Output [][]emulated.Element[FR], Proof Proofs[FR]) func(t *testing.T) {

	return func(t *testing.T) {

		assert := test.NewAssert(t)

		assignment := &GkrVerifierCircuitEmulated[FR]{
			Input:           Input,
			Output:          Output,
			SerializedProof: Proof.Serialize(),
			ToFail:          false,
		}

		validCircuit := &GkrVerifierCircuitEmulated[FR]{
			Input:           make([][]emulated.Element[FR], len(Input)),
			Output:          make([][]emulated.Element[FR], len(Output)),
			SerializedProof: make([]emulated.Element[FR], len(assignment.SerializedProof)),
			ToFail:          false,
		}

		invalidCircuit := &GkrVerifierCircuitEmulated[FR]{
			Input:           make([][]emulated.Element[FR], len(Input)),
			Output:          make([][]emulated.Element[FR], len(Output)),
			SerializedProof: make([]emulated.Element[FR], len(assignment.SerializedProof)),
			ToFail:          true,
		}

		fillWithBlanks(validCircuit.Input, len(Input[0]))
		fillWithBlanks(validCircuit.Output, len(Input[0]))
		fillWithBlanks(invalidCircuit.Input, len(Input[0]))
		fillWithBlanks(invalidCircuit.Output, len(Input[0]))

		assert.CheckCircuit(validCircuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.WithValidAssignment(assignment))
		//test.IsSolved(validCircuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.WithValidAssignment(assignment))
		// assert.CheckCircuit(invalidCircuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.WithInvalidAssignment(assignment))
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

func generateTestVerifier[FR emulated.FieldParams](path string, options ...option) func(t *testing.T) {
	var opts _options
	for _, opt := range options {
		opt(&opts)
	}

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

		invalidCircuit := &GkrVerifierCircuitEmulated[FR]{
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
			assert.CheckCircuit(validCircuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.WithValidAssignment(assignment))
		}

		// if !opts.noFail {
		// 	assert.CheckCircuit(invalidCircuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.WithInvalidAssignment(assignment))
		// }
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

	println("c.TestCaseName", c.TestCaseName)
	// var proofRef Proof
	if testCase, err = getTestCase[FR](c.TestCaseName); err != nil {
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
	Circuit string                 `json:"circuit"`
	Input   [][]interface{}       `json:"input"`
	Output  [][]interface{} `json:"output"`
	Proof   PrintableProof  `json:"proof"`
}

// var testCases = make(map[string]*TestCase[emulated.FieldParams])
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
			circuit, err = toCircuitEmulated[FR](circuitInfo)
			if err == nil {
				circuitCache[path] = circuit
			}
		}
	}
	return
}

func toCircuitEmulated[FR emulated.FieldParams](c CircuitInfo) (circuit CircuitEmulated[FR], err error) {
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

type _select[FR emulated.FieldParams] int

// func init() {
// 	var GatesEmulated = map[string]GateEmulated[FR]{
// 		"identity": IdentityGate[*sumcheck.EmuEngine[FR], *emulated.Element[FR]]{},
// 		"add":      AddGate[*sumcheck.EmuEngine[FR], *emulated.Element[FR]]{},
// 		"mul":      MulGate[*sumcheck.EmuEngine[FR], *emulated.Element[FR]]{},
// 	}
	
// 	GatesEmulated["select-input-3"] = _select[FR](2)
// }

func (g _select[FR]) Evaluate(_ *sumcheck.EmuEngine[FR], in ...*emulated.Element[FR]) *emulated.Element[FR] {
	return in[g]
}

func (g _select[FR]) Degree() int {
	return 1
}

type PrintableProof []PrintableSumcheckProof

type PrintableSumcheckProof struct {
	FinalEvalProof       interface{}     `json:"finalEvalProof"`
	RoundPolyEvaluations [][]interface{} `json:"roundPolyEvaluations"`
}

func unmarshalProof(printable PrintableProof) (proof NativeProofs) {
	proof = make(NativeProofs, len(printable))
	for i := range printable {

		if printable[i].FinalEvalProof != nil {
			finalEvalSlice := reflect.ValueOf(printable[i].FinalEvalProof)
			finalEvalProof := make(sumcheck.NativeDeferredEvalProof, finalEvalSlice.Len())
			for k := range finalEvalProof {
				finalEvalSlice := finalEvalSlice.Index(k).Interface().([]interface{})
				var byteArray []byte
				for _, val := range finalEvalSlice {
					floatVal := val.(float64)
					bits := math.Float64bits(floatVal)
					bytes := make([]byte, 8)
					binary.BigEndian.PutUint64(bytes, bits)
					byteArray = append(byteArray, bytes...)
				}
				finalEvalProof[k] = *big.NewInt(0).SetBytes(byteArray)
			}
			proof[i].FinalEvalProof = finalEvalProof
		} else {
			proof[i].FinalEvalProof = nil
		}

		proof[i].RoundPolyEvaluations = make([]sumcheck.NativePolynomial, len(printable[i].RoundPolyEvaluations))
		for k := range printable[i].RoundPolyEvaluations {
			evals := printable[i].RoundPolyEvaluations[k]
			proof[i].RoundPolyEvaluations[k] = make(sumcheck.NativePolynomial, len(evals))
			for j, eval := range evals {
				evalSlice := reflect.ValueOf(eval).Interface().([]interface{})
				var byteArray []byte
				for _, val := range evalSlice {
					floatVal := val.(float64)
					bits := math.Float64bits(floatVal)
					bytes := make([]byte, 8)
					binary.BigEndian.PutUint64(bytes, bits)
					byteArray = append(byteArray, bytes...)
				}
				proof[i].RoundPolyEvaluations[k][j] = big.NewInt(0).SetBytes(byteArray)
			}
		}

	}
	return
}

// func unmarshalProofEmulated[FR emulated.FieldParams](printable PrintableProof) (proof Proofs[FR]) {
// 	proof = make(Proofs[FR], len(printable))
// 	for i := range printable {

// 		if printable[i].FinalEvalProof != nil {
// 			finalEvalSlice := reflect.ValueOf(printable[i].FinalEvalProof)
// 			finalEvalProof := make(sumcheck.DeferredEvalProof[FR], finalEvalSlice.Len())
// 			for k := range finalEvalProof {
// 				finalEvalProof[k] = utils.ToVariableFr[FR](finalEvalSlice.Index(k).Interface())
// 			}
// 			proof[i].FinalEvalProof = finalEvalProof
// 		} else {
// 			proof[i].FinalEvalProof = nil
// 		}

// 		proof[i].RoundPolyEvaluations = make([]polynomial.Univariate[FR], len(printable[i].RoundPolyEvaluations))
// 		for k := range printable[i].RoundPolyEvaluations {
// 			proof[i].RoundPolyEvaluations[k] = utils.ToVariableSliceFr[FR](printable[i].RoundPolyEvaluations[k])
// 		}
// 	}
// 	return
// }

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

// type constHashCircuit struct {
// 	X frontend.Variable
// }

// func (c *constHashCircuit) Define(api frontend.API) error {
// 	hsh := utils.NewMessageCounter(api, 0, 0)
// 	hsh.Reset()
// 	hsh.Write(c.X)
// 	sum := hsh.Sum()
// 	api.AssertIsEqual(sum, 0)
// 	api.AssertIsEqual(api.Mul(c.X, c.X), 1) // ensure we have at least 2 constraints
// 	return nil
// }

// func TestConstHash(t *testing.T) {
// 	test.NewAssert(t).CheckCircuit(
// 		&constHashCircuit{},

// 		test.WithValidAssignment(&constHashCircuit{X: 1}),
// 	)
// }

// var mimcSnarkTotalCalls = 0

// type MiMCCipherGate struct {
// 	Ark frontend.Variable
// }

// func (m MiMCCipherGate) Evaluate(api frontend.API, input ...frontend.Variable) frontend.Variable {
// 	mimcSnarkTotalCalls++

// 	if len(input) != 2 {
// 		panic("mimc has fan-in 2")
// 	}
// 	sum := api.Add(input[0], input[1], m.Ark)

// 	sumCubed := api.Mul(sum, sum, sum) // sum^3
// 	return api.Mul(sumCubed, sumCubed, sum)
// }

// func (m MiMCCipherGate) Degree() int {
// 	return 7
// }

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
// 				if _, err := utils.SetElement(&finalEvalProof[k], finalEvalSlice.Index(k).Interface()); err != nil {
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
// 			if proof[i].PartialSumPolys[k], err = utils.SliceToElementSlice(printable[i].PartialSumPolys[k]); err != nil {
// 				return nil, err
// 			}
// 		}
// 	}
// 	return proof, nil
// }

type TestCase struct {
	Current         big.Int
	Target          big.Int
	Circuit         Circuit
	Hash            gohash.Hash //utils.HashDescription
	Proof           NativeProofs
	FullAssignment  WireAssignment
	InOutAssignment WireAssignment
}

// var testCases = make(map[string]*TestCase)

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
