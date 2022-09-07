package gkr

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/sumcheck"
	"github.com/consensys/gnark/frontend"
	"testing"
)

func TestNoGateTwoInstances(t *testing.T) {
	// Testing a single instance is not possible because the sumcheck implementation doesn't cover the trivial 0-variate case
	testNoGate(t, []frontend.Variable{4, 3})
}

func TestNoGate(t *testing.T) {
	testManyInstances(t, 1, testNoGate)
}

func TestSingleMulGateTwoInstances(t *testing.T) {
	testSingleMulGate(t, []frontend.Variable{4, 3}, []frontend.Variable{2, 3})
}

func TestSingleMulGate(t *testing.T) {
	testManyInstances(t, 2, testSingleMulGate)
}

func TestSingleInputTwoIdentityGatesTwoInstances(t *testing.T) {

	testSingleInputTwoIdentityGates(t, []frontend.Variable{2, 3})
}

func TestSingleInputTwoIdentityGates(t *testing.T) {

	testManyInstances(t, 2, testSingleInputTwoIdentityGates)
}

func TestSingleInputTwoEqualityGatesComposedTwoInstances(t *testing.T) {
	testSingleInputTwoEqualityGatesComposed(t, []frontend.Variable{2, 1})
}

func TestSingleInputTwoEqualityGatesComposed(t *testing.T) {
	testManyInstances(t, 1, testSingleInputTwoEqualityGatesComposed)
}

func TestSingleMimcCipherGateTwoInstances(t *testing.T) {
	testSingleMimcCipherGate(t, []frontend.Variable{1, 1}, []frontend.Variable{1, 2})
}

func TestSingleMimcCipherGate(t *testing.T) {
	testManyInstances(t, 2, testSingleMimcCipherGate)
}

func TestATimesBSquaredTwoInstances(t *testing.T) {
	testATimesBSquared(t, 2, []frontend.Variable{1, 1}, []frontend.Variable{1, 2})
}

func TestShallowMimcTwoInstances(t *testing.T) {
	testMimc(t, 2, []frontend.Variable{1, 1}, []frontend.Variable{1, 2})
}

func TestMimcTwoInstances(t *testing.T) {
	testMimc(t, 93, []frontend.Variable{1, 1}, []frontend.Variable{1, 2})
}

func TestMimc(t *testing.T) {
	testManyInstances(t, 2, generateTestMimc(93))
}

// complete the circuit evaluation from input values
func (a WireAssignment) complete(c Circuit) WireAssignment {
	numEvaluations := len(a[&c[len(c)-1][0]])

	for i := len(c) - 2; i >= 0; i-- { //there can only be input wires in the bottommost layer
		layer := c[i]
		for j := 0; j < len(layer); j++ {
			wire := &layer[j]

			if !wire.IsInput() {
				evals := make([]frontend.Variable, numEvaluations)
				ins := make([]frontend.Variable, len(wire.Inputs))
				for k := 0; k < numEvaluations; k++ {
					for inI, in := range wire.Inputs {
						ins[inI] = a[in][k]
					}
					evals[k] = wire.Gate.Evaluate(ins...)
				}
				a[wire] = evals
			}
		}
	}
	return a
}

func testManyInstances(t *testing.T, numInput int, test func(*testing.T, ...[]frontend.Variable)) {
	fullAssignments := make([][]frontend.Variable, numInput)
	maxSize := 16777216

	t.Log("Entered test orchestrator, assigning and randomizing inputs")

	for i := range fullAssignments {
		fullAssignments[i] = make([]frontend.Variable, maxSize)
		setRandom(fullAssignments[i])
	}

	inputAssignments := make([][]frontend.Variable, numInput)
	for numEvals := maxSize; numEvals <= maxSize; numEvals *= 2 {
		for i, fullAssignment := range fullAssignments {
			inputAssignments[i] = fullAssignment[:numEvals]
		}

		t.Log("Selected inputs for test")
		test(t, inputAssignments...)
	}
}

func testNoGate(t *testing.T, inputAssignments ...[]frontend.Variable) {
	c := Circuit{
		{
			{
				Inputs:     []*Wire{},
				NumOutputs: 1,
				Gate:       nil,
			},
		},
	}

	assignment := WireAssignment{&c[0][0]: inputAssignments[0]}

	proof := Prove(c, assignment, sumcheck.NewMessageCounter(1, 1))

	// Even though a hash is called here, the proof is empty

	if !Verify(c, assignment, proof, sumcheck.NewMessageCounter(1, 1)) {
		t.Error("Proof rejected")
	}
}

func testSingleMulGate(t *testing.T, inputAssignments ...[]frontend.Variable) {
	c := make(Circuit, 2)

	c[1] = CircuitLayer{
		{
			Inputs:     []*Wire{},
			NumOutputs: 1,
			Gate:       nil,
		},
		{
			Inputs:     []*Wire{},
			NumOutputs: 1,
			Gate:       nil,
		},
	}

	c[0] = CircuitLayer{{
		Inputs:     []*Wire{&c[1][0], &c[1][1]},
		NumOutputs: 1,
		Gate:       mulGate{},
	}}

	assignment := WireAssignment{&c[1][0]: inputAssignments[0], &c[1][1]: inputAssignments[1]}.complete(c)

	proof := Prove(c, assignment, sumcheck.NewMessageCounter(1, 1))

	if !Verify(c, assignment, proof, sumcheck.NewMessageCounter(1, 1)) {
		t.Error("Proof rejected")
	}

	if Verify(c, assignment, proof, sumcheck.NewMessageCounter(0, 1)) {
		t.Error("Bad proof accepted")
	}
}

func testSingleInputTwoIdentityGates(t *testing.T, inputAssignments ...[]frontend.Variable) {
	c := make(Circuit, 2)

	c[1] = CircuitLayer{
		{
			Inputs:     []*Wire{},
			NumOutputs: 2,
			Gate:       nil,
		},
	}

	c[0] = CircuitLayer{
		{
			Inputs:     []*Wire{&c[1][0]},
			NumOutputs: 1,
			Gate:       identityGate{},
		},
		{
			Inputs:     []*Wire{&c[1][0]},
			NumOutputs: 1,
			Gate:       identityGate{},
		},
	}

	assignment := WireAssignment{&c[1][0]: inputAssignments[0]}.complete(c)

	proof := Prove(c, assignment, sumcheck.NewMessageCounter(0, 1))

	if !Verify(c, assignment, proof, sumcheck.NewMessageCounter(0, 1)) {
		t.Error("Proof rejected")
	}

	if Verify(c, assignment, proof, sumcheck.NewMessageCounter(1, 1)) {
		t.Error("Bad proof accepted")
	}
}

func testSingleMimcCipherGate(t *testing.T, inputAssignments ...[]frontend.Variable) {
	c := make(Circuit, 2)

	c[1] = CircuitLayer{
		{
			Inputs:     []*Wire{},
			NumOutputs: 1,
			Gate:       nil,
		},
		{
			Inputs:     []*Wire{},
			NumOutputs: 1,
			Gate:       nil,
		},
	}

	c[0] = CircuitLayer{
		{
			Inputs:     []*Wire{&c[1][0], &c[1][1]},
			NumOutputs: 1,
			Gate:       mimcCipherGate{},
		},
	}
	t.Log("Evaluating all circuit wires")
	assignment := WireAssignment{&c[1][0]: inputAssignments[0], &c[1][1]: inputAssignments[1]}.complete(c)
	t.Log("Circuit evaluation complete")
	proof := Prove(c, assignment, sumcheck.NewMessageCounter(0, 1))
	t.Log("Proof complete")
	if !Verify(c, assignment, proof, sumcheck.NewMessageCounter(0, 1)) {
		t.Error("Proof rejected")
	}
	t.Log("Successful verification complete")
	if Verify(c, assignment, proof, sumcheck.NewMessageCounter(1, 1)) {
		t.Error("Bad proof accepted")
	}
	t.Log("Unsuccessful verification complete")
}

func testSingleInputTwoEqualityGatesComposed(t *testing.T, inputAssignments ...[]frontend.Variable) {
	c := make(Circuit, 3)

	c[2] = CircuitLayer{{
		Gate:       nil,
		Inputs:     []*Wire{},
		NumOutputs: 1,
	}}
	c[1] = CircuitLayer{{
		Gate:       identityGate{},
		Inputs:     []*Wire{&c[2][0]},
		NumOutputs: 1,
	}}
	c[0] = CircuitLayer{{
		Gate:       identityGate{},
		Inputs:     []*Wire{&c[1][0]},
		NumOutputs: 1,
	}}

	assignment := WireAssignment{&c[2][0]: inputAssignments[0]}.complete(c)

	proof := Prove(c, assignment, sumcheck.NewMessageCounter(0, 1))

	if !Verify(c, assignment, proof, sumcheck.NewMessageCounter(0, 1)) {
		t.Error("Proof rejected")
	}

	if Verify(c, assignment, proof, sumcheck.NewMessageCounter(1, 1)) {
		t.Error("Bad proof accepted")
	}
}

func generateTestMimc(numRounds int) func(*testing.T, ...[]frontend.Variable) {
	return func(t *testing.T, inputAssignments ...[]frontend.Variable) {
		testMimc(t, numRounds, inputAssignments...)
	}
}

func testMimc(t *testing.T, numRounds int, inputAssignments ...[]frontend.Variable) {
	//TODO: Implement mimc correctly. Currently, the computation is mimc(a,b) = cipher( cipher( ... cipher(a, b), b) ..., b)
	// @AlexandreBelling: Please explain the extra layers in https://github.com/ConsenSys/gkr-mimc/blob/81eada039ab4ed403b7726b535adb63026e8011f/examples/mimc.go#L10

	c := make(Circuit, numRounds+1)

	c[numRounds] = CircuitLayer{
		{
			Inputs:     []*Wire{},
			NumOutputs: 1,
			Gate:       nil,
		},
		{
			Inputs:     []*Wire{},
			NumOutputs: numRounds,
			Gate:       nil,
		},
	}

	for i := numRounds; i > 0; i-- {
		c[i-1] = CircuitLayer{
			{
				Inputs:     []*Wire{&c[i][0], &c[numRounds][1]},
				NumOutputs: 1,
				Gate:       mimcCipherGate{}, //TODO: Put arks in there
			},
		}
	}

	t.Log("Evaluating all circuit wires")
	assignment := WireAssignment{&c[numRounds][0]: inputAssignments[0], &c[numRounds][1]: inputAssignments[1]}.complete(c)
	t.Log("Circuit evaluation complete")

	proof := Prove(c, assignment, sumcheck.NewMessageCounter(0, 1))

	t.Log("Proof finished")
	if !Verify(c, assignment, proof, sumcheck.NewMessageCounter(0, 1)) {
		t.Error("Proof rejected")
	}

	t.Log("Successful verification finished")
	if Verify(c, assignment, proof, sumcheck.NewMessageCounter(1, 1)) {
		t.Error("Bad proof accepted")
	}
	t.Log("Unsuccessful verification finished")
}

func testATimesBSquared(t *testing.T, numRounds int, inputAssignments ...[]frontend.Variable) {
	// This imitates the MiMC circuit

	c := make(Circuit, numRounds+1)

	c[numRounds] = CircuitLayer{
		{
			Inputs:     []*Wire{},
			NumOutputs: 1,
			Gate:       nil,
		},
		{
			Inputs:     []*Wire{},
			NumOutputs: numRounds,
			Gate:       nil,
		},
	}

	for i := numRounds; i > 0; i-- {
		c[i-1] = CircuitLayer{
			{
				Inputs:     []*Wire{&c[i][0], &c[numRounds][1]},
				NumOutputs: 1,
				Gate:       mulGate{},
			},
		}
	}

	assignment := WireAssignment{&c[numRounds][0]: inputAssignments[0], &c[numRounds][1]: inputAssignments[1]}.complete(c)

	proof := Prove(c, assignment, sumcheck.NewMessageCounter(0, 1))

	if !Verify(c, assignment, proof, sumcheck.NewMessageCounter(0, 1)) {
		t.Error("Proof rejected")
	}

	if Verify(c, assignment, proof, sumcheck.NewMessageCounter(1, 1)) {
		t.Error("Bad proof accepted")
	}
}

func setRandom(slice []frontend.Variable) {
	for i := range slice {
		slice[i].SetRandom()
	}
}

type mulGate struct{}

func (m mulGate) Evaluate(element ...frontend.Variable) (result frontend.Variable) {
	result.Mul(&element[0], &element[1])
	return
}

func (m mulGate) Degree() int {
	return 2
}

type mimcCipherGate struct {
	ark frontend.Variable
}

func (m mimcCipherGate) Evaluate(input ...frontend.Variable) (res frontend.Variable) {
	var sum frontend.Variable

	sum.
		Add(&input[0], &input[1]).
		Add(&sum, &m.ark)

	res.Square(&sum)    // sum^2
	res.Mul(&res, &sum) // sum^3
	res.Square(&sum)    //sum^6
	res.Mul(&res, &sum) //sum^7

	return
}

func (m mimcCipherGate) Degree() int {
	return 7
}
