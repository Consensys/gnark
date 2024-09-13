package gkrnonative

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	fpbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fp"

	"github.com/consensys/gnark/frontend"
	// "github.com/consensys/gnark/frontend/cs/scs"
	// "github.com/consensys/gnark/profile"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/std/recursion"
	"github.com/consensys/gnark/std/recursion/gkr/utils"
	"github.com/consensys/gnark/std/recursion/sumcheck"
	"github.com/consensys/gnark/test"
)

type GkrVerifierCircuitEmulated[FR emulated.FieldParams] struct {
	Input           [][]emulated.Element[FR]
	Output          [][]emulated.Element[FR] `gnark:",public"`
	SerializedProof []emulated.Element[FR]
	ToFail          bool
	TestCaseName    string
}

func makeInOutAssignmentBundle[FR emulated.FieldParams](c CircuitBundleEmulated[FR], inputValues [][]emulated.Element[FR], outputValues [][]emulated.Element[FR]) WireAssignmentBundleEmulated[FR] {
	sorted := topologicalSortBundleEmulated(c)
	res := make(WireAssignmentBundleEmulated[FR], len(sorted))
	for _, w := range sorted {
		if w.IsInput() {
			res[w] = make(WireAssignmentEmulated[FR], len(w.Inputs))
			for _, wire := range w.Inputs {
				res[w][wireKey(wire)] = inputValues[wire.WireIndex]
			}
		} else if w.IsOutput() {
			res[w] = make(WireAssignmentEmulated[FR], len(w.Outputs))
			for _, wire := range w.Outputs {
				res[w][wireKey(wire)] = outputValues[wire.WireIndex]
			}
		}
	}
	return res
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

	if proof, err = DeserializeProofBundle(sorted, c.SerializedProof); err != nil {
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

func testMultipleDblAddSelectGKRInstance[FR emulated.FieldParams](t *testing.T, current *big.Int, target *big.Int, inputs [][]*big.Int, outputs [][]*big.Int, depth int) {
	selector := []*big.Int{big.NewInt(1)}
	c := make(CircuitBundle, depth + 1)
	c[0] = InitFirstWireBundle(len(inputs), len(c))
	for i := 1; i < depth + 1; i++ {
		c[i] = NewWireBundle(
			sumcheck.DblAddSelectGateFullOutput[*sumcheck.BigIntEngine, *big.Int]{Selector: selector[0]},
			c[i-1].Outputs,
			i,
			len(c),
		)
	}

	selectorEmulated := make([]emulated.Element[FR], len(selector))
	for i, f := range selector {
		selectorEmulated[i] = emulated.ValueOf[FR](f)
	}

	cEmulated := make(CircuitBundleEmulated[FR], len(c))
	cEmulated[0] = InitFirstWireBundleEmulated[FR](len(inputs), len(c))
	for i := 1; i < depth + 1; i++ {
		cEmulated[i] = NewWireBundleEmulated(
			sumcheck.DblAddSelectGateFullOutput[*sumcheck.EmuEngine[FR], *emulated.Element[FR]]{Selector: &selectorEmulated[0]},
			c[i-1].Outputs,
			i,
			len(c),
		)
	}

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

	t.Log("Circuit evaluation complete")
	proof, err := Prove(current, target, c, fullAssignment, fiatshamir.WithHashBigInt(hash))
	assert.NoError(err)
	t.Log("Proof complete")
	
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

	// p := profile.Start()
	// _, _ = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, validCircuit)
	// p.Stop()

	// fmt.Println(p.NbConstraints())
}

func TestMultipleDblAddSelectGKR(t *testing.T) {
	var P1 bn254.G1Affine
	var one fpbn254.Element
	one.SetOne() 
	var zero fpbn254.Element
	zero.SetZero()
	var random fpbn254.Element

	depth := 64
	arity := 6
	nBInstances := 2048
	var fp emparams.BN254Fp
	be := sumcheck.NewBigIntEngine(fp.Modulus())
	gate := sumcheck.DblAddSelectGateFullOutput[*sumcheck.BigIntEngine, *big.Int]{Selector: big.NewInt(1)}

	res := make([][]*big.Int, nBInstances)
	gateInputs := make([][]*big.Int, nBInstances)
	for i := 0; i < nBInstances; i++ {
		random.SetRandom()
		element := P1.ScalarMultiplicationBase(random.BigInt(new(big.Int)))
		gateInputs[i] = []*big.Int{ElementToBigInt(element.X), ElementToBigInt(element.Y), ElementToBigInt(one), ElementToBigInt(zero), ElementToBigInt(one), ElementToBigInt(zero)}
		inputLayer := gateInputs[i]
		for j := 0; j < depth; j++ {
			res[i] = gate.Evaluate(be, inputLayer...)
			inputLayer = res[i]
		}
	}

	inputs := make([][]*big.Int, arity)
	outputs := make([][]*big.Int, arity)
	for i := 0; i < arity; i++ {
		inputs[i] = make([]*big.Int, nBInstances)
		outputs[i] = make([]*big.Int, nBInstances)
		for j := 0; j < nBInstances; j++ {
			inputs[i][j] = gateInputs[j][i]
			outputs[i][j] = res[j][i]
		}
	}

	testMultipleDblAddSelectGKRInstance[emparams.BN254Fp](t, ecc.BN254.ScalarField(), fp.Modulus(), inputs, outputs, depth)

}
