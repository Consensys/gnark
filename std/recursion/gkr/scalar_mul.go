package gkr

import (
	//"fmt"
	//gohash "hash"
	"math/big"
	"testing"

	//fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/math/emulated"
	//"github.com/consensys/gnark/std/recursion/gkr/utils"
	"github.com/consensys/gnark/std/recursion/sumcheck"
	//"github.com/consensys/gnark/test"
)

func testProjDblAddSelectGKRInstance[FR emulated.FieldParams](t *testing.T, current *big.Int, target *big.Int, inputs [][]int) {
	//var fr FR
	c := make(Circuit, 3)
	c[1] = Wire{
		Gate: sumcheck.DblAddSelectGate[*sumcheck.BigIntEngine, *big.Int]{
			Folding: []*big.Int{
				big.NewInt(1),
				big.NewInt(2),
				big.NewInt(3),
				big.NewInt(4),
				big.NewInt(5),
				big.NewInt(6),
			},
		},
		Inputs: []*Wire{&c[0]},
	}

	// val1 := emulated.ValueOf[FR](1)
	// val2 := emulated.ValueOf[FR](2)
	// val3 := emulated.ValueOf[FR](3)
	// val4 := emulated.ValueOf[FR](4)
	// val5 := emulated.ValueOf[FR](5)
	// val6 := emulated.ValueOf[FR](6)
	// cEmulated := make(CircuitEmulated[FR], len(c))
	// cEmulated[1] = WireEmulated[FR]{
	// 	Gate:  sumcheck.DblAddSelectGate[*sumcheck.EmuEngine[FR], *emulated.Element[FR]]{
	// 		Folding: []*emulated.Element[FR]{
	// 			&val1,
	// 			&val2,
	// 			&val3,
	// 			&val4,
	// 			&val5,
	// 			&val6,
	// 		},
	// 	},
	// 	Inputs: []*WireEmulated[FR]{&cEmulated[0]},
	// }

	// assert := test.NewAssert(t)
	// inputB := make([][]*big.Int, len(inputs))
	// for i := range inputB {
	// 	inputB[i] = make([]*big.Int, len(inputs[i]))
	// 	for j := range inputs[i] {
	// 		inputB[i][j] = big.NewInt(int64(inputs[i][j]))
	// 	}
	// }

	// var hash gohash.Hash
	// hash, err := utils.HashFromDescription(map[string]interface{}{
	// 	"hash": map[string]interface{}{
	// 		"type": "const",
	// 		"val":  -1,
	// 	},
	// })
	// assert.NoError(err)

	// t.Log("Evaluating all circuit wires")
	// assignment := WireAssignment{&c[0]: inputAssignments[0], &c[1]: inputAssignments[1]}.Complete(c, target)
	// t.Log("Circuit evaluation complete")
	// proof, err := Prove(current, target, c, assignment, fiatshamir.WithHashBigInt(hash))
	// assert.NoError(err)
	// fmt.Println(proof)
	// //assert.NoError(proofEquals(testCase.Proof, proof))

	// t.Log("Proof complete")

	// evalPointsB, evalPointsPH, evalPointsC := getChallengeEvaluationPoints[FR](inputB)
	// claim, evals, err := newNativeGate(fr.Modulus(), nativeGate, inputB, evalPointsB)
	// assert.NoError(err)
	// proof, err := Prove(current, fr.Modulus(), claim)
	// assert.NoError(err)
	// nbVars := bits.Len(uint(len(inputs[0]))) - 1
	// circuit := &ProjDblAddSelectSumcheckCircuit[FR]{
	// 	Inputs:           make([][]emulated.Element[FR], len(inputs)),
	// 	Proof:            placeholderGateProof[FR](nbVars, nativeGate.Degree()),
	// 	EvaluationPoints: evalPointsPH,
	// 	Claimed:          make([]emulated.Element[FR], 1),
	// }
	// assignment := &ProjDblAddSelectSumcheckCircuit[FR]{
	// 	Inputs:           make([][]emulated.Element[FR], len(inputs)),
	// 	Proof:            ValueOfProof[FR](proof),
	// 	EvaluationPoints: evalPointsC,
	// 	Claimed:          []emulated.Element[FR]{emulated.ValueOf[FR](evals[0])},
	// }
	// for i := range inputs {
	// 	circuit.Inputs[i] = make([]emulated.Element[FR], len(inputs[i]))
	// 	assignment.Inputs[i] = make([]emulated.Element[FR], len(inputs[i]))
	// 	for j := range inputs[i] {
	// 		assignment.Inputs[i][j] = emulated.ValueOf[FR](inputs[i][j])
	// 	}
	// }
	// err = test.IsSolved(circuit, assignment, current)
	// assert.NoError(err)
}

// func TestProjDblAddSelectSumCheckSumcheck(t *testing.T) {
// 	// testProjDblAddSelectSumCheckInstance[emparams.BN254Fr](t, ecc.BN254.ScalarField(), [][]int{{4, 3}, {2, 3}, {3, 6}, {4, 9}, {13, 3}, {31, 9}})
// 	// testProjDblAddSelectSumCheckInstance[emparams.BN254Fr](t, ecc.BN254.ScalarField(), [][]int{{1, 2, 3, 4}, {5, 6, 7, 8}})
// 	// testProjDblAddSelectSumCheckInstance[emparams.BN254Fr](t, ecc.BN254.ScalarField(), [][]int{{1, 2, 3, 4, 5, 6, 7, 8}, {11, 12, 13, 14, 15, 16, 17, 18}})
// 	inputs := [][]int{{0}, {1}, {2}, {3}, {4}, {5}, {6}}
// 	for i := 1; i < (1 << 14); i++ {
// 		inputs[0] = append(inputs[0], (inputs[0][i-1]-1)*(inputs[0][i-1]-1))
// 		inputs[1] = append(inputs[1], (inputs[0][i-1]+1)*2)
// 		inputs[2] = append(inputs[2], (inputs[1][i-1]+2)*7)
// 		inputs[3] = append(inputs[3], (inputs[2][i-1]+3)*6)
// 		inputs[4] = append(inputs[4], (inputs[3][i-1]+4)*5)
// 		inputs[5] = append(inputs[5], (inputs[4][i-1]+5)*4)
// 		inputs[6] = append(inputs[6], (inputs[5][i-1]+6)*3)
// 	}
// 	testProjDblAddSelectSumCheckInstance[emparams.BN254Fr](t, ecc.BN254.ScalarField(), inputs)
// }
