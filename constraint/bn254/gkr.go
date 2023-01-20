package cs

import (
	"encoding/json"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/gkr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/test_vector_utils"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/std/utils/algo_utils"
	"hash"
	"math/big"
)

type gkrSolvingData struct {
	assignments gkr.WireAssignment
	circuit     gkr.Circuit
	memoryPool  polynomial.Pool
}

func convertCircuit(noPtr constraint.GkrCircuit) gkr.Circuit {
	resCircuit := make(gkr.Circuit, len(noPtr))
	for i := range noPtr {
		resCircuit[i].Gate = GkrGateRegistry[noPtr[i].Gate]
		resCircuit[i].Inputs = algo_utils.Map(noPtr[i].Inputs, algo_utils.SlicePtrAt(resCircuit))
	}
	return resCircuit
}

// this module assumes that wire and instance indexes respect dependencies

type gkrAssignment [][]fr.Element //gkrAssignment is indexed wire first, instance second

// assumes assignmentVector is arranged wire first, instance second in order of solution
func gkrSolve(info constraint.GkrInfo, solvingData gkrSolvingData, assignmentVector []*big.Int) gkrAssignment {
	circuit := info.Circuit
	nbInstances := info.NbInstances
	offsets := info.AssignmentOffsets()
	nbDepsResolved := make([]int, len(circuit))
	inputs := make([]fr.Element, info.MaxNIns)

	assignments := make(gkrAssignment, len(circuit))
	for i := range assignments {
		assignments[i] = make([]fr.Element, nbInstances)
	}

	for instanceI := 0; instanceI < nbInstances; instanceI++ {
		//fmt.Println("instance", instanceI)
		for wireI, wire := range circuit {
			//fmt.Print("\twire ", wireI, ": ")
			if wire.IsInput() {
				//fmt.Print("input.")
				if nbDepsResolved[wireI] < len(wire.Dependencies) && instanceI == wire.Dependencies[nbDepsResolved[wireI]].InputInstance {
					//fmt.Print(" copying value from dependency")
					dep := wire.Dependencies[nbDepsResolved[wireI]]
					assignments[wireI][instanceI].Set(&assignments[dep.OutputWire][dep.OutputInstance])
					nbDepsResolved[wireI]++
				} else {
					//fmt.Print(" taking value from input")
					assignments[wireI][instanceI].SetBigInt(assignmentVector[offsets[wireI]+instanceI-nbDepsResolved[wireI]])
				}
			} else {
				//fmt.Print("gated.")
				// assemble the inputs
				inputIndexes := info.Circuit[wireI].Inputs
				for i, inputI := range inputIndexes {
					inputs[i].Set(&assignments[inputI][instanceI])
				}
				gate := solvingData.circuit[wireI].Gate
				assignments[wireI][instanceI] = gate.Evaluate(inputs[:len(inputIndexes)]...)
			}
			//fmt.Println("\n\t\tresult: ", assignments[wireI][instanceI].Text(10))
		}
	}
	return assignments
}

func toMapAssignment(circuit gkr.Circuit, assignment gkrAssignment) gkr.WireAssignment {
	res := make(gkr.WireAssignment, len(circuit))
	for i := range circuit {
		res[&circuit[i]] = assignment[i]
	}
	return res
}

func gkrSetOutputValues(circuit []constraint.GkrWire, assignments gkrAssignment, outs []*big.Int) {
	outsI := 0
	for i := range circuit {
		if circuit[i].IsOutput() {
			for j := range assignments[i] {
				assignments[i][j].BigInt(outs[outsI])
				outsI++
			}
		}
	}
	// Check if outsI == len(outs)?
}

func gkrSolveHint(data constraint.GkrInfo, res *gkrSolvingData) hint.Function {
	return func(_ *big.Int, ins, outs []*big.Int) error {

		res.circuit = convertCircuit(data.Circuit) // TODO: Take this out of here into the proving module
		res.memoryPool = polynomial.NewPool(256, data.NbInstances)

		assignments := gkrSolve(data, *res, ins)
		res.assignments = toMapAssignment(res.circuit, assignments)
		gkrSetOutputValues(data.Circuit, assignments, outs)

		//fmt.Println("assignment ", sliceSliceToString(assignments))
		//fmt.Println("returning ", bigIntPtrSliceToString(outs))

		return nil
	}
}

func bigIntPtrSliceToString(slice []*big.Int) []interface{} {
	return algo_utils.Map(slice, func(e *big.Int) interface{} {
		if e.IsInt64() {
			return e.Int64()
		} else {
			return e.Text(10)
		}
	})
}

func sliceSliceToString(slice [][]fr.Element) string {
	printable := make([]interface{}, len(slice))
	for i, s := range slice {
		printable[i] = test_vector_utils.ElementSliceToInterfaceSlice(s)
	}
	res, err := json.Marshal(printable)
	if err != nil {
		panic(err.Error())
	}
	return string(res)
}

func frToBigInts(dst []*big.Int, src []fr.Element) {
	for i := range src {
		src[i].BigInt(dst[i])
	}
}

func gkrProveHint(hashName string, data *gkrSolvingData) hint.Function {

	return func(_ *big.Int, ins, outs []*big.Int) error {
		insBytes := algo_utils.Map(ins[1:], func(i *big.Int) []byte { // the first input is dummy, just to ensure the solver's work is done before the prover is called
			b := i.Bytes()
			return b[:]
		})

		hsh := HashBuilderRegistry[hashName]()

		proof, err := gkr.Prove(data.circuit, data.assignments, fiatshamir.WithHash(hsh, insBytes...), gkr.WithPool(&data.memoryPool)) // TODO: Do transcriptSettings properly
		if err != nil {
			return err
		}

		// serialize proof: TODO: In gnark-crypto?
		offset := 0
		for i := range proof {
			for _, poly := range proof[i].PartialSumPolys {
				frToBigInts(outs[offset:], poly)
				offset += len(poly)
			}
			if proof[i].FinalEvalProof != nil {
				finalEvalProof := proof[i].FinalEvalProof.([]fr.Element)
				frToBigInts(outs[offset:], finalEvalProof)
				offset += len(finalEvalProof)
			}
		}
		return nil

	}
}

func defineGkrHints(info constraint.GkrInfo, hintFunctions map[hint.ID]hint.Function) map[hint.ID]hint.Function {
	res := make(map[hint.ID]hint.Function, len(hintFunctions)+2)
	for k, v := range hintFunctions {
		res[k] = v
	}
	var gkrData gkrSolvingData
	res[info.SolveHintID] = gkrSolveHint(info, &gkrData)
	res[info.ProveHintID] = gkrProveHint(info.HashName, &gkrData)
	return res
}

var GkrGateRegistry = map[string]gkr.Gate{ // TODO: Migrate to gnark-crypto
	"mul": mulGate(2),
	"add": addGate{},
	"sub": subGate{},
	"neg": negGate{},
}

// TODO: Move to gnark-crypto
var HashBuilderRegistry = make(map[string]func() hash.Hash)

type mulGate int
type addGate struct{}
type subGate struct{}
type negGate struct{}

func (g mulGate) Evaluate(x ...fr.Element) (res fr.Element) {
	if len(x) != int(g) {
		panic("wrong input count")
	}
	switch len(x) {
	case 0:
		res.SetOne()
	case 1:
		res.Set(&x[0])
	default:
		res.Mul(&x[0], &x[1])
		for i := 2; i < len(x); i++ {
			res.Mul(&res, &x[2])
		}
	}
	return
}

func (g mulGate) Degree() int {
	return int(g)
}

func (g addGate) Evaluate(x ...fr.Element) (res fr.Element) {
	switch len(x) {
	case 0:
	// set zero
	case 1:
		res.Set(&x[0])
	case 2:
		res.Add(&x[0], &x[1])
		for i := 2; i < len(x); i++ {
			res.Add(&res, &x[2])
		}
	}
	return
}

func (g addGate) Degree() int {
	return 1
}

func (g subGate) Evaluate(element ...fr.Element) (diff fr.Element) {
	if len(element) > 2 {
		panic("not implemented") //TODO
	}
	diff.Sub(&element[0], &element[1])
	return
}

func (g subGate) Degree() int {
	return 1
}

func (g negGate) Evaluate(element ...fr.Element) (neg fr.Element) {
	if len(element) != 1 {
		panic("univariate gate")
	}
	neg.Neg(&element[0])
	return
}

func (g negGate) Degree() int {
	return 1
}
