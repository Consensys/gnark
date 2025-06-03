package gkr

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver/gkrgates"
	"github.com/consensys/gnark/frontend"
	bls12377 "github.com/consensys/gnark/internal/gkr/bls12-377"
	bls12381 "github.com/consensys/gnark/internal/gkr/bls12-381"
	bls24315 "github.com/consensys/gnark/internal/gkr/bls24-315"
	bls24317 "github.com/consensys/gnark/internal/gkr/bls24-317"
	bn254 "github.com/consensys/gnark/internal/gkr/bn254"
	bw6633 "github.com/consensys/gnark/internal/gkr/bw6-633"
	bw6761 "github.com/consensys/gnark/internal/gkr/bw6-761"
	"github.com/consensys/gnark/internal/gkr/gkrinfo"
	"github.com/consensys/gnark/internal/gkr/gkrtypes"
	"github.com/consensys/gnark/internal/utils"
)

func modKey(mod *big.Int) string {
	return mod.Text(32)
}

type TestEngineHints struct {
	assignment gkrtypes.WireAssignment
	info       *gkrinfo.StoringInfo
	circuit    gkrtypes.Circuit
	gateIns    []frontend.Variable
}

func NewTestEngineHints(info *gkrinfo.StoringInfo) (*TestEngineHints, error) {
	circuit, err := gkrtypes.CircuitInfoToCircuit(info.Circuit, gkrgates.Get)
	if err != nil {
		return nil, err
	}

	return &TestEngineHints{
			info:    info,
			circuit: circuit,
			gateIns: make([]frontend.Variable, circuit.MaxGateNbIn()),
		},
		err
}

// Solve solves one instance of a GKR circuit.
// The first input is the index of the instance. The rest are the inputs of the circuit, in their nominal order.
func (h *TestEngineHints) Solve(mod *big.Int, ins []*big.Int, outs []*big.Int) error {

	// TODO handle prints

	if in0 := ins[0].Uint64(); !ins[0].IsUint64() || in0 >= uint64(len(h.info.Circuit)) || in0 > 0xffffffff {
		return errors.New("first input must be a uint32 instance index")
	} else if in0 != uint64(h.info.NbInstances) || h.info.NbInstances != len(h.assignment[0]) {
		return errors.New("first input must equal the number of instances, and calls to Solve must be done in order of instance index")
	}

	api := gateAPI{mod}

	inI := 1
	outI := 0
	for wI := range h.circuit {
		w := &h.circuit[wI]
		var val frontend.Variable
		if w.IsInput() {
			val = utils.FromInterface(ins[inI])
			inI++
		} else {
			for gateInI, inWI := range w.Inputs {
				h.gateIns[gateInI] = h.assignment[inWI][gateInI]
			}
			val = w.Gate.Evaluate(api, h.gateIns[:len(w.Inputs)]...)
		}
		if w.IsOutput() {
			*outs[outI] = utils.FromInterface(val)
		}
		h.assignment[wI] = append(h.assignment[wI], val)
	}
	return nil
}

func (h *TestEngineHints) Prove(mod *big.Int, ins, outs []*big.Int) error {

	// todo handle prints
	k := modKey(mod)
	data, ok := testEngineGkrSolvingData[k]
	if !ok {
		return errors.New("solving data not found")
	}
	delete(testEngineGkrSolvingData, k)

	// TODO @Tabaie autogenerate this or decide not to
	if mod.Cmp(ecc.BLS12_377.ScalarField()) == 0 {
		return bls12377.ProveHint(hashName, data.(*bls12377.SolvingData))(mod, ins, outs)
	}
	if mod.Cmp(ecc.BLS12_381.ScalarField()) == 0 {
		return bls12381.ProveHint(hashName, data.(*bls12381.SolvingData))(mod, ins, outs)
	}
	if mod.Cmp(ecc.BLS24_315.ScalarField()) == 0 {
		return bls24315.ProveHint(hashName, data.(*bls24315.SolvingData))(mod, ins, outs)
	}
	if mod.Cmp(ecc.BLS24_317.ScalarField()) == 0 {
		return bls24317.ProveHint(hashName, data.(*bls24317.SolvingData))(mod, ins, outs)
	}
	if mod.Cmp(ecc.BN254.ScalarField()) == 0 {
		return bn254.ProveHint(hashName, data.(*bn254.SolvingData))(mod, ins, outs)
	}
	if mod.Cmp(ecc.BW6_633.ScalarField()) == 0 {
		return bw6633.ProveHint(hashName, data.(*bw6633.SolvingData))(mod, ins, outs)
	}
	if mod.Cmp(ecc.BW6_761.ScalarField()) == 0 {
		return bw6761.ProveHint(hashName, data.(*bw6761.SolvingData))(mod, ins, outs)
	}

	return errors.New("unsupported modulus")

}

type gateAPI struct{ *big.Int }

func (g gateAPI) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	in1 := utils.FromInterface(i1)
	in2 := utils.FromInterface(i2)

	in1.Add(&in1, &in2)
	for _, v := range in {
		inV := utils.FromInterface(v)
		in1.Add(&in1, &inV)
	}
	return &in1
}

func (g gateAPI) MulAcc(a, b, c frontend.Variable) frontend.Variable {
	x, y := utils.FromInterface(b), utils.FromInterface(c)
	x.Mul(&x, &y)
	y = utils.FromInterface(a)
	x.Add(&x, &y)
	return &x
}

func (g gateAPI) Neg(i1 frontend.Variable) frontend.Variable {
	x := utils.FromInterface(i1)
	x.Neg(&x)
	return &x
}

func (g gateAPI) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	x := utils.FromInterface(i1)
	y := utils.FromInterface(i2)
	x.Sub(&x, &y)
	for _, v := range in {
		y = utils.FromInterface(v)
		x.Sub(&x, &y)
	}
	return &x
}

func (g gateAPI) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	x := utils.FromInterface(i1)
	y := utils.FromInterface(i2)
	x.Mul(&x, &y)
	for _, v := range in {
		y = utils.FromInterface(v)
		x.Mul(&x, &y)
	}
	return &x
}

func (g gateAPI) Println(a ...frontend.Variable) {
	strings := make([]string, len(a))
	for i := range a {
		if s, ok := a[i].(fmt.Stringer); ok {
			strings[i] = s.String()
		} else {
			bigInt := utils.FromInterface(a[i])
			strings[i] = bigInt.String()
		}
	}
}
