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

type TestEngineHints struct {
	assignment gkrtypes.WireAssignment
	info       *gkrinfo.StoringInfo // we retain a reference to the solving info to allow the caller to modify it between calls to Solve and Prove
	circuit    gkrtypes.Circuit
	gateIns    []frontend.Variable
}

func NewTestEngineHints(info *gkrinfo.StoringInfo) (*TestEngineHints, error) {
	circuit, err := gkrtypes.CircuitInfoToCircuit(info.Circuit, gkrgates.Get)
	if err != nil {
		return nil, err
	}

	return &TestEngineHints{
			info:       info,
			circuit:    circuit,
			gateIns:    make([]frontend.Variable, circuit.MaxGateNbIn()),
			assignment: make(gkrtypes.WireAssignment, len(circuit)),
		},
		err
}

// Solve solves one instance of a GKR circuit.
// The first input is the index of the instance. The rest are the inputs of the circuit, in their nominal order.
func (h *TestEngineHints) Solve(mod *big.Int, ins []*big.Int, outs []*big.Int) error {

	instanceI := len(h.assignment[0])
	if in0 := ins[0].Uint64(); !ins[0].IsUint64() || in0 > 0xffffffff {
		return errors.New("first input must be a uint32 instance index")
	} else if in0 != uint64(instanceI) || h.info.NbInstances-1 != instanceI {
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
				h.gateIns[gateInI] = h.assignment[inWI][instanceI]
			}
			val = w.Gate.Evaluate(api, h.gateIns[:len(w.Inputs)]...)
		}
		if w.IsOutput() {
			*outs[outI] = utils.FromInterface(val)
			outI++
		}
		h.assignment[wI] = append(h.assignment[wI], val)
	}
	return nil
}

func (h *TestEngineHints) Prove(mod *big.Int, ins, outs []*big.Int) error {

	info, err := gkrtypes.StoringToSolvingInfo(*h.info, gkrgates.Get)
	if err != nil {
		return fmt.Errorf("failed to convert storing info to solving info: %w", err)
	}

	// TODO @Tabaie autogenerate this or decide not to
	if mod.Cmp(ecc.BLS12_377.ScalarField()) == 0 {
		data := bls12377.NewSolvingData(info, bls12377.WithAssignment(h.assignment))
		return bls12377.ProveHint(info.HashName, data)(mod, ins, outs)
	}
	if mod.Cmp(ecc.BLS12_381.ScalarField()) == 0 {
		data := bls12381.NewSolvingData(info, bls12381.WithAssignment(h.assignment))
		return bls12381.ProveHint(info.HashName, data)(mod, ins, outs)
	}
	if mod.Cmp(ecc.BLS24_315.ScalarField()) == 0 {
		data := bls24315.NewSolvingData(info, bls24315.WithAssignment(h.assignment))
		return bls24315.ProveHint(info.HashName, data)(mod, ins, outs)
	}
	if mod.Cmp(ecc.BLS24_317.ScalarField()) == 0 {
		data := bls24317.NewSolvingData(info, bls24317.WithAssignment(h.assignment))
		return bls24317.ProveHint(info.HashName, data)(mod, ins, outs)
	}
	if mod.Cmp(ecc.BN254.ScalarField()) == 0 {
		data := bn254.NewSolvingData(info, bn254.WithAssignment(h.assignment))
		return bn254.ProveHint(info.HashName, data)(mod, ins, outs)
	}
	if mod.Cmp(ecc.BW6_633.ScalarField()) == 0 {
		data := bw6633.NewSolvingData(info, bw6633.WithAssignment(h.assignment))
		return bw6633.ProveHint(info.HashName, data)(mod, ins, outs)
	}
	if mod.Cmp(ecc.BW6_761.ScalarField()) == 0 {
		data := bw6761.NewSolvingData(info, bw6761.WithAssignment(h.assignment))
		return bw6761.ProveHint(info.HashName, data)(mod, ins, outs)
	}

	return errors.New("unsupported modulus")
}

// GetAssignment returns the assignment for a particular wire and instance.
func (h *TestEngineHints) GetAssignment(_ *big.Int, ins []*big.Int, outs []*big.Int) error {
	if len(ins) != 3 || !ins[0].IsUint64() || !ins[1].IsUint64() {
		return errors.New("expected 3 inputs: wire index, instance index, and dummy output from the same instance")
	}
	if len(outs) != 1 {
		return errors.New("expected 1 output: the value of the wire at the given instance")
	}
	*outs[0] = utils.FromInterface(h.assignment[ins[0].Uint64()][ins[1].Uint64()])
	return nil
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
	x.Mod(&x, g.Int) // reduce
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
	x.Mod(&x, g.Int) // reduce
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
