package gkrapi

import (
	"fmt"
	"reflect"
	"slices"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark/internal/gkr/bls12-377"
	bls12381 "github.com/consensys/gnark/internal/gkr/bls12-381"
	bn254 "github.com/consensys/gnark/internal/gkr/bn254"
	bw6761 "github.com/consensys/gnark/internal/gkr/bw6-761"
	"github.com/consensys/gnark/internal/gkr/gkrtypes"
	"github.com/consensys/gnark/std/gkrapi/gkr"
)

type (
	gateRegistry struct {
		ids    map[uintptr][]gateID // ids maps a gate function to gates defined using it.
		gates  []*gkrtypes.RegisteredGate
		tester gateTester
	}
)

const (
	idIdentity gateID = iota
	idAdd2
	idSub2
	idNeg
	idMul2
)

var builtinGates = [...]*gkrtypes.RegisteredGate{
	idIdentity: gkrtypes.Identity(),
	idAdd2:     gkrtypes.Add2(),
	idSub2:     gkrtypes.Sub2(),
	idNeg:      gkrtypes.Neg(),
	idMul2:     gkrtypes.Mul2(),
}

func newGateRegistry(curve ecc.ID) gateRegistry {
	res := gateRegistry{
		ids:   make(map[uintptr][]gateID),
		gates: slices.Clone(builtinGates[:]),
	}

	switch curve {
	case ecc.BLS12_377:
		res.tester = &bls12377.GateTester{}
	case ecc.BLS12_381:
		res.tester = &bls12381.GateTester{}
	case ecc.BN254:
		res.tester = &bn254.GateTester{}
	case ecc.BW6_761:
		res.tester = &bw6761.GateTester{}
	default:
		panic(fmt.Errorf("unsupported curve %s", curve))
	}

	return res
}

// getID looks up f in the cache, adding it if necessary.
// Gate ID is returned.
func (r *gateRegistry) getID(f gkr.GateFunction, nbIn int) gateID {
	bytecode, err := gkrtypes.CompileGateFunction(f, nbIn)
	if err != nil {
		panic(err)
	}

	ptr := reflect.ValueOf(f).Pointer()

	for _, id := range r.ids[ptr] {
		if reflect.DeepEqual(r.gates[id].Evaluate.Bytecode, bytecode) {
			return id
		}
	}

	r.tester.SetGate(bytecode, nbIn)

	g := gkrtypes.RegisteredGate{
		Evaluate: gkrtypes.BothExecutables{
			Bytecode:      bytecode,
			SnarkFriendly: f,
		},
		NbIn:        nbIn,
		Degree:      r.tester.FindDegree(),
		SolvableVar: -1,
	}

	for i := range nbIn {
		if r.tester.IsAdditive(i) {
			g.SolvableVar = i
			break
		}
	}

	if g.Degree == -1 {
		panic("cannot find degree for gate")
	}

	id := gateID(len(r.gates))
	r.gates = append(r.gates, &g)
	r.ids[ptr] = append(r.ids[ptr], id)

	return id
}

func (r *gateRegistry) toSerializableCircuit(c circuit) gkrtypes.SerializableCircuit {
	res := make(gkrtypes.SerializableCircuit, len(c))
	for i := range c {
		res[i].Inputs = c[i].Inputs
		res[i].Gate = gkrtypes.ToSerializableGate(r.gates[c[i].Gate])
	}
	return res
}

func (r *gateRegistry) getGateFunction(id gateID) gkr.GateFunction {
	return r.gates[id].Evaluate.SnarkFriendly
}

func (r *gateRegistry) toGadgetCircuit(c circuit) gkrtypes.GadgetCircuit {
	res := make(gkrtypes.GadgetCircuit, len(c))
	for i := range c {
		res[i].Inputs = c[i].Inputs
		res[i].Gate = gkrtypes.ToGadgetGate(r.gates[c[i].Gate])
	}
	return res
}

type gateTester interface {
	IsAdditive(varIndex int) bool
	FindDegree() int
	SetGate(g *gkrtypes.GateBytecode, nbIn int)
}
