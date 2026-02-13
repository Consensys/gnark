package gkr

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark/internal/gkr/bls12-377"
	bls12381 "github.com/consensys/gnark/internal/gkr/bls12-381"
	bn254 "github.com/consensys/gnark/internal/gkr/bn254"
	bw6761 "github.com/consensys/gnark/internal/gkr/bw6-761"
	"github.com/consensys/gnark/internal/gkr/gkrtypes"
)

// GateTester is an interface for testing gate properties (degree, additivity).
type GateTester interface {
	IsAdditive(varIndex int) bool
	FindDegree() int
	SetGate(g *gkrtypes.GateBytecode, nbIn int)
}

// NewGateTester returns a curve-specific GateTester.
func NewGateTester(curve ecc.ID) GateTester {
	switch curve {
	case ecc.BLS12_377:
		return &bls12377.GateTester{}
	case ecc.BLS12_381:
		return &bls12381.GateTester{}
	case ecc.BN254:
		return &bn254.GateTester{}
	case ecc.BW6_761:
		return &bw6761.GateTester{}
	default:
		panic(fmt.Errorf("unsupported curve %s", curve))
	}
}

// ToSerializableCircuit converts a gadget circuit to a serializable circuit by compiling the gate functions.
// It also sets the gate metadata (Degree, SolvableVar) for both the input and output circuits.
func ToSerializableCircuit(curve ecc.ID, c gkrtypes.GadgetCircuit) gkrtypes.SerializableCircuit {
	tester := NewGateTester(curve)

	var err error
	res := make(gkrtypes.SerializableCircuit, len(c))
	for i := range c {
		res[i].Inputs = c[i].Inputs

		c[i].Gate.NbIn = len(c[i].Inputs)
		res[i].Gate.NbIn = c[i].Gate.NbIn

		if res[i].Gate.Evaluate, err = gkrtypes.CompileGateFunction(c[i].Gate.Evaluate, c[i].Gate.NbIn); err != nil {
			panic(err)
		}

		tester.SetGate(res[i].Gate.Evaluate, c[i].Gate.NbIn)

		if c[i].Gate.Degree = tester.FindDegree(); c[i].Gate.Degree == -1 {
			panic("cannot find degree for gate")
		}
		res[i].Gate.Degree = c[i].Gate.Degree

		for j := range c[i].Inputs {
			if tester.IsAdditive(j) {
				c[i].Gate.SolvableVar = j
				break
			}
		}
		res[i].Gate.SolvableVar = c[i].Gate.SolvableVar
	}
	return res
}
