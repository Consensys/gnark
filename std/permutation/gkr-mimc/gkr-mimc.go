package gkr_mimc

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	frBls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/mimc"
	bls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/fr/mimc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	bw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/fr/mimc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/constraint/solver/gkrgates"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/kvstore"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/gkrapi"
	"github.com/consensys/gnark/std/gkrapi/gkr"
	"github.com/consensys/gnark/std/hash"
	_ "github.com/consensys/gnark/std/hash/all"
)

// compressor implements a compression function by applying
// the Miyaguchi–Preneel transformation to the MiMC encryption function.
type compressor struct {
	gkrCircuit    *gkrapi.Circuit
	in0, in1, out gkr.Variable
}

func (c *compressor) Compress(x frontend.Variable, y frontend.Variable) frontend.Variable {
	res, err := c.gkrCircuit.AddInstance(map[gkr.Variable]frontend.Variable{c.in0: x, c.in1: y})
	if err != nil {
		panic(err)
	}
	return res[c.out]
}

func NewCompressor(api frontend.API) (hash.Compressor, error) {

	store, ok := api.(kvstore.Store)
	if !ok {
		return nil, fmt.Errorf("api of type %T does not implement kvstore.Store", api)
	}

	cached := store.GetKeyValue(gkrMiMCKey{})
	if cached != nil {
		if compressor, ok := cached.(*compressor); ok {
			return compressor, nil
		}
		return nil, fmt.Errorf("cached value is of type %T, not a compressor", cached)
	}

	gkrApi := gkrapi.New()

	in0 := gkrApi.NewInput()
	in1 := gkrApi.NewInput()

	y := in1

	curve := utils.FieldToCurve(api.Compiler().Field())
	params, _, err := getParams(curve) // params is only used for its length
	if err != nil {
		return nil, err
	}
	if err = RegisterGates(curve); err != nil {
		return nil, err
	}
	gateNamer := newGateNamer(curve)

	for i := range len(params) - 1 {
		y = gkrApi.NamedGate(gateNamer.round(i), in0, y)
	}

	y = gkrApi.NamedGate(gateNamer.round(len(params)-1), in0, y, in1)

	res :=
		&compressor{
			gkrCircuit: gkrApi.Compile(api, "POSEIDON2"),
			in0:        in0,
			in1:        in1,
			out:        y,
		}

	store.SetKeyValue(gkrMiMCKey{}, res)
	return res, nil
}

func RegisterGates(curves ...ecc.ID) error {
	for _, curve := range curves {
		constants, deg, err := getParams(curve)
		if err != nil {
			return err
		}
		gateNamer := newGateNamer(curve)
		var lastLayerSBox, nonLastLayerSBox func(*big.Int) gkr.GateFunction
		switch deg {
		case 5:
			lastLayerSBox = addPow5Add
			nonLastLayerSBox = addPow5
		case 7:
			lastLayerSBox = addPow7Add
			nonLastLayerSBox = addPow7
		case 17:
			lastLayerSBox = addPow17Add
			nonLastLayerSBox = addPow17
		default:
			return fmt.Errorf("s-Box of degree %d not supported", deg)
		}

		for i := range len(constants) - 1 {
			if _, err = gkrgates.Register(nonLastLayerSBox(&constants[i]), 2, gkrgates.WithName(gateNamer.round(i)), gkrgates.WithUnverifiedDegree(deg), gkrgates.WithCurves(curve)); err != nil {
				return fmt.Errorf("failed to register keyed GKR gate for round %d of MiMC on curve %s: %w", i, curve, err)
			}
		}

		if _, err = gkrgates.Register(lastLayerSBox(&constants[len(constants)-1]), 3, gkrgates.WithName(gateNamer.round(len(constants)-1)), gkrgates.WithUnverifiedDegree(deg), gkrgates.WithCurves(curve)); err != nil {
			return fmt.Errorf("failed to register keyed GKR gate for round %d of MiMC on curve %s: %w", len(constants)-1, curve, err)
		}
	}
	return nil
}

// getParams returns the parameters for the MiMC encryption function for the given curve.
// It also returns the degree of the s-Box
func getParams(curve ecc.ID) ([]big.Int, int, error) {
	switch curve {
	case ecc.BN254:
		return bn254.GetConstants(), 5, nil
	case ecc.BLS12_381:
		return bls12381.GetConstants(), 5, nil
	case ecc.BLS12_377:
		return bls12377.GetConstants(), 17, nil
	case ecc.BLS24_315:
		return bls24315.GetConstants(), 5, nil
	case ecc.BLS24_317:
		return bls24317.GetConstants(), 7, nil
	case ecc.BW6_633:
		return bw6633.GetConstants(), 5, nil
	case ecc.BW6_761:
		return bw6761.GetConstants(), 5, nil
	default:
		return nil, -1, fmt.Errorf("unsupported curve ID: %s", curve)
	}
}

type gateNamer string

func newGateNamer(o fmt.Stringer) gateNamer {
	return gateNamer("MiMC-" + o.String() + "-round-")
}
func (n gateNamer) round(i int) gkr.GateName {
	return gkr.GateName(fmt.Sprintf("%s%d", string(n), i))
}

func addPow5(key *big.Int) gkr.GateFunction {
	return func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		if len(in) != 2 {
			panic("expected two input")
		}
		s := api.Add(in[0], in[1], key)
		t := api.Mul(s, s)
		return api.Mul(t, t, s)
	}
}

// addPow5Add: (in[0]+in[1]+key)⁵ + 2*in[0] + in[2]
func addPow5Add(key *big.Int) gkr.GateFunction {
	return func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		if len(in) != 3 {
			panic("expected three input")
		}
		s := api.Add(in[0], in[1], key)
		t := api.Mul(s, s)
		t = api.Mul(t, t, s)

		return api.Add(t, in[0], in[0], in[2])
	}
}

func addPow7(key *big.Int) gkr.GateFunction {
	return func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		if len(in) != 2 {
			panic("expected two input")
		}
		s := api.Add(in[0], in[1], key)
		t := api.Mul(s, s)
		return api.Mul(t, t, t, s) // s⁶ × s
	}
}

// addPow7Add: (in[0]+in[1]+key)⁷ + 2*in[0] + in[2]
func addPow7Add(key *big.Int) gkr.GateFunction {
	return func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		if len(in) != 3 {
			panic("expected three input")
		}
		s := api.Add(in[0], in[1], key)
		t := api.Mul(s, s)
		return api.Add(api.Mul(t, t, t, s), in[0], in[0], in[2]) // s⁶ × s + 2*in[0] + in[2]
	}
}

// addPow17: (in[0]+in[1]+key)¹⁷
func addPow17(key *big.Int) gkr.GateFunction {
	var cachedKey frontend.Variable
	return func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		if len(in) != 2 {
			panic("expected two input")
		}
		if cachedKey == nil {
			if _, ok := in[0].(*frBls12377.Element); ok {
				var ck frBls12377.Element
				ck.SetBigInt(key)
				cachedKey = &ck
			} else {
				return api.SumExp17(in[0], in[1], key)
			}
		}

		return api.SumExp17(in[0], in[1], cachedKey)
	}
}

// addPow17Add: (in[0]+in[1]+key)¹⁷ + in[0] + in[2]
func addPow17Add(key *big.Int) gkr.GateFunction {
	return func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		if len(in) != 3 {
			panic("expected three input")
		}
		s := api.Add(in[0], in[1], key)
		t := api.Mul(s, s)                                 // s²
		t = api.Mul(t, t)                                  // s⁴
		t = api.Mul(t, t)                                  // s⁸
		t = api.Mul(t, t)                                  // s¹⁶
		return api.Add(api.Mul(t, s), in[0], in[0], in[2]) // s¹⁶ × s + 2*in[0] + in[2]
	}
}

type gkrMiMCKey struct{}
