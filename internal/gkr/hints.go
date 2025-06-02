package gkr

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/constraint/solver/gkrgates"
	bls12377 "github.com/consensys/gnark/internal/gkr/bls12-377"
	bls12381 "github.com/consensys/gnark/internal/gkr/bls12-381"
	bls24315 "github.com/consensys/gnark/internal/gkr/bls24-315"
	bls24317 "github.com/consensys/gnark/internal/gkr/bls24-317"
	bn254 "github.com/consensys/gnark/internal/gkr/bn254"
	bw6633 "github.com/consensys/gnark/internal/gkr/bw6-633"
	bw6761 "github.com/consensys/gnark/internal/gkr/bw6-761"
	"github.com/consensys/gnark/internal/gkr/gkrinfo"
	"github.com/consensys/gnark/internal/gkr/gkrtypes"
)

var testEngineGkrSolvingData = make(map[string]any)

func modKey(mod *big.Int) string {
	return mod.Text(32)
}

// SolveHintPlaceholder solves one instance of a GKR circuit.
// The first input is the index of the instance. The rest are the inputs of the circuit, in their nominal order.
func SolveHintPlaceholder(gkrInfo gkrinfo.StoringInfo) (solver.Hint, solver.HintID) {
	hint := func(mod *big.Int, ins []*big.Int, outs []*big.Int) error {

		solvingInfo, err := gkrtypes.StoringToSolvingInfo(gkrInfo, gkrgates.Get)
		if err != nil {
			return err
		}

		var hint solver.Hint

		// TODO @Tabaie autogenerate this or decide not to
		if mod.Cmp(ecc.BLS12_377.ScalarField()) == 0 {
			data := bls12377.NewSolvingData(solvingInfo)
			hint = bls12377.SolveHint(data)
			testEngineGkrSolvingData[modKey(mod)] = data
		} else if mod.Cmp(ecc.BLS12_381.ScalarField()) == 0 {
			data := bls12381.NewSolvingData(solvingInfo)
			hint = bls12381.SolveHint(data)
			testEngineGkrSolvingData[modKey(mod)] = data
		} else if mod.Cmp(ecc.BLS24_315.ScalarField()) == 0 {
			data := bls24315.NewSolvingData(solvingInfo)
			hint = bls24315.SolveHint(data)
			testEngineGkrSolvingData[modKey(mod)] = data
		} else if mod.Cmp(ecc.BLS24_317.ScalarField()) == 0 {
			data := bls24317.NewSolvingData(solvingInfo)
			hint = bls24317.SolveHint(data)
			testEngineGkrSolvingData[modKey(mod)] = data
		} else if mod.Cmp(ecc.BN254.ScalarField()) == 0 {
			data := bn254.NewSolvingData(solvingInfo)
			hint = bn254.SolveHint(data)
			testEngineGkrSolvingData[modKey(mod)] = data
		} else if mod.Cmp(ecc.BW6_633.ScalarField()) == 0 {
			data := bw6633.NewSolvingData(solvingInfo)
			hint = bw6633.SolveHint(data)
			testEngineGkrSolvingData[modKey(mod)] = data
		} else if mod.Cmp(ecc.BW6_761.ScalarField()) == 0 {
			data := bw6761.NewSolvingData(solvingInfo)
			hint = bw6761.SolveHint(data)
			testEngineGkrSolvingData[modKey(mod)] = data
		} else {
			return errors.New("unsupported modulus")
		}

		return hint(mod, ins, outs)
	}
	return hint, solver.GetHintID(hint)
}

func ProveHintPlaceholder(hashName string) solver.Hint {
	return func(mod *big.Int, ins, outs []*big.Int) error {
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
}
