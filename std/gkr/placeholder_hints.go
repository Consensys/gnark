package gkr

import (
	"errors"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	bls12_377 "github.com/consensys/gnark/constraint/bls12-377"
	bls12_381 "github.com/consensys/gnark/constraint/bls12-381"
	bls24_315 "github.com/consensys/gnark/constraint/bls24-315"
	bls24_317 "github.com/consensys/gnark/constraint/bls24-317"
	bn254 "github.com/consensys/gnark/constraint/bn254"
	bw6_633 "github.com/consensys/gnark/constraint/bw6-633"
	bw6_761 "github.com/consensys/gnark/constraint/bw6-761"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/internal/utils"
	"math/big"
)

// TODO @Tabaie Autogen this and possibly move to another package

var placeholderGkrSolvingData = make(map[solver.HintID]any)

func SolveHintPlaceholderGenerator(hintId solver.HintID, gkrInfo constraint.GkrInfo) func(*big.Int, []*big.Int, []*big.Int) error {
	return func(mod *big.Int, in []*big.Int, out []*big.Int) (err error) {
		solver.RemoveNamedHint(hintId)
		delete(constraint.GkrHints, hintId)

		curve := utils.FieldToCurve(mod)
		switch curve {
		case ecc.BLS12_377:
			var data bls12_377.GkrSolvingData
			placeholderGkrSolvingData[hintId] = &data
			err = bls12_377.GkrSolveHint(gkrInfo, &data)(mod, in, out)
		case ecc.BLS12_381:
			var data bls12_381.GkrSolvingData
			placeholderGkrSolvingData[hintId] = &data
			err = bls12_381.GkrSolveHint(gkrInfo, &data)(mod, in, out)
		case ecc.BLS24_315:
			var data bls24_315.GkrSolvingData
			placeholderGkrSolvingData[hintId] = &data
			err = bls24_315.GkrSolveHint(gkrInfo, &data)(mod, in, out)
		case ecc.BLS24_317:
			var data bls24_317.GkrSolvingData
			placeholderGkrSolvingData[hintId] = &data
			err = bls24_317.GkrSolveHint(gkrInfo, &data)(mod, in, out)
		case ecc.BN254:
			var data bn254.GkrSolvingData
			placeholderGkrSolvingData[hintId] = &data
			err = bn254.GkrSolveHint(gkrInfo, &data)(mod, in, out)
		case ecc.BW6_633:
			var data bw6_633.GkrSolvingData
			placeholderGkrSolvingData[hintId] = &data
			err = bw6_633.GkrSolveHint(gkrInfo, &data)(mod, in, out)
		case ecc.BW6_761:
			var data bw6_761.GkrSolvingData
			placeholderGkrSolvingData[hintId] = &data
			err = bw6_761.GkrSolveHint(gkrInfo, &data)(mod, in, out)
		default:
			err = errors.New("unsupported curve")
		}

		return err
	}
}

func ProveHintPlaceholderGenerator(hashName string, solveHintId, proveHintId solver.HintID) func(*big.Int, []*big.Int, []*big.Int) error {
	return func(mod *big.Int, in []*big.Int, out []*big.Int) (err error) {
		solver.RemoveNamedHint(proveHintId)
		delete(constraint.GkrHints, proveHintId)

		curve := utils.FieldToCurve(mod)
		switch curve {
		case ecc.BN254:
			err = bn254.GkrProveHint(hashName, placeholderGkrSolvingData[solveHintId].(*bn254.GkrSolvingData))(mod, in, out)
		default:
			err = errors.New("unsupported curve")
		}

		delete(placeholderGkrSolvingData, solveHintId)

		return err
	}
}
