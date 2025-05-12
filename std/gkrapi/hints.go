package gkrapi

import (
	"errors"
	"fmt"
	"hash"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	csBls12377 "github.com/consensys/gnark/constraint/bls12-377"
	csBls12381 "github.com/consensys/gnark/constraint/bls12-381"
	csBls24315 "github.com/consensys/gnark/constraint/bls24-315"
	csBls24317 "github.com/consensys/gnark/constraint/bls24-317"
	csBn254 "github.com/consensys/gnark/constraint/bn254"
	csBw6633 "github.com/consensys/gnark/constraint/bw6-633"
	csBw6761 "github.com/consensys/gnark/constraint/bw6-761"
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

func SolveHintPlaceholder(gkrInfo gkrinfo.StoringInfo) solver.Hint {
	return func(mod *big.Int, ins []*big.Int, outs []*big.Int) error {

		solvingInfo, err := gkrtypes.StoringToSolvingInfo(gkrInfo, gkrgates.Get)
		if err != nil {
			return err
		}

		// TODO @Tabaie autogenerate this or decide not to
		if mod.Cmp(ecc.BLS12_377.ScalarField()) == 0 {
			var data bls12377.SolvingData
			testEngineGkrSolvingData[modKey(mod)] = &data
			return bls12377.SolveHint(gkrInfo, &data)(mod, ins, outs)
		}
		if mod.Cmp(ecc.BLS12_381.ScalarField()) == 0 {
			var data bls12381.SolvingData
			testEngineGkrSolvingData[modKey(mod)] = &data
			return bls12381.SolveHint(gkrInfo, &data)(mod, ins, outs)
		}
		if mod.Cmp(ecc.BLS24_315.ScalarField()) == 0 {
			var data bls24315.SolvingData
			testEngineGkrSolvingData[modKey(mod)] = &data
			return bls24315.SolveHint(gkrInfo, &data)(mod, ins, outs)
		}
		if mod.Cmp(ecc.BLS24_317.ScalarField()) == 0 {
			var data bls24317.SolvingData
			testEngineGkrSolvingData[modKey(mod)] = &data
			return bls24317.SolveHint(solvingInfo, &data)(mod, ins, outs)
		}
		if mod.Cmp(ecc.BN254.ScalarField()) == 0 {
			var data bn254.SolvingData
			testEngineGkrSolvingData[modKey(mod)] = &data
			return bn254.SolveHint(solvingInfo, &data)(mod, ins, outs)
		}
		if mod.Cmp(ecc.BW6_633.ScalarField()) == 0 {
			var data bw6633.SolvingData
			testEngineGkrSolvingData[modKey(mod)] = &data
			return bw6633.SolveHint(gkrInfo, &data)(mod, ins, outs)
		}
		if mod.Cmp(ecc.BW6_761.ScalarField()) == 0 {
			var data bw6761.SolvingData
			testEngineGkrSolvingData[modKey(mod)] = &data
			return bw6761.SolveHint(gkrInfo, &data)(mod, ins, outs)
		}

		return errors.New("unsupported modulus")
	}
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

func CheckHashHint(hashName string) solver.Hint {
	return func(mod *big.Int, ins, outs []*big.Int) error {
		if len(ins) != 2 || len(outs) != 1 {
			return errors.New("invalid number of inputs/outputs")
		}

		var (
			builder func() hash.Hash
			err     error
		)
		if mod.Cmp(ecc.BLS12_377.ScalarField()) == 0 {
			builder, err = csBls12377.GetHashBuilder(hashName)
		} else if mod.Cmp(ecc.BLS12_381.ScalarField()) == 0 {
			builder, err = csBls12381.GetHashBuilder(hashName)
		} else if mod.Cmp(ecc.BLS24_315.ScalarField()) == 0 {
			builder, err = csBls24315.GetHashBuilder(hashName)
		} else if mod.Cmp(ecc.BLS24_317.ScalarField()) == 0 {
			builder, err = csBls24317.GetHashBuilder(hashName)
		} else if mod.Cmp(ecc.BN254.ScalarField()) == 0 {
			builder, err = csBn254.GetHashBuilder(hashName)
		} else if mod.Cmp(ecc.BW6_633.ScalarField()) == 0 {
			builder, err = csBw6633.GetHashBuilder(hashName)
		} else if mod.Cmp(ecc.BW6_761.ScalarField()) == 0 {
			builder, err = csBw6761.GetHashBuilder(hashName)
		} else {
			return errors.New("unsupported modulus")
		}

		if err != nil {
			return err
		}

		toHash := ins[0].Bytes()
		expectedHash := ins[1]

		hsh := builder()
		hsh.Write(toHash)
		hashed := hsh.Sum(nil)

		if hashed := new(big.Int).SetBytes(hashed); hashed.Cmp(expectedHash) != 0 {
			return fmt.Errorf("hash mismatch: expected %s, got %s", expectedHash.String(), hashed.String())
		}

		outs[0].SetBytes(hashed)

		return nil
	}
}
