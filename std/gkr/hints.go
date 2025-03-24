package gkr

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	bls12377 "github.com/consensys/gnark/constraint/bls12-377"
	bls12381 "github.com/consensys/gnark/constraint/bls12-381"
	bls24315 "github.com/consensys/gnark/constraint/bls24-315"
	bls24317 "github.com/consensys/gnark/constraint/bls24-317"
	bn254 "github.com/consensys/gnark/constraint/bn254"
	bw6633 "github.com/consensys/gnark/constraint/bw6-633"
	bw6761 "github.com/consensys/gnark/constraint/bw6-761"
	"github.com/consensys/gnark/constraint/solver"
	"hash"
	"math/big"
)

var testEngineGkrSolvingData = make(map[string]any)

func modKey(mod *big.Int) string {
	return mod.Text(32)
}

func SolveHintPlaceholder(gkrInfo constraint.GkrInfo) solver.Hint {
	return func(mod *big.Int, ins []*big.Int, outs []*big.Int) error {

		// TODO @Tabaie autogenerate this or decide not to
		if mod.Cmp(ecc.BLS12_377.ScalarField()) == 0 {
			var data bls12377.GkrSolvingData
			testEngineGkrSolvingData[modKey(mod)] = &data
			return bls12377.GkrSolveHint(gkrInfo, &data)(mod, ins, outs)
		}
		if mod.Cmp(ecc.BLS12_381.ScalarField()) == 0 {
			var data bls12381.GkrSolvingData
			testEngineGkrSolvingData[modKey(mod)] = &data
			return bls12381.GkrSolveHint(gkrInfo, &data)(mod, ins, outs)
		}
		if mod.Cmp(ecc.BLS24_315.ScalarField()) == 0 {
			var data bls24315.GkrSolvingData
			testEngineGkrSolvingData[modKey(mod)] = &data
			return bls24315.GkrSolveHint(gkrInfo, &data)(mod, ins, outs)
		}
		if mod.Cmp(ecc.BLS24_317.ScalarField()) == 0 {
			var data bls24317.GkrSolvingData
			testEngineGkrSolvingData[modKey(mod)] = &data
			return bls24317.GkrSolveHint(gkrInfo, &data)(mod, ins, outs)
		}
		if mod.Cmp(ecc.BN254.ScalarField()) == 0 {
			var data bn254.GkrSolvingData
			testEngineGkrSolvingData[modKey(mod)] = &data
			return bn254.GkrSolveHint(gkrInfo, &data)(mod, ins, outs)
		}
		if mod.Cmp(ecc.BW6_633.ScalarField()) == 0 {
			var data bw6633.GkrSolvingData
			testEngineGkrSolvingData[modKey(mod)] = &data
			return bw6633.GkrSolveHint(gkrInfo, &data)(mod, ins, outs)
		}
		if mod.Cmp(ecc.BW6_761.ScalarField()) == 0 {
			var data bw6761.GkrSolvingData
			testEngineGkrSolvingData[modKey(mod)] = &data
			return bw6761.GkrSolveHint(gkrInfo, &data)(mod, ins, outs)
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
			return bls12377.GkrProveHint(hashName, data.(*bls12377.GkrSolvingData))(mod, ins, outs)
		}
		if mod.Cmp(ecc.BLS12_381.ScalarField()) == 0 {
			return bls12381.GkrProveHint(hashName, data.(*bls12381.GkrSolvingData))(mod, ins, outs)
		}
		if mod.Cmp(ecc.BLS24_315.ScalarField()) == 0 {
			return bls24315.GkrProveHint(hashName, data.(*bls24315.GkrSolvingData))(mod, ins, outs)
		}
		if mod.Cmp(ecc.BLS24_317.ScalarField()) == 0 {
			return bls24317.GkrProveHint(hashName, data.(*bls24317.GkrSolvingData))(mod, ins, outs)
		}
		if mod.Cmp(ecc.BN254.ScalarField()) == 0 {
			return bn254.GkrProveHint(hashName, data.(*bn254.GkrSolvingData))(mod, ins, outs)
		}
		if mod.Cmp(ecc.BW6_633.ScalarField()) == 0 {
			return bw6633.GkrProveHint(hashName, data.(*bw6633.GkrSolvingData))(mod, ins, outs)
		}
		if mod.Cmp(ecc.BW6_761.ScalarField()) == 0 {
			return bw6761.GkrProveHint(hashName, data.(*bw6761.GkrSolvingData))(mod, ins, outs)
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
			builder, err = bls12377.GetHashBuilder(hashName)
		} else if mod.Cmp(ecc.BLS12_381.ScalarField()) == 0 {
			builder, err = bls12381.GetHashBuilder(hashName)
		} else if mod.Cmp(ecc.BLS24_315.ScalarField()) == 0 {
			builder, err = bls24315.GetHashBuilder(hashName)
		} else if mod.Cmp(ecc.BLS24_317.ScalarField()) == 0 {
			builder, err = bls24317.GetHashBuilder(hashName)
		} else if mod.Cmp(ecc.BN254.ScalarField()) == 0 {
			builder, err = bn254.GetHashBuilder(hashName)
		} else if mod.Cmp(ecc.BW6_633.ScalarField()) == 0 {
			builder, err = bw6633.GetHashBuilder(hashName)
		} else if mod.Cmp(ecc.BW6_761.ScalarField()) == 0 {
			builder, err = bw6761.GetHashBuilder(hashName)
		} else {
			return errors.New("unsupported modulus")
		}

		if err != nil {
			return err
		}

		toHash := ins[0].Bytes()
		expectedHash := ins[1].Bytes()

		hsh := builder()
		hsh.Write(toHash)
		hashed := hsh.Sum(nil)

		if !bytes.Equal(hashed, expectedHash) {
			return fmt.Errorf("hash mismatch: expected %x, got %x", expectedHash, hashed)
		}

		return nil
	}
}
