package evmprecompiles

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
	"github.com/consensys/gnark/std/math/emulated"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all the hints used in this package.
func GetHints() []solver.Hint {
	return []solver.Hint{recoverPublicKeyHint}
}

func recoverPublicKeyHintArgs(msg emulated.Element[emulated.Secp256k1Fr],
	v frontend.Variable, r, s emulated.Element[emulated.Secp256k1Fr]) []frontend.Variable {
	args := msg.Limbs
	args = append(args, v)
	args = append(args, r.Limbs...)
	args = append(args, s.Limbs...)
	return args
}

func recoverPublicKeyHint(nativeMod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	// message -nb limbs
	// then v - 1
	// r -- nb limbs
	// s -- nb limbs
	// return 2x nb limbs
	nbFrLimbs, nbFrBitsPerLimb := emulated.GetEffectiveFieldParams[emulated.Secp256k1Fr](nativeMod)
	nbFpLimbs, nbFpBitsPerLimb := emulated.GetEffectiveFieldParams[emulated.Secp256k1Fp](nativeMod)
	if len(inputs) != int(nbFrLimbs)*3+1 {
		return fmt.Errorf("expected %d limbs got %d", nbFrLimbs*3+1, len(inputs))
	}
	if !inputs[nbFrLimbs].IsInt64() {
		return fmt.Errorf("second input must be in [0,3]")
	}
	if len(outputs) != 2*int(nbFpLimbs)+1 {
		return fmt.Errorf("expected output %d limbs got %d", 2*nbFpLimbs, len(outputs))
	}
	msg, r, s := new(big.Int), new(big.Int), new(big.Int)
	err := limbs.Recompose(inputs[:nbFrLimbs], nbFrBitsPerLimb, msg)
	if err != nil {
		return fmt.Errorf("recompose message: %w", err)
	}
	v := inputs[nbFrLimbs].Uint64()
	err = limbs.Recompose(inputs[nbFrLimbs+1:2*nbFrLimbs+1], nbFrBitsPerLimb, r)
	if err != nil {
		return fmt.Errorf("recompose r: %w", err)
	}
	err = limbs.Recompose(inputs[2*nbFrLimbs+1:3*nbFrLimbs+1], nbFrBitsPerLimb, s)
	if err != nil {
		return fmt.Errorf("recompose s: %w", err)
	}
	var pk ecdsa.PublicKey
	var isQNRFailure int
	if err := pk.RecoverFrom(msg.Bytes(), uint(v), r, s); err != nil {
		// in case we have some other possible error except QNR failure, then we return the error as is
		if !errors.Is(err, ecdsa.ErrNoSqrtR) {
			return fmt.Errorf("recover public key: %w", err)
		}
		// otherwise, we set the flag to 1. NB! In this case the public key is (0,0).
		isQNRFailure = 1
	}
	Px := pk.A.X.BigInt(new(big.Int))
	Py := pk.A.Y.BigInt(new(big.Int))
	if err := limbs.Decompose(Px, nbFpBitsPerLimb, outputs[0:nbFpLimbs]); err != nil {
		return fmt.Errorf("decompose x: %w", err)
	}
	if err := limbs.Decompose(Py, nbFpBitsPerLimb, outputs[nbFpLimbs:2*nbFpLimbs]); err != nil {
		return fmt.Errorf("decompose y: %w", err)
	}
	// we also return a flag that indicates if the public key is zero but only
	// if the QNR failure flag is not set.
	zero := new(big.Int)
	xIsZero := 1 - Px.Cmp(zero)
	yIsZero := 1 - Py.Cmp(zero)
	isZero := (1 - isQNRFailure) * xIsZero * yIsZero
	outputs[2*nbFpLimbs].SetInt64(int64(isZero))
	return nil
}
