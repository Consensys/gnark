package evmprecompiles

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all the hints used in this package.
func GetHints() []solver.Hint {
	return []solver.Hint{recoverPointHint, recoverPublicKeyHint}
}

func recoverPointHintArgs(v frontend.Variable, r emulated.Element[emulated.Secp256k1Fr]) []frontend.Variable {
	args := []frontend.Variable{v}
	args = append(args, r.Limbs...)
	return args
}

func recoverPointHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	var emfp emulated.Secp256k1Fp
	if len(inputs) != int(emfp.NbLimbs())+1 {
		return fmt.Errorf("expected input %d limbs got %d", emfp.NbLimbs()+1, len(inputs))
	}
	if !inputs[0].IsInt64() {
		return fmt.Errorf("first input supposed to be in [0,3]")
	}
	if len(outputs) != 2*int(emfp.NbLimbs()) {
		return fmt.Errorf("expected output %d limbs got %d", 2*emfp.NbLimbs(), len(outputs))
	}
	v := inputs[0].Uint64()
	r := recompose(inputs[1:], emfp.BitsPerLimb())
	P, err := ecdsa.RecoverP(uint(v), r)
	if err != nil {
		return fmt.Errorf("recover: %s", err)
	}
	if err := decompose(P.X.BigInt(new(big.Int)), emfp.BitsPerLimb(), outputs[0:emfp.NbLimbs()]); err != nil {
		return fmt.Errorf("decompose x: %w", err)
	}
	if err := decompose(P.Y.BigInt(new(big.Int)), emfp.BitsPerLimb(), outputs[emfp.NbLimbs():]); err != nil {
		return fmt.Errorf("decompose y: %w", err)
	}
	return nil
}

func recoverPublicKeyHintArgs(msg emulated.Element[emulated.Secp256k1Fr],
	v frontend.Variable, r, s emulated.Element[emulated.Secp256k1Fr]) []frontend.Variable {
	args := msg.Limbs
	args = append(args, v)
	args = append(args, r.Limbs...)
	args = append(args, s.Limbs...)
	return args
}

func recoverPublicKeyHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	// message -nb limbs
	// then v - 1
	// r -- nb limbs
	// s -- nb limbs
	// return 2x nb limbs
	var emfr emulated.Secp256k1Fr
	var emfp emulated.Secp256k1Fp
	if len(inputs) != int(emfr.NbLimbs())*3+1 {
		return fmt.Errorf("expected %d limbs got %d", emfr.NbLimbs()*3+1, len(inputs))
	}
	if !inputs[emfr.NbLimbs()].IsInt64() {
		return fmt.Errorf("second input input must be in [0,3]")
	}
	if len(outputs) != 2*int(emfp.NbLimbs()) {
		return fmt.Errorf("expected output %d limbs got %d", 2*emfp.NbLimbs(), len(outputs))
	}
	msg := recompose(inputs[:emfr.NbLimbs()], emfr.BitsPerLimb())
	v := inputs[emfr.NbLimbs()].Uint64()
	r := recompose(inputs[emfr.NbLimbs()+1:2*emfr.NbLimbs()+1], emfr.BitsPerLimb())
	s := recompose(inputs[2*emfr.NbLimbs()+1:3*emfr.NbLimbs()+1], emfr.BitsPerLimb())
	var pk ecdsa.PublicKey
	if err := pk.RecoverFrom(msg.Bytes(), uint(v), r, s); err != nil {
		return fmt.Errorf("recover public key: %w", err)
	}
	Px := pk.A.X.BigInt(new(big.Int))
	Py := pk.A.Y.BigInt(new(big.Int))
	if err := decompose(Px, emfp.BitsPerLimb(), outputs[0:emfp.NbLimbs()]); err != nil {
		return fmt.Errorf("decompose x: %w", err)
	}
	if err := decompose(Py, emfp.BitsPerLimb(), outputs[emfp.NbLimbs():2*emfp.NbLimbs()]); err != nil {
		return fmt.Errorf("decompose y: %w", err)
	}
	return nil
}
