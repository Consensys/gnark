package evmprecompiles

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
)

// ECRecover implements [ECRECOVER] precompile contract at address 0x01.
//
// [ECRECOVER]: https://ethereum.github.io/execution-specs/autoapi/ethereum/paris/vm/precompiled_contracts/ecrecover/index.html
func ECRecover(api frontend.API, msg emulated.Element[emulated.Secp256k1Fr],
	v frontend.Variable, r, s emulated.Element[emulated.Secp256k1Fr],
	strictRange frontend.Variable) *sw_emulated.AffinePoint[emulated.Secp256k1Fp] {
	// EVM uses v \in {27, 28}, but everyone else v >= 0. Convert back
	v = api.Sub(v, 27)
	var emfp emulated.Secp256k1Fp
	var emfr emulated.Secp256k1Fr
	fpField, err := emulated.NewField[emulated.Secp256k1Fp](api)
	if err != nil {
		panic(fmt.Sprintf("new field: %v", err))
	}
	frField, err := emulated.NewField[emulated.Secp256k1Fr](api)
	if err != nil {
		panic(fmt.Sprintf("new field: %v", err))
	}
	// with the encoding we may have that r,s < 2*Fr (i.e. not r,s < Fr). Apply more thorough checks.
	frField.AssertIsLessOrEqual(&r, frField.Modulus())
	// Ethereum Yellow Paper defines that the check for s should be more strict
	// when checking transaction signatures (Appendix F). There we should check
	// that s <= (Fr-1)/2
	halfFr := new(big.Int).Sub(emfr.Modulus(), big.NewInt(1))
	halfFr.Div(halfFr, big.NewInt(2))
	bound := frField.Select(strictRange, frField.NewElement(halfFr), frField.Modulus())
	frField.AssertIsLessOrEqual(&s, bound)

	curve, err := sw_emulated.New[emulated.Secp256k1Fp, emulated.Secp256k1Fr](api, sw_emulated.GetSecp256k1Params())
	if err != nil {
		panic(fmt.Sprintf("new curve: %v", err))
	}
	// we cannot directly use the field emulation hint calling wrappers as we work between two fields.
	Rlimbs, err := api.Compiler().NewHint(recoverPointHint, 2*int(emfp.NbLimbs()), recoverPointHintArgs(v, r)...)
	if err != nil {
		panic(fmt.Sprintf("point hint: %v", err))
	}
	R := sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
		X: *fpField.NewElement(Rlimbs[0:emfp.NbLimbs()]),
		Y: *fpField.NewElement(Rlimbs[emfp.NbLimbs() : 2*emfp.NbLimbs()]),
	}
	// we cannot directly use the field emulation hint calling wrappers as we work between two fields.
	Plimbs, err := api.Compiler().NewHint(recoverPublicKeyHint, 2*int(emfp.NbLimbs()), recoverPublicKeyHintArgs(msg, v, r, s)...)
	if err != nil {
		panic(fmt.Sprintf("point hint: %v", err))
	}
	P := sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
		X: *fpField.NewElement(Plimbs[0:emfp.NbLimbs()]),
		Y: *fpField.NewElement(Plimbs[emfp.NbLimbs() : 2*emfp.NbLimbs()]),
	}
	// check that len(v) = 2
	vbits := bits.ToBinary(api, v, bits.WithNbDigits(2))
	// check that Rx is correct: x = r+v[1]*fr
	tmp := fpField.Select(vbits[1], fpField.NewElement(emfr.Modulus()), fpField.NewElement(0))
	rbits := frField.ToBits(&r)
	rfp := fpField.FromBits(rbits...)
	tmp = fpField.Add(rfp, tmp)
	fpField.AssertIsEqual(tmp, &R.X)
	// check that Ry is correct: oddity(y) = v[0]
	Rynormal := fpField.Reduce(&R.Y)
	Rybits := fpField.ToBits(Rynormal)
	api.AssertIsEqual(vbits[0], Rybits[0])
	// compute u1 = -msg * r^{-1} mod fr
	u1 := frField.Div(&msg, &r)
	u1 = frField.Neg(u1)
	// compute u2 = s * r^{-1} mod fr
	u2 := frField.Div(&s, &r)
	// check u1 * G + u2 R == P
	C := curve.JointScalarMulBase(&R, u2, u1)
	curve.AssertIsEqual(C, &P)
	return &P
}
