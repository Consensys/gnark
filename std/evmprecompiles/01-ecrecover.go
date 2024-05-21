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
// The method allows checking both the transaction signatures and ECRecover
// precompile calls. The difference between TX signature verification and
// ECRecover precompile call is that there is additional check for s <= (Fr-1)/2
// in the former case. To enforce this check, the strictRange variable should be
// set to 1.
//
// The isFailure variable is set to 1 when the inputs are expected to be invalid
// in the context of ECRecover. The failure cases are:
//  1. The public key is zero.
//  2. The value r^3 + 7 is not a quadratic residue.
//
// [ECRECOVER]: https://ethereum.github.io/execution-specs/autoapi/ethereum/paris/vm/precompiled_contracts/ecrecover/index.html
func ECRecover(api frontend.API, msg emulated.Element[emulated.Secp256k1Fr],
	v frontend.Variable, r, s emulated.Element[emulated.Secp256k1Fr],
	strictRange frontend.Variable, isFailure frontend.Variable) *sw_emulated.AffinePoint[emulated.Secp256k1Fp] {
	// the field implementations are cached. So it is safe to initialize
	// them at every call to ECRecover. This allows to simplify the
	// interface of ECRecover.
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
	curve, err := sw_emulated.New[emulated.Secp256k1Fp, emulated.Secp256k1Fr](api, sw_emulated.GetSecp256k1Params())
	if err != nil {
		panic(fmt.Sprintf("new curve: %v", err))
	}

	// sanity check that input is valid. First we need to ensure the failure
	// tag is boolean.
	api.AssertIsBoolean(isFailure)

	// EVM uses v \in {27, 28}, but everyone else v >= 0. Convert back
	v = api.Sub(v, 27)
	// check that len(v) = 2
	vbits := bits.ToBinary(api, v, bits.WithNbDigits(2))

	// with the encoding we may have that r,s < 2*Fr (i.e. not r,s < Fr). Apply more thorough checks.
	frField.AssertIsLessOrEqual(&r, frField.Modulus())
	// Ethereum Yellow Paper defines that the check for s should be more strict
	// when checking transaction signatures (Appendix F). There we should check
	// that s <= (Fr-1)/2
	halfFr := new(big.Int).Sub(emfr.Modulus(), big.NewInt(1))
	halfFr.Div(halfFr, big.NewInt(2))
	bound := frField.Select(strictRange, frField.NewElement(halfFr), frField.Modulus())
	frField.AssertIsLessOrEqual(&s, bound)

	// compute P, the public key
	// we cannot directly use the field emulation hint calling wrappers as we work between two fields.
	Plimbs, err := api.Compiler().NewHint(recoverPublicKeyHint, 2*int(emfp.NbLimbs())+1, recoverPublicKeyHintArgs(msg, v, r, s)...)
	if err != nil {
		panic(fmt.Sprintf("point hint: %v", err))
	}
	P := sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
		X: *fpField.NewElement(Plimbs[0:emfp.NbLimbs()]),
		Y: *fpField.NewElement(Plimbs[emfp.NbLimbs() : 2*emfp.NbLimbs()]),
	}
	// we also get a flag from the hint if the returned public key is zero. This
	// is only set when we have no QNR failure.
	pIsZero := Plimbs[2*emfp.NbLimbs()]
	api.AssertIsBoolean(pIsZero)

	// the failure can be either that we have quadratic non residue or that the
	// public key is zero. We set the QNR failure flag here.
	//
	// However, the flag coming from the hint is not strongly asserted as it
	// comes from the hint. We need to later assert again against the computed
	// public key (variable isZero).
	isQNRFailure := api.Sub(isFailure, pIsZero)

	// compute R, the commitment
	// the signature as elements in Fr, but it actually represents elements in Fp. Convert to Fp element.
	rbits := frField.ToBits(&r)
	rfp := fpField.FromBits(rbits...)
	// compute R.X x = r+v[1]*fr
	Rx := fpField.Select(vbits[1], fpField.NewElement(emfr.Modulus()), fpField.NewElement(0))
	Rx = fpField.Add(rfp, Rx) // Rx = r + v[1]*fr
	Ry := fpField.Mul(Rx, Rx) // Ry = x^2
	// compute R.y y = sqrt(x^3+7)
	Ry = fpField.Mul(Ry, Rx)   // Ry = x^3
	b := fpField.NewElement(7) // b = 7 for secp256k1, a = 0
	Ry = fpField.Add(Ry, b)    // Ry = x^3 + 7
	// in case of failure due to no QNR, negate Ry so that exists a square root
	Ry = fpField.Select(isQNRFailure, fpField.Sub(fpField.Modulus(), Ry), Ry)
	Ry = fpField.Sqrt(Ry) // Ry = sqrt(x^3 + 7)
	// ensure the oddity of Ry is same as vbits[0], otherwise negate Ry
	Rybits := fpField.ToBits(Ry)
	Ry = fpField.Select(api.Xor(vbits[0], Rybits[0]), fpField.Sub(fpField.Modulus(), Ry), Ry)

	R := sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
		X: *Rx,
		Y: *Ry,
	}
	// compute the public key C also in-circuit. We need to compute u1 and u2
	// and use these to compute the public key.
	//
	// compute u1 = -msg * r^{-1} mod fr
	u1 := frField.Div(&msg, &r)
	u1 = frField.Neg(u1)
	// compute u2 = s * r^{-1} mod fr
	u2 := frField.Div(&s, &r)
	// compute public key in circuit C = u1 * G + u2 R
	//
	// in case the public key is expected to be zero, then we add 1 to u1 to
	// avoid falling to incomplete edge case in scalar multiplication. Otherwise we add 0.
	u1 = frField.Add(u1, frField.Select(pIsZero, frField.One(), frField.Zero()))
	C := curve.JointScalarMulBase(&R, u2, u1)
	// check that the in-circuit computed public key corresponds to the hint
	// public key if it is not a QNR failure.
	//
	// now, when we added 1 to u1, then the computed public key should be
	// generator (as we only add 1 when pIsZero=1). Instead of needing to
	// subtract G using complete arithmetic, we switch between G and the
	// computed public key.
	condP := curve.Select(pIsZero, curve.Generator(), &P)
	xIsEqual := fpField.IsZero(fpField.Sub(&C.X, &condP.X))
	yIsEqual := fpField.IsZero(fpField.Sub(&C.Y, &condP.Y))
	isEqual := api.Mul(xIsEqual, yIsEqual)
	api.AssertIsEqual(isEqual, api.Sub(1, isQNRFailure))
	// check that the result is zero if isFailure is true. This holds because in
	// case of any failure the returned public key from hint is zero.
	isZero := fpField.IsZero(&P.X)
	// yIsZero := fpField.IsZero(&P.Y)
	// isZero := api.Mul(xIsZero, yIsZero)
	api.AssertIsEqual(isZero, isFailure)
	// when there was a QNR failure then the computed public key C is random. We
	// only check for zero public key failure in case of no QNR failure.
	//
	// So, when there was a QNR failure, hint has returned pIsZero = 0, but the
	// computed isZero 1. We set isZero to 0 by multiplying with
	// (1-isQNRFailure).
	api.AssertIsEqual(pIsZero, api.Mul(api.Sub(1, isQNRFailure), isZero))
	return &P
}
