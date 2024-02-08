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
	// compute rinv = r^{-1} mod fr
	rinv := frField.Inverse(&r)
	// compute u1 = -msg * rinv
	u1 := frField.MulMod(&msg, rinv)
	u1 = frField.Neg(u1)
	// compute u2 = s * rinv
	u2 := frField.MulMod(&s, rinv)

	// 💡 Optimization idea:
	// we need to check that [u1]G + [u2]R == P which is equivalent to:
	// [v]P == [v*u2]R + [v*u1]G if we multiply by some integer v.
	// Now if we find u s.t. u2 = u/v mod n and u,v are half-size of n,
	// then we need to check that [v]P - [u]R == [w]G

	// 1. first find subScalars[0]=-u and subScalars[1]=v
	subScalars, err := frField.NewHint(halfEuclideanDivision, 4, frField.Modulus(), u2)
	if err != nil {
		panic(fmt.Sprintf("sub-scalars hint: %v", err))
	}
	// 2. assert that u2 = u/v mod n
	frField.AssertIsEqual(frField.Div(frField.Neg(subScalars[0]), subScalars[1]), u2)
	// 2.1 negate P if v is negative
	selector := frField.IsZero(frField.Sub(subScalars[3], subScalars[1]))
	_P := sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
		X: P.X,
		Y: *fpField.Select(selector, &P.Y, fpField.Neg(&P.Y)),
	}
	s1 := frField.Select(selector, subScalars[1], subScalars[3])
	s0 := subScalars[0]
	// 3. get w = u1 * u
	w := frField.Mul(subScalars[1], u1)
	// 4. compute [w]G
	_C := curve.ScalarMulBase(w)
	// 5. compute [v]P - [u]R using Shamir's trick
	C := curve.JointScalarMulHalfSize(&_P, &R, s1, s0)
	// 6. check that [v]P - [u]R == [w]G
	curve.AssertIsEqual(_C, C)
	return &P
}
