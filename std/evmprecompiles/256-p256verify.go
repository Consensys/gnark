package evmprecompiles

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// P256Verify implements [P256Verify] precompile contract at address 0x100.
//
// This circuit performs ECDSA signature verification over the secp256r1
// elliptic curve (also known as P-256 or prime256v1).
//
// The method is specific to zkEVM context where some checks are already done by
// the arithmetization. Particularly this method assumes:
// * r and s are in the range [1, n-1]
// * 0 ≤ qx < p and 0 ≤ qy < p
// * (qx, qy) is a valid point on the curve P256
// * (qx, qy) is not (0,0)
//
// [P256Verify]: https://eips.ethereum.org/EIPS/eip-7951
func P256Verify(api frontend.API,
	msgHash *emulated.Element[emulated.P256Fr],
	r, s *emulated.Element[emulated.P256Fr],
	qx, qy *emulated.Element[emulated.P256Fp],
) frontend.Variable {
	// we currently implement signature verification directly to avoid cases
	// which the ECDSA gadget does not handle:
	// * we don't need to perform range checks on r and s as they are done by the arithmetization
	// * instead of two divs we compute an inverse and do two multiplications
	// * we perform modular equality check instead of bitwise equality check
	curve, err := sw_emulated.New[emulated.P256Fp, emulated.P256Fr](api, sw_emulated.GetP256Params())
	if err != nil {
		panic(err)
	}
	scalarApi, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		panic(err)
	}
	baseApi, err := emulated.NewField[emulated.P256Fp](api)
	if err != nil {
		panic(err)
	}
	// we don't perform range checks on r and s as they are done by the arithmetization
	msInv := scalarApi.Div(msgHash, s)
	rsInv := scalarApi.Div(r, s)
	PK := sw_emulated.AffinePoint[emulated.P256Fp]{X: *qx, Y: *qy}
	Rprime := curve.JointScalarMulBase(&PK, rsInv, msInv, algopts.WithCompleteArithmetic())

	ResIsInfinity := api.And(
		baseApi.IsZero(&Rprime.X),
		baseApi.IsZero(&Rprime.Y),
	)
	// we need to perform modular equality check, but r and Rx are in different fields. We manually
	// enforce them to be in the same field by doing limbwise conversion.
	Rx := baseApi.ReduceStrict(&Rprime.X)
	RxInFr := scalarApi.NewElement(Rx.Limbs)

	// we don't have IsEqual method, so we do it through a diff
	diffRxR := scalarApi.Sub(RxInFr, r)
	isEqual := scalarApi.IsZero(diffRxR)

	res := api.And(
		api.Sub(1, ResIsInfinity), // signature is invalid if R' is infinity
		isEqual,                   // r == R'.X mod n
	)
	return res

}
