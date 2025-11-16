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
// [P256Verify]: https://eips.ethereum.org/EIPS/eip-7951
func P256Verify(api frontend.API,
	msgHash *emulated.Element[emulated.P256Fr],
	r, s *emulated.Element[emulated.P256Fr],
	qx, qy *emulated.Element[emulated.P256Fp],
) frontend.Variable {
	// XXX: I think it is more efficient to just compute JointScalarMul here -- we don't need to do range checks.
	// XXX: should we also explicitly check that the recovered point is not infinity? It is implicit anyway as we never receive `r==0` here (because of arithmetization checks),
	// but I think we should at least mention it?
	// XXX: and I think we also cannot directly check as the IsValid method checks that the r and r' are equal bitwise, but the EIP defines the check modulo n.

	// Input validation:
	// 1. input_length == 160 ==> checked by the arithmetization
	// 2. 0 < r < n and 0 < s < n ==> checked by the arithmetization/ECDATA and enforced in `IsValid()`
	// 3. 0 ≤ qx < p and 0 ≤ qy < p ==> checked by the arithmetization/ECDATA
	// 4. (qx, qy) is a valid point on the curve P256 ==> checked by the arithmetization/ECDATA
	// 5. (qx, qy) is not (0,0) ==> checked by the arithmetization/ECDATA

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
	sinv := scalarApi.Inverse(s)
	msInv := scalarApi.Mul(msgHash, sinv)
	rsInv := scalarApi.Mul(r, sinv)
	msInvG := curve.ScalarMulBase(msInv, algopts.WithCompleteArithmetic())
	PK := sw_emulated.AffinePoint[emulated.P256Fp]{X: *qx, Y: *qy}
	rsInvQ := curve.ScalarMul(&PK, rsInv, algopts.WithCompleteArithmetic())
	Rprime := curve.AddUnified(msInvG, rsInvQ)

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
