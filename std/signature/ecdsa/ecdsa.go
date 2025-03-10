package ecdsa

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// Signature represents the signature for some message.
type Signature[Scalar emulated.FieldParams] struct {
	R, S emulated.Element[Scalar]
}

// PublicKey represents the public key to verify the signature for.
type PublicKey[Base, Scalar emulated.FieldParams] sw_emulated.AffinePoint[Base]

// Verify asserts that the signature sig verifies for the message msg and public
// key pk. The curve parameters params define the elliptic curve.
//
// We assume that the message msg is already hashed to the scalar field.
func (pk PublicKey[T, S]) Verify(api frontend.API, params sw_emulated.CurveParams, msg *emulated.Element[S], sig *Signature[S]) {
	qxBits, rbits, err := pk.checkParams(api, params, msg, sig)
	if err != nil {
		panic("ecdsa check params error")
	}
	for i := range rbits {
		api.AssertIsEqual(rbits[i], qxBits[i])
	}
}

// IsVerified modified from the Verify method, asserts that the signature sig verifies for the message msg and public
// key pk. The curve parameters params define the elliptic curve.
// We assume that the message msg is already hashed to the scalar field.
// If the signature is valid, it returns 1; otherwise, it returns  0
func (pk PublicKey[T, S]) IsVerified(api frontend.API, params sw_emulated.CurveParams, msg *emulated.Element[S], sig *Signature[S]) frontend.Variable {
	qxBits, rbits, err := pk.checkParams(api, params, msg, sig)
	if err != nil {
		panic("ecdsa check params error")
	}
	verified := frontend.Variable(1)
	for i := range rbits {
		res := api.IsZero(api.Sub(rbits[i], qxBits[i]))
		verified = api.And(verified, res)
	}
	return verified

}

func (pk PublicKey[T, S]) checkParams(api frontend.API, params sw_emulated.CurveParams, msg *emulated.Element[S], sig *Signature[S]) ([]frontend.Variable, []frontend.Variable, error) {
	cr, err := sw_emulated.New[T, S](api, params)
	if err != nil {
		return nil, nil, err
	}
	scalarApi, err := emulated.NewField[S](api)
	if err != nil {
		return nil, nil, err
	}
	baseApi, err := emulated.NewField[T](api)
	if err != nil {
		return nil, nil, err
	}
	pkpt := sw_emulated.AffinePoint[T](pk)
	msInv := scalarApi.Div(msg, &sig.S)
	rsInv := scalarApi.Div(&sig.R, &sig.S)

	// q = [rsInv]pkpt + [msInv]g
	q := cr.JointScalarMulBase(&pkpt, rsInv, msInv)
	qx := baseApi.Reduce(&q.X)
	qxBits := baseApi.ToBits(qx)
	rbits := scalarApi.ToBits(&sig.R)
	if len(rbits) != len(qxBits) {
		return nil, nil, fmt.Errorf("non-equal lengths")
	}
	return qxBits, rbits, nil
}
