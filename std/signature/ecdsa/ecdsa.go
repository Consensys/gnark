package ecdsa

import (
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
	qxBits, rbits := pk.prepareVerification(api, params, msg, sig)
	for i := range rbits {
		api.AssertIsEqual(rbits[i], qxBits[i])
	}
}

// IsValid returns a boolean indicating if the signature sig is valid for public
// key pk and the message (return value 1 for valid signature and 0 for invalid
// signature). It is equivalent to [PublicKey.Verify] but allows for more
// flexible usage in circuits which could allow processing invalid signatures.
//
// The curve parameters params define the elliptic curve.
//
// We assume that the message msg is already hashed to the scalar field.
func (pk PublicKey[T, S]) IsValid(api frontend.API, params sw_emulated.CurveParams, msg *emulated.Element[S], sig *Signature[S]) frontend.Variable {
	qxBits, rbits := pk.prepareVerification(api, params, msg, sig)
	verified := frontend.Variable(1)
	for i := range rbits {
		res := api.IsZero(api.Sub(rbits[i], qxBits[i]))
		verified = api.And(verified, res)
	}
	return verified

}

// prepareVerification computes Q = [r/s]PK + [m/s]G and returns the bits of Q.x
// and r. The verifier should check that the bits are equal.
func (pk PublicKey[T, S]) prepareVerification(api frontend.API, params sw_emulated.CurveParams, msg *emulated.Element[S], sig *Signature[S]) ([]frontend.Variable, []frontend.Variable) {
	cr, err := sw_emulated.New[T, S](api, params)
	if err != nil {
		panic(err)
	}
	scalarApi, err := emulated.NewField[S](api)
	if err != nil {
		panic(err)
	}
	baseApi, err := emulated.NewField[T](api)
	if err != nil {
		panic(err)
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
		panic("non-equal lengths")
	}
	return qxBits, rbits
}
