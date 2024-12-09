package p256

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

type EcdsaCircuit[T, S emulated.FieldParams] struct {
	Commitment frontend.Variable `gnark:",public"` // Keccak256(Pub[0], Msg[0], Sig[1], Msg[1], ...)[1:32], ignore the first byte, since BN254 order < uint256

	Pub [NumSignatures]PublicKey[T, S]     `gnark:",secret"`
	Msg [NumSignatures]emulated.Element[S] `gnark:",secret"`
	Sig [NumSignatures]Signature[S]        `gnark:",secret"`
}

func (c *EcdsaCircuit[T, S]) Define(api frontend.API) error {
	// Verify all ECDSA-P256 signatures
	for i := range c.Sig {
		c.Pub[i].Verify(api, sw_emulated.GetCurveParams[T](), &c.Msg[i], &c.Sig[i])
	}
	// Keccak256 Commit to all signatures
	h, err := sha3.NewLegacyKeccak256(api)
	if err != nil {
		return err
	}
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return err
	}

	var tInstance T
	var sInstance S
	perSignatureHashSize := 2*tInstance.NbLimbs() + sInstance.NbLimbs()

	hashIn := make([]uints.U8, 0, NumSignatures*perSignatureHashSize)
	for i := 0; i < NumSignatures; i++ {
		// hashIn += Pub[i].X
		// Pay attention to the ordering!
		for j := len(c.Pub[i].X.Limbs) - 1; j >= 0; j-- {
			pubXLimb := uapi.UnpackMSB(uapi.ValueOf(c.Pub[i].X.Limbs[j]))
			hashIn = append(hashIn, pubXLimb[:]...)
		}
		// hashIn += Pub[i].Y
		for j := len(c.Pub[i].X.Limbs) - 1; j >= 0; j-- {
			pubYLimb := uapi.UnpackMSB(uapi.ValueOf(c.Pub[i].Y.Limbs[j]))
			hashIn = append(hashIn, pubYLimb[:]...)
		}
		// hashIn += Msg[i]
		for j := len(c.Msg[i].Limbs) - 1; j >= 0; j-- {
			msgLimb := uapi.UnpackMSB(uapi.ValueOf(c.Msg[i].Limbs[j]))
			hashIn = append(hashIn, msgLimb[:]...)
		}
	}
	h.Write(hashIn)
	hashOutU8 := h.Sum() // Keccak256(Pub[0], Msg[0], Sig[1], Msg[1], ...)[0:32]

	// Commitment = hashoutU8[1:32]
	hashOutU8[0] = uints.NewU8(0) // ignore the first byte, since BN254 order < uint256
	// Big endian [32]bytes to BigInt
	for i := range hashOutU8 {
		index := len(hashOutU8) - i - 1
		c.Commitment = api.MulAcc(c.Commitment, hashOutU8[index].Val, 1<<(i*8))
	}
	return nil
}

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
	sInv := scalarApi.Inverse(&sig.S)
	msInv := scalarApi.MulMod(msg, sInv)
	rsInv := scalarApi.MulMod(&sig.R, sInv)

	// q = [rsInv]pkpt + [msInv]g
	q := cr.JointScalarMulBase(&pkpt, rsInv, msInv)
	qx := baseApi.Reduce(&q.X)
	qxBits := baseApi.ToBits(qx)
	rbits := scalarApi.ToBits(&sig.R)
	if len(rbits) != len(qxBits) {
		panic("non-equal lengths")
	}
	for i := range rbits {
		api.AssertIsEqual(rbits[i], qxBits[i])
	}
}
