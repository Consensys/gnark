package evmprecompiles

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

// P256Verify implements [P256Verify] precompile contract at address 0x100.
//
// ...
//
// [P256Verify]: https://eips.ethereum.org/EIPS/eip-7951
func P256Verify(api frontend.API,
	msgHash emulated.Element[emulated.P256Fr],
	r, s emulated.Element[emulated.P256Fr],
	qx, qy emulated.Element[emulated.P256Fp],
) frontend.Variable {
	// Input validation
	// 1. input_length == 160 ==> enforced by emulated.P256Fr, and emulated.P256Fp?
	// 2. 0 < r < n and 0 < s < n ==> enforced by IsValid()
	// 3. (qx, qy) is a valid point on the curve P256
	curve, err := sw_emulated.New[emulated.P256Fp, emulated.P256Fr](api, sw_emulated.GetP256Params())
	if err != nil {
		panic(fmt.Sprintf("new curve: %v", err))
	}
	q := sw_emulated.AffinePoint[emulated.P256Fp]{
		X: qx,
		Y: qy,
	}
	curve.AssertIsOnCurve(&q) // todo: return bit
	// 4. (qx, qy) != O
	// impelemnt in sw_emulated

	pk := ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{
		X: qx,
		Y: qy,
	}
	sig := ecdsa.Signature[emulated.P256Fr]{
		R: r,
		S: s,
	}

	verified := pk.IsValid(api, sw_emulated.GetCurveParams[emulated.P256Fp](), &msgHash, &sig)

	return verified
}
