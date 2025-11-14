package evmprecompiles

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

// P256Verify implements [P256Verify] precompile contract at address 0x100.
//
// This circuit performs ECDSA signature verification over the secp256r1
// elliptic curve (also known as P-256 or prime256v1).
//
// [P256Verify]: https://eips.ethereum.org/EIPS/eip-7951
func P256Verify(api frontend.API,
	msgHash emulated.Element[emulated.P256Fr],
	r, s emulated.Element[emulated.P256Fr],
	qx, qy emulated.Element[emulated.P256Fp],
) frontend.Variable {
	// Input validation:
	// 1. input_length == 160 ==> checked by the arithmetization
	// 2. 0 < r < n and 0 < s < n ==> checked by the arithmetization/ECDATA and enforced in `IsValid()`
	// 3. 0 ≤ qx < p and 0 ≤ qy < p ==> checked by the arithmetization/ECDATA
	// 4. (qx, qy) is a valid point on the curve P256 ==> checked by the arithmetization/ECDATA
	// 5. (qx, qy) is not (0,0) ==> checked by the arithmetization/ECDATA
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
