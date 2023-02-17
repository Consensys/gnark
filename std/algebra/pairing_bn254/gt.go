package pairing_bn254

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

type GTEl = e12

func NewGTEl(v bn254.GT) GTEl {
	return GTEl{
		C0: e6{
			B0: e2{
				A0: emulated.ValueOf[emulated.BN254Fp](v.C0.B0.A0),
				A1: emulated.ValueOf[emulated.BN254Fp](v.C0.B0.A1),
			},
			B1: e2{
				A0: emulated.ValueOf[emulated.BN254Fp](v.C0.B1.A0),
				A1: emulated.ValueOf[emulated.BN254Fp](v.C0.B1.A1),
			},
			B2: e2{
				A0: emulated.ValueOf[emulated.BN254Fp](v.C0.B2.A0),
				A1: emulated.ValueOf[emulated.BN254Fp](v.C0.B2.A1),
			},
		},
		C1: e6{
			B0: e2{
				A0: emulated.ValueOf[emulated.BN254Fp](v.C1.B0.A0),
				A1: emulated.ValueOf[emulated.BN254Fp](v.C1.B0.A1),
			},
			B1: e2{
				A0: emulated.ValueOf[emulated.BN254Fp](v.C1.B1.A0),
				A1: emulated.ValueOf[emulated.BN254Fp](v.C1.B1.A1),
			},
			B2: e2{
				A0: emulated.ValueOf[emulated.BN254Fp](v.C1.B2.A0),
				A1: emulated.ValueOf[emulated.BN254Fp](v.C1.B2.A1),
			},
		},
	}
}
