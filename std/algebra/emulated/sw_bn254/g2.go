package sw_bn254

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

type G2Affine struct {
	X, Y fields_bn254.E2
}

func NewG2Affine(v bn254.G2Affine) G2Affine {
	return G2Affine{
		X: fields_bn254.E2{
			A0: emulated.ValueOf[emulated.BN254Fp](v.X.A0),
			A1: emulated.ValueOf[emulated.BN254Fp](v.X.A1),
		},
		Y: fields_bn254.E2{
			A0: emulated.ValueOf[emulated.BN254Fp](v.Y.A0),
			A1: emulated.ValueOf[emulated.BN254Fp](v.Y.A1),
		},
	}
}

func (p *G2Affine) AssertIsOnCurve(api frontend.API) {
	ba, _ := emulated.NewField[emulated.BN254Fp](api)
	e := fields_bn254.NewExt2(ba)

	// Y^2 = X^3 + b
	// where b = 3/(9+u)
	b := fields_bn254.E2{
		A0: emulated.ValueOf[emulated.BN254Fp]("19485874751759354771024239261021720505790618469301721065564631296452457478373"),
		A1: emulated.ValueOf[emulated.BN254Fp]("266929791119991161246907387137283842545076965332900288569378510910307636690"),
	}
	left := e.Square(&p.Y)
	right := e.Square(&p.X)
	right = e.Mul(right, &p.X)
	right = e.Add(right, &b)
	e.AssertIsEqual(left, right)
}
