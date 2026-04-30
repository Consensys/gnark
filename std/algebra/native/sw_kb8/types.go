package sw_kb8

import (
	nativekb8 "github.com/consensys/gnark-crypto/ecc/kb8"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/fields_kb8"
)

type E2 = fields_kb8.E2
type E4 = fields_kb8.E4
type E8 = fields_kb8.E8

type G1Affine struct {
	X, Y E8
}

func NewG1Affine(v nativekb8.G1Affine) G1Affine {
	return G1Affine{X: fields_kb8.NewE8(v.X), Y: fields_kb8.NewE8(v.Y)}
}

func (p *G1Affine) Assign(v *nativekb8.G1Affine) {
	p.X.Assign(&v.X)
	p.Y.Assign(&v.Y)
}

func (p *G1Affine) AssertIsEqual(api frontend.API, other G1Affine) {
	p.X.AssertIsEqual(api, other.X)
	p.Y.AssertIsEqual(api, other.Y)
}
