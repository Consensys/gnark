package sw_octobear

import (
	nativeoctobear "github.com/consensys/gnark-crypto/ecc/octobear"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/fields_octobear"
)

type E2 = fields_octobear.E2
type E4 = fields_octobear.E4
type E8 = fields_octobear.E8

type G1Affine struct {
	X, Y E8
}

func NewG1Affine(v nativeoctobear.G1Affine) G1Affine {
	return G1Affine{X: fields_octobear.NewE8(v.X), Y: fields_octobear.NewE8(v.Y)}
}

func (p *G1Affine) Assign(v *nativeoctobear.G1Affine) {
	p.X.Assign(&v.X)
	p.Y.Assign(&v.Y)
}

func (p *G1Affine) AssertIsEqual(api frontend.API, other G1Affine) {
	p.X.AssertIsEqual(api, other.X)
	p.Y.AssertIsEqual(api, other.Y)
}
