package sw_bls24315

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

func init() {
	companionsOnce.Do(func() {
		bls24315lambda := new(big.Int).SetBytes([]byte{0x19, 0x6d, 0xea, 0xc2,
			0x4a, 0x9d, 0xa1, 0x2b, 0x25, 0xfc, 0x7e, 0xc9, 0xcf, 0x92, 0x7a,
			0x99, 0x19, 0x73, 0x9f, 0x46, 0x27, 0xd9, 0x92, 0x6e, 0x38, 0x20,
			0xfb, 0xfa, 0x01, 0x80, 0x00, 0x01})
		bls24315thirdRootOne := new(big.Int).SetBytes([]byte{
			0x04, 0xc2, 0x3a, 0x02, 0xa2, 0x79, 0x2a, 0xda, 0xed, 0x93, 0x38,
			0xb4, 0xa8, 0x19, 0x5d, 0x81, 0xe9, 0xa0, 0x5f, 0x2f, 0x09, 0x88,
			0xc6, 0x57, 0x4e, 0xbb, 0xb2, 0xb0, 0xf7, 0x7c, 0x94, 0x0a, 0x4f,
			0x58, 0x14, 0xfe, 0x80, 0x60, 0x00, 0x02,
		})
		bls24315glvBasis := new(ecc.Lattice)
		ecc.PrecomputeLattice(ecc.BLS24_315.Info().Fr.Modulus(), bls24315lambda, bls24315glvBasis)
		companionCurves[ecc.BW6_633] = &companionConfig{
			thirdRootOne: bls24315thirdRootOne,
			glvBasis:     bls24315glvBasis,
			lambda:       bls24315lambda,
			fp:           ecc.BLS24_315.Info().Fp.Modulus(),
			fr:           ecc.BLS24_315.Info().Fr.Modulus(),
		}
	})
}

var companionsOnce sync.Once

type companionConfig struct {
	thirdRootOne *big.Int
	glvBasis     *ecc.Lattice
	lambda       *big.Int
	fr           *big.Int
	fp           *big.Int
}

var companionCurves = make(map[ecc.ID]*companionConfig)

func (cc *companionConfig) phi(api frontend.API, res, P *G1Affine) *G1Affine {
	res.X = api.Mul(P.X, cc.thirdRootOne)
	res.Y = P.Y
	return res
}

// companionCurve returns the configuration of the companion elliptic curve
// which can be defined on the scalars of main curve.
func companionCurve(main ecc.ID) *companionConfig {
	if cc, ok := companionCurves[main]; ok {
		return cc
	}
	panic(fmt.Sprintf("curve %s does not have a companion curve", main.String()))
}
