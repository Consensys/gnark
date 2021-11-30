package sw

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

func init() {
	companionsOnce.Do(func() {
		bls12377lambda := new(big.Int).SetBytes([]byte{0x45, 0x22, 0x17, 0xcc, 0x90, 0x00, 0x00, 0x01, 0x0a, 0x11, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00})
		bls12377thirdRootOne := new(big.Int).SetBytes([]byte{
			0x09, 0xb3, 0xaf, 0x05, 0xdd, 0x14, 0xf6, 0xec, 0x61, 0x9a, 0xaf, 0x7d, 0x34, 0x59,
			0x4a, 0xab, 0xc5, 0xed, 0x13, 0x47, 0x97, 0x0d, 0xec, 0x00, 0x45, 0x22, 0x17, 0xcc,
			0x90, 0x00, 0x00, 0x00, 0x85, 0x08, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x01})
		bls12377glvBasis := new(ecc.Lattice)
		ecc.PrecomputeLattice(ecc.BLS12_377.Info().Fp.Modulus(), bls12377lambda, bls12377glvBasis)
		companionCurves[ecc.BW6_761] = &companionConfig{
			thirdRootOne: bls12377thirdRootOne,
			glvBasis:     bls12377glvBasis,
			lambda:       bls12377lambda,
			fp:           ecc.BLS12_377.Info().Fp.Modulus(),
			fr:           ecc.BLS12_377.Info().Fr.Modulus(),
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
