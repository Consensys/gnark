package sw_grumpkin

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/grumpkin"
	"github.com/consensys/gnark/frontend"
)

var mappingOnce sync.Once

type innerConfig struct {
	thirdRootOne1 *big.Int
	thirdRootOne2 *big.Int
	glvBasis      *ecc.Lattice
	lambda        *big.Int
	fr            *big.Int
	fp            *big.Int
}

var innerConfigBN254 innerConfig

func (cc *innerConfig) phi1(api frontend.API, res, P *G1Affine) *G1Affine {
	res.X = api.Mul(P.X, cc.thirdRootOne1)
	res.Y = P.Y
	return res
}

func (cc *innerConfig) phi2Neg(api frontend.API, res, P *G1Affine) *G1Affine {
	res.X = api.Mul(P.X, cc.thirdRootOne2)
	res.Y = api.Sub(0, P.Y)
	return res
}

// getInnerCurveConfig returns the configuration of the inner elliptic curve
// which can be defined on the scalars of outer curve.
func getInnerCurveConfig(outerCurveScalarField *big.Int) *innerConfig {
	if outerCurveScalarField.Cmp(ecc.BN254.ScalarField()) != 0 {
		panic(fmt.Sprintf("outer curve %s does not have a inner curve", outerCurveScalarField.String()))
	}

	mappingOnce.Do(func() {
		grumpkinlambda := new(big.Int).SetBytes([]byte{0x59, 0xe2, 0x6b, 0xce, 0xa0, 0xd4, 0x8b, 0xac, 0xd4, 0xf2, 0x63, 0xf1, 0xac, 0xdb, 0x5c, 0x4f, 0x57, 0x63, 0x47, 0x31, 0x77, 0xff, 0xff, 0xfe})
		grumpkinthirdRootOne1 := new(big.Int).SetBytes([]byte{0xb3, 0xc4, 0xd7, 0x9d, 0x41, 0xa9, 0x17, 0x58, 0x5b, 0xfc, 0x41, 0x8, 0x8d, 0x8d, 0xaa, 0xa7, 0x8b, 0x17, 0xea, 0x66, 0xb9, 0x9c, 0x90, 0xdd})
		grumpkinthirdRootOne2 := new(big.Int).Mul(grumpkinthirdRootOne1, grumpkinthirdRootOne1)
		grumpkinglvBasis := new(ecc.Lattice)
		ecc.PrecomputeLattice(ecc.GRUMPKIN.ScalarField(), grumpkinlambda, grumpkinglvBasis)
		innerConfigBN254 = innerConfig{
			thirdRootOne1: grumpkinthirdRootOne1,
			thirdRootOne2: grumpkinthirdRootOne2,
			glvBasis:      grumpkinglvBasis,
			lambda:        grumpkinlambda,
			fp:            ecc.GRUMPKIN.BaseField(),
			fr:            ecc.GRUMPKIN.ScalarField(),
		}
	})

	return &innerConfigBN254
}

var (
	computedCurveTable [][2]*big.Int
)

func init() {
	computedCurveTable = computeCurveTable()
}

type curvePoints struct {
	G1x *big.Int      // base point x
	G1y *big.Int      // base point y
	G1m [][2]*big.Int // m*base points (x,y)
}

func getCurvePoints() curvePoints {
	g1aff, _ := grumpkin.Generators()
	return curvePoints{
		G1x: g1aff.X.BigInt(new(big.Int)),
		G1y: g1aff.Y.BigInt(new(big.Int)),
		G1m: computedCurveTable,
	}
}
