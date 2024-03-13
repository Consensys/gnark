package sw_bls24315

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
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

var innerConfigBW6_633 innerConfig

// getInnerCurveConfig returns the configuration of the inner elliptic curve
// which can be defined on the scalars of outer curve.
func getInnerCurveConfig(outerCurveScalarField *big.Int) *innerConfig {
	if outerCurveScalarField.Cmp(ecc.BW6_633.ScalarField()) != 0 {
		panic(fmt.Sprintf("outer curve %s does not have a inner curve", outerCurveScalarField.String()))
	}
	mappingOnce.Do(func() {
		bls24315lambda := new(big.Int).SetBytes([]byte{0x19, 0x6d, 0xea, 0xc2,
			0x4a, 0x9d, 0xa1, 0x2b, 0x25, 0xfc, 0x7e, 0xc9, 0xcf, 0x92, 0x7a,
			0x99, 0x19, 0x73, 0x9f, 0x46, 0x27, 0xd9, 0x92, 0x6e, 0x38, 0x20,
			0xfb, 0xfa, 0x01, 0x80, 0x00, 0x01})
		bls24315thirdRootOne1 := new(big.Int).SetBytes([]byte{
			0x04, 0xc2, 0x3a, 0x02, 0xa2, 0x79, 0x2a, 0xda, 0xed, 0x93, 0x38,
			0xb4, 0xa8, 0x19, 0x5d, 0x81, 0xe9, 0xa0, 0x5f, 0x2f, 0x09, 0x88,
			0xc6, 0x57, 0x4e, 0xbb, 0xb2, 0xb0, 0xf7, 0x7c, 0x94, 0x0a, 0x4f,
			0x58, 0x14, 0xfe, 0x80, 0x60, 0x00, 0x02,
		})
		bls24315thirdRootOne2 := new(big.Int).Mul(bls24315thirdRootOne1, bls24315thirdRootOne1)
		bls24315glvBasis := new(ecc.Lattice)
		ecc.PrecomputeLattice(ecc.BLS24_315.ScalarField(), bls24315lambda, bls24315glvBasis)
		innerConfigBW6_633 = innerConfig{
			thirdRootOne1: bls24315thirdRootOne1,
			thirdRootOne2: bls24315thirdRootOne2,
			glvBasis:      bls24315glvBasis,
			lambda:        bls24315lambda,
			fp:            ecc.BLS24_315.BaseField(),
			fr:            ecc.BLS24_315.ScalarField(),
		}
	})
	return &innerConfigBW6_633
}

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

func (cc *innerConfig) phi2(api frontend.API, res, P *g2AffP) *g2AffP {
	res.X.MulByFp(api, P.X, cc.thirdRootOne2)
	res.Y = P.Y
	return res
}

func (cc *innerConfig) phi1Neg(api frontend.API, res, P *g2AffP) *g2AffP {
	res.X.MulByFp(api, P.X, cc.thirdRootOne1)
	res.Y.Neg(api, P.Y)
	return res
}

type curvePoints struct {
	G1x *big.Int      // base point x
	G1y *big.Int      // base point y
	G1m [][2]*big.Int // m*base points (x,y)
}

var (
	computedCurveTable [][2]*big.Int
	computedTwistTable [][8]*big.Int
)

func init() {
	computedCurveTable = computeCurveTable()
	computedTwistTable = computeTwistTable()
}

func getCurvePoints() curvePoints {
	_, _, g1aff, _ := bls24315.Generators()
	return curvePoints{
		G1x: g1aff.X.BigInt(new(big.Int)),
		G1y: g1aff.Y.BigInt(new(big.Int)),
		G1m: computedCurveTable,
	}
}

type twistPoints struct {
	G2x [4]*big.Int   // base point x ∈ E4
	G2y [4]*big.Int   // base point y ∈ E4
	G2m [][8]*big.Int // m*base points (x,y)
}

func getTwistPoints() twistPoints {
	_, _, _, g2aff := bls24315.Generators()
	return twistPoints{
		G2x: [4]*big.Int{
			g2aff.X.B0.A0.BigInt(new(big.Int)),
			g2aff.X.B0.A1.BigInt(new(big.Int)),
			g2aff.X.B1.A0.BigInt(new(big.Int)),
			g2aff.X.B1.A1.BigInt(new(big.Int)),
		},
		G2y: [4]*big.Int{
			g2aff.Y.B0.A0.BigInt(new(big.Int)),
			g2aff.Y.B0.A1.BigInt(new(big.Int)),
			g2aff.Y.B1.A0.BigInt(new(big.Int)),
			g2aff.Y.B1.A1.BigInt(new(big.Int)),
		},
		G2m: computedTwistTable,
	}

}
