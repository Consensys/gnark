package sw_bls24315

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
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

func (cc *innerConfig) phi2(api frontend.API, res, P *G2Affine) *G2Affine {
	res.X.MulByFp(api, P.X, cc.thirdRootOne2)
	res.Y = P.Y
	return res
}

type CurvePoints struct {
	G1x *big.Int      // base point x
	G1y *big.Int      // base point y
	G1m [][2]*big.Int // m*base points (x,y)
}

func GetCurvePoints() CurvePoints {
	g1x, _ := new(big.Int).SetString("41a0a424393988da1b2b117076ef6e4f54b344cc46dde3c983603a832cb638dbf4b721710866097", 16)
	g1y, _ := new(big.Int).SetString("2e6f83c55deff20227ecdf0db2bb2ebb5d72c8a29010871d3cce9059e83dfb96f2922d5da4e4e5f", 16)
	return CurvePoints{
		G1x: g1x,
		G1y: g1y,
		G1m: computeCurveTable(),
	}
}

type TwistPoints struct {
	G2x [4]*big.Int   // base point x ∈ E4
	G2y [4]*big.Int   // base point y ∈ E4
	G2m [][8]*big.Int // m*base points (x,y)
}

func GetTwistPoints() TwistPoints {
	g2x0, _ := new(big.Int).SetString("2f339ada8942f92aefa14196bfee2552a7c5675f5e5e9da798458f72ff50f96f5c357cf13710f63", 16)
	g2x1, _ := new(big.Int).SetString("20b1a8dca4b18842b40079be727cbfd1a16ed134a080b759ae503618e92871697838dc4c689911c", 16)
	g2x2, _ := new(big.Int).SetString("16eab1e76670eb9affa1bc77400be688d5cd69566f9325b329b40db85b47f236d5c34e8ffed7536", 16)
	g2x3, _ := new(big.Int).SetString("6e8c608261f21c41f2479ca4824deba561b9689a9c03a5b8b36a6cbbed0a7d9468e07e557d8569", 16)
	g2y0, _ := new(big.Int).SetString("3cdd8218baa5276421c9923cde33a45399a1d878d5202fae600a8502a29681f74ccdcc053b278b7", 16)
	g2y1, _ := new(big.Int).SetString("3a079c670190bb49b1bd21e10aac3191535e32ce99da592ddfa8bd09d57a7374ed63ad7f25e398d", 16)
	g2y2, _ := new(big.Int).SetString("1b38dd0c5ec49a0883a950c631c688eb3b01f45b7c0d2990cd99052005ebf2fa9e7043bbd605ef5", 16)
	g2y3, _ := new(big.Int).SetString("495d6de2e4fed6be3e1d24dd724163e01d88643f7e83d31528ab0a80ced619175a1a104574ac83", 16)
	return TwistPoints{
		G2x: [4]*big.Int{g2x0, g2x1, g2x2, g2x3},
		G2y: [4]*big.Int{g2y0, g2y1, g2y2, g2y3},
		G2m: computeTwistTable(),
	}

}
