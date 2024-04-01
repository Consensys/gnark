package sw_bls12377

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
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

var innerConfigBW6_761 innerConfig

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

// getInnerCurveConfig returns the configuration of the inner elliptic curve
// which can be defined on the scalars of outer curve.
func getInnerCurveConfig(outerCurveScalarField *big.Int) *innerConfig {
	if outerCurveScalarField.Cmp(ecc.BW6_761.ScalarField()) != 0 {
		panic(fmt.Sprintf("outer curve %s does not have a inner curve", outerCurveScalarField.String()))
	}

	mappingOnce.Do(func() {
		bls12377lambda := new(big.Int).SetBytes([]byte{0x45, 0x22, 0x17, 0xcc, 0x90, 0x00, 0x00, 0x01, 0x0a, 0x11, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00})
		bls12377thirdRootOne1 := new(big.Int).SetBytes([]byte{
			0x09, 0xb3, 0xaf, 0x05, 0xdd, 0x14, 0xf6, 0xec, 0x61, 0x9a, 0xaf, 0x7d, 0x34, 0x59,
			0x4a, 0xab, 0xc5, 0xed, 0x13, 0x47, 0x97, 0x0d, 0xec, 0x00, 0x45, 0x22, 0x17, 0xcc,
			0x90, 0x00, 0x00, 0x00, 0x85, 0x08, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x01})
		bls12377thirdRootOne2 := new(big.Int).Mul(bls12377thirdRootOne1, bls12377thirdRootOne1)
		bls12377glvBasis := new(ecc.Lattice)
		ecc.PrecomputeLattice(ecc.BLS12_377.ScalarField(), bls12377lambda, bls12377glvBasis)
		innerConfigBW6_761 = innerConfig{
			thirdRootOne1: bls12377thirdRootOne1,
			thirdRootOne2: bls12377thirdRootOne2,
			glvBasis:      bls12377glvBasis,
			lambda:        bls12377lambda,
			fp:            ecc.BLS12_377.BaseField(),
			fr:            ecc.BLS12_377.ScalarField(),
		}
	})

	return &innerConfigBW6_761
}

var (
	computedCurveTable [][2]*big.Int
	computedTwistTable [][4]*big.Int
)

func init() {
	computedCurveTable = computeCurveTable()
	computedTwistTable = computeTwistTable()
}

type curvePoints struct {
	G1x *big.Int      // base point x
	G1y *big.Int      // base point y
	G1m [][2]*big.Int // m*base points (x,y)
}

func getCurvePoints() curvePoints {
	_, _, g1aff, _ := bls12377.Generators()
	return curvePoints{
		G1x: g1aff.X.BigInt(new(big.Int)),
		G1y: g1aff.Y.BigInt(new(big.Int)),
		G1m: computedCurveTable,
	}
}

type twistPoints struct {
	G2x [2]*big.Int   // base point x ∈ E2
	G2y [2]*big.Int   // base point y ∈ E2
	G2m [][4]*big.Int // m*base points (x,y)
}

func getTwistPoints() twistPoints {
	_, _, _, g2aff := bls12377.Generators()
	return twistPoints{
		G2x: [2]*big.Int{g2aff.X.A0.BigInt(new(big.Int)), g2aff.X.A1.BigInt(new(big.Int))},
		G2y: [2]*big.Int{g2aff.Y.A0.BigInt(new(big.Int)), g2aff.Y.A1.BigInt(new(big.Int))},
		G2m: computedTwistTable,
	}

}
