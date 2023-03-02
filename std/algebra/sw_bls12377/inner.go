package sw_bls12377

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

var innerConfigBW6_761 innerConfig

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

type CurvePoints struct {
	G1x *big.Int      // base point x
	G1y *big.Int      // base point y
	G1m [][2]*big.Int // m*base points (x,y)
}

func GetBLS12377CurvePoints() CurvePoints {
	g1x, _ := new(big.Int).SetString("8848defe740a67c8fc6225bf87ff5485951e2caa9d41bb188282c8bd37cb5cd5481512ffcd394eeab9b16eb21be9ef", 16)
	g1y, _ := new(big.Int).SetString("1914a69c5102eff1f674f5d30afeec4bd7fb348ca3e52d96d182ad44fb82305c2fe3d3634a9591afd82de55559c8ea6", 16)
	return CurvePoints{
		G1x: g1x,
		G1y: g1y,
		G1m: computeBLS12377CurveTable(),
	}
}

type TwistPoints struct {
	G2x [2]*big.Int   // base point x ∈ E2
	G2y [2]*big.Int   // base point y ∈ E2
	G2m [][4]*big.Int // m*base points (x,y)
}

func GetBLS12377TwistPoints() TwistPoints {
	g2x0, _ := new(big.Int).SetString("18480be71c785fec89630a2a3841d01c565f071203e50317ea501f557db6b9b71889f52bb53540274e3e48f7c005196", 16)
	g2x1, _ := new(big.Int).SetString("ea6040e700403170dc5a51b1b140d5532777ee6651cecbe7223ece0799c9de5cf89984bff76fe6b26bfefa6ea16afe", 16)
	g2y0, _ := new(big.Int).SetString("690d665d446f7bd960736bcbb2efb4de03ed7274b49a58e458c282f832d204f2cf88886d8c7c2ef094094409fd4ddf", 16)
	g2y1, _ := new(big.Int).SetString("f8169fd28355189e549da3151a70aa61ef11ac3d591bf12463b01acee304c24279b83f5e52270bd9a1cdd185eb8f93", 16)
	return TwistPoints{
		G2x: [2]*big.Int{g2x0, g2x1},
		G2y: [2]*big.Int{g2y0, g2y1},
		G2m: computeBLS12377TwistTable(),
	}

}
