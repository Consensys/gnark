package sw

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/hint"
)

type wrappedHint struct {
	curve ecc.ID
	inner hint.Function
}

func (wh *wrappedHint) UUID() hint.ID {
	return hint.UUID(wh.inner.Call, uint64(wh.curve))
}

func (wh *wrappedHint) Call(curveID ecc.ID, inputs []*big.Int, res []*big.Int) error {
	return wh.inner.Call(curveID, inputs, res)
}

func (wh *wrappedHint) NbOutputs(curveID ecc.ID, nInputs int) (nOutputs int) {
	return wh.inner.NbOutputs(curveID, nInputs)
}

func (wh *wrappedHint) String() string {
	return wh.inner.String()
}

func getDecompositionHint(lambda *big.Int, modulus *big.Int, lattice *ecc.Lattice) hint.Function {
	return hint.NewStaticHint(func(curve ecc.ID, inputs []*big.Int, res []*big.Int) error {
		sp := ecc.SplitScalar(inputs[0], lattice)
		res[0].Set(&(sp[0]))
		res[1].Set(&(sp[1]))
		one := big.NewInt(1)
		// add (lambda+1, lambda) until scalar compostion is over Fr to ensure that
		// the high bits are set in decomposition.
		for res[0].Cmp(lambda) < 1 && res[1].Cmp(lambda) < 1 {
			res[0].Add(res[0], lambda)
			res[0].Add(res[0], one)
			res[1].Add(res[1], lambda)
		}
		// figure out how many times we have overflowed
		res[2].Mul(res[1], lambda).Add(res[2], res[0])
		res[2].Sub(res[2], inputs[0])
		res[2].Div(res[2], modulus)

		return nil
	}, 1, 3)
}

func init() {
	mappingOnce.Do(func() {
		bls12377frmodulus := ecc.BLS12_377.Info().Fr.Modulus()
		bls12377lambda := new(big.Int).SetBytes([]byte{0x45, 0x22, 0x17, 0xcc, 0x90, 0x00, 0x00, 0x01, 0x0a, 0x11, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00})
		bls12377thirdRootOne := new(big.Int).SetBytes([]byte{
			0x09, 0xb3, 0xaf, 0x05, 0xdd, 0x14, 0xf6, 0xec, 0x61, 0x9a, 0xaf, 0x7d, 0x34, 0x59,
			0x4a, 0xab, 0xc5, 0xed, 0x13, 0x47, 0x97, 0x0d, 0xec, 0x00, 0x45, 0x22, 0x17, 0xcc,
			0x90, 0x00, 0x00, 0x00, 0x85, 0x08, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x01})
		bls12377glvBasis := new(ecc.Lattice)
		ecc.PrecomputeLattice(bls12377frmodulus, bls12377lambda, bls12377glvBasis)
		bls12377ateLoop := uint64(9586122913090633729)
		bls12377ateLoopDecomp := []int8{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1}
		bls12377hintFn := &wrappedHint{curve: ecc.BLS12_377, inner: getDecompositionHint(bls12377lambda, bls12377frmodulus, bls12377glvBasis)}
		hint.Register(bls12377hintFn)
		innerCurves[ecc.BW6_761] = &innerConfig{
			thirdRootOne:      bls12377thirdRootOne,
			glvBasis:          bls12377glvBasis,
			lambda:            bls12377lambda,
			fp:                ecc.BLS12_377.Info().Fp.Modulus(),
			fr:                bls12377frmodulus,
			decompose:         bls12377hintFn,
			ateLoop:           bls12377ateLoop,
			ateLoopDecomposed: bls12377ateLoopDecomp,
		}
		bls24315frmodulus := ecc.BLS24_315.Info().Fr.Modulus()
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
		ecc.PrecomputeLattice(bls24315frmodulus, bls24315lambda, bls24315glvBasis)
		bls24315ateLoop := uint64(3218079743)
		bls24315ateLoopDecomp := []int8{-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, -1, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1}
		bls24315hintFn := &wrappedHint{curve: ecc.BLS24_315, inner: getDecompositionHint(bls24315lambda, bls24315frmodulus, bls24315glvBasis)}
		hint.Register(bls24315hintFn)
		innerCurves[ecc.BW6_633] = &innerConfig{
			thirdRootOne:      bls24315thirdRootOne,
			glvBasis:          bls24315glvBasis,
			lambda:            bls24315lambda,
			fp:                ecc.BLS24_315.Info().Fp.Modulus(),
			fr:                bls24315frmodulus,
			decompose:         bls24315hintFn,
			ateLoop:           bls24315ateLoop,
			ateLoopDecomposed: bls24315ateLoopDecomp,
		}
	})
}

var mappingOnce sync.Once

type innerConfig struct {
	thirdRootOne      *big.Int
	glvBasis          *ecc.Lattice
	lambda            *big.Int
	fr                *big.Int
	fp                *big.Int
	decompose         hint.Function
	ateLoop           uint64
	ateLoopDecomposed []int8
}

var innerCurves = make(map[ecc.ID]*innerConfig)

func (p *G1Affine) phi(res, P *G1Affine) *G1Affine {
	api := p.api
	res.X = api.Mul(P.X, p.config.thirdRootOne)
	res.Y = P.Y
	return res
}

// getInnerConfig returns the configuration of the inner elliptic curve
// which can be defined on the scalars of outer curve.
func getInnerConfig(outerCurve ecc.ID) (*innerConfig, error) {
	if cc, ok := innerCurves[outerCurve]; ok {
		return cc, nil
	}
	return nil, fmt.Errorf("incombatible with outer curve %s", outerCurve)
}
