package stats

import (
	"math"
	"sync"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/algebra/native/sw_bls24315"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
)

var (
	initOnce sync.Once
	snippets = make(map[string]Circuit)
)

func GetSnippets() map[string]Circuit {
	initOnce.Do(initSnippets)
	return snippets
}

type snippet func(api frontend.API, newVariable func() frontend.Variable)

func registerSnippet(name string, snippet snippet, curves ...ecc.ID) {
	if _, ok := snippets[name]; ok {
		panic("circuit " + name + " already registered")
	}
	if len(curves) == 0 {
		curves = gnark.Curves()
	}
	snippets[name] = Circuit{makeSnippetCircuit(snippet), curves}
}

func initSnippets() {
	// add api snippets
	registerSnippet("api/IsZero", func(api frontend.API, newVariable func() frontend.Variable) {
		_ = api.IsZero(newVariable())
	})

	registerSnippet("api/Lookup2", func(api frontend.API, newVariable func() frontend.Variable) {
		_ = api.Lookup2(newVariable(), newVariable(), newVariable(), newVariable(), newVariable(), newVariable())
	})

	registerSnippet("api/AssertIsLessOrEqual", func(api frontend.API, newVariable func() frontend.Variable) {
		api.AssertIsLessOrEqual(newVariable(), newVariable())
	})
	registerSnippet("api/AssertIsLessOrEqual/constant_bound_64_bits", func(api frontend.API, newVariable func() frontend.Variable) {
		bound := uint64(math.MaxUint64)
		api.AssertIsLessOrEqual(newVariable(), bound)
	})

	// add std snippets
	registerSnippet("math/bits.ToBinary", func(api frontend.API, newVariable func() frontend.Variable) {
		_ = bits.ToBinary(api, newVariable())
	})
	registerSnippet("math/bits.ToBinary/unconstrained", func(api frontend.API, newVariable func() frontend.Variable) {
		_ = bits.ToBinary(api, newVariable(), bits.WithUnconstrainedOutputs())
	})
	registerSnippet("math/bits.ToTernary", func(api frontend.API, newVariable func() frontend.Variable) {
		_ = bits.ToTernary(api, newVariable())
	})
	registerSnippet("math/bits.ToTernary/unconstrained", func(api frontend.API, newVariable func() frontend.Variable) {
		_ = bits.ToTernary(api, newVariable(), bits.WithUnconstrainedOutputs())
	})
	registerSnippet("math/bits.ToNAF", func(api frontend.API, newVariable func() frontend.Variable) {
		_ = bits.ToNAF(api, newVariable())
	})
	registerSnippet("math/bits.ToNAF/unconstrained", func(api frontend.API, newVariable func() frontend.Variable) {
		_ = bits.ToNAF(api, newVariable(), bits.WithUnconstrainedOutputs())
	})

	registerSnippet("hash/mimc", func(api frontend.API, newVariable func() frontend.Variable) {
		mimc, _ := mimc.NewMiMC(api)
		mimc.Write(newVariable())
		_ = mimc.Sum()
	})
	registerSnippet("math/emulated/secp256k1_64", func(api frontend.API, newVariable func() frontend.Variable) {
		secp256k1, _ := emulated.NewField[emulated.Secp256k1Fp](api)

		newElement := func() *emulated.Element[emulated.Secp256k1Fp] {
			limbs := make([]frontend.Variable, emulated.Secp256k1Fp{}.NbLimbs())
			for i := 0; i < len(limbs); i++ {
				limbs[i] = newVariable()
			}
			return secp256k1.NewElement(limbs)
		}

		x13 := secp256k1.Mul(newElement(), newElement())
		x13 = secp256k1.Mul(x13, newElement())
		five := emulated.ValueOf[emulated.Secp256k1Fp](5)
		fx2 := secp256k1.Mul(&five, newElement())
		nom := secp256k1.Sub(fx2, x13)
		denom := secp256k1.Add(newElement(), newElement())
		denom = secp256k1.Add(denom, newElement())
		denom = secp256k1.Add(denom, newElement())
		free := secp256k1.Div(nom, denom)
		res := secp256k1.Add(x13, fx2)
		res = secp256k1.Add(res, free)
		secp256k1.AssertIsEqual(res, newElement())
	})

	registerSnippet("pairing_bls12377", func(api frontend.API, newVariable func() frontend.Variable) {

		var dummyG1 sw_bls12377.G1Affine
		var dummyG2 sw_bls12377.G2Affine
		dummyG1.X = newVariable()
		dummyG1.Y = newVariable()
		dummyG2.P.X.A0 = newVariable()
		dummyG2.P.X.A1 = newVariable()
		dummyG2.P.Y.A0 = newVariable()
		dummyG2.P.Y.A1 = newVariable()

		_, _ = sw_bls12377.Pair(api, []sw_bls12377.G1Affine{dummyG1}, []sw_bls12377.G2Affine{dummyG2})

	}, ecc.BW6_761)

	registerSnippet("pairing_bls24315", func(api frontend.API, newVariable func() frontend.Variable) {

		var dummyG1 sw_bls24315.G1Affine
		var dummyG2 sw_bls24315.G2Affine
		dummyG1.X = newVariable()
		dummyG1.Y = newVariable()
		dummyG2.P.X.B0.A0 = newVariable()
		dummyG2.P.X.B0.A1 = newVariable()
		dummyG2.P.X.B1.A0 = newVariable()
		dummyG2.P.X.B1.A1 = newVariable()
		dummyG2.P.Y.B0.A0 = newVariable()
		dummyG2.P.Y.B0.A1 = newVariable()
		dummyG2.P.Y.B1.A0 = newVariable()
		dummyG2.P.Y.B1.A1 = newVariable()

		_, _ = sw_bls24315.Pair(api, []sw_bls24315.G1Affine{dummyG1}, []sw_bls24315.G2Affine{dummyG2})

	}, ecc.BW6_633)

	registerSnippet("pairing_bls12381", func(api frontend.API, newVariable func() frontend.Variable) {

		bls12381, _ := emulated.NewField[emulated.BLS12381Fp](api)
		newElement := func() *emulated.Element[emulated.BLS12381Fp] {
			limbs := make([]frontend.Variable, emulated.BLS12381Fp{}.NbLimbs())
			for i := 0; i < len(limbs); i++ {
				limbs[i] = newVariable()
			}
			return bls12381.NewElement(limbs)
		}
		var dummyG1 sw_bls12381.G1Affine
		var dummyG2 sw_bls12381.G2Affine
		dummyG1.X = *newElement()
		dummyG1.Y = *newElement()
		dummyG2.P.X.A0 = *newElement()
		dummyG2.P.X.A1 = *newElement()
		dummyG2.P.Y.A0 = *newElement()
		dummyG2.P.Y.A1 = *newElement()

		pr, err := sw_bls12381.NewPairing(api)
		if err != nil {
			panic(err)
		}
		_, _ = pr.Pair([]*sw_bls12381.G1Affine{&dummyG1}, []*sw_bls12381.G2Affine{&dummyG2})

	}, ecc.BN254)

	registerSnippet("pairing_bn254", func(api frontend.API, newVariable func() frontend.Variable) {

		bn254, _ := emulated.NewField[emulated.BN254Fp](api)
		newElement := func() *emulated.Element[emulated.BN254Fp] {
			limbs := make([]frontend.Variable, emulated.BN254Fp{}.NbLimbs())
			for i := 0; i < len(limbs); i++ {
				limbs[i] = newVariable()
			}
			return bn254.NewElement(limbs)
		}
		var dummyG1 sw_bn254.G1Affine
		var dummyG2 sw_bn254.G2Affine
		dummyG1.X = *newElement()
		dummyG1.Y = *newElement()
		dummyG2.P.X.A0 = *newElement()
		dummyG2.P.X.A1 = *newElement()
		dummyG2.P.Y.A0 = *newElement()
		dummyG2.P.Y.A1 = *newElement()

		pr, err := sw_bn254.NewPairing(api)
		if err != nil {
			panic(err)
		}
		_, _ = pr.Pair([]*sw_bn254.G1Affine{&dummyG1}, []*sw_bn254.G2Affine{&dummyG2})

	}, ecc.BN254)

	registerSnippet("pairing_bw6761", func(api frontend.API, newVariable func() frontend.Variable) {

		bw6761, _ := emulated.NewField[emulated.BW6761Fp](api)
		newElement := func() *emulated.Element[emulated.BW6761Fp] {
			limbs := make([]frontend.Variable, emulated.BW6761Fp{}.NbLimbs())
			for i := 0; i < len(limbs); i++ {
				limbs[i] = newVariable()
			}
			return bw6761.NewElement(limbs)
		}
		var dummyG1 sw_bw6761.G1Affine
		var dummyG2 sw_bw6761.G2Affine
		dummyG1.X = *newElement()
		dummyG1.Y = *newElement()
		dummyG2.P.X = *newElement()
		dummyG2.P.Y = *newElement()

		pr, err := sw_bw6761.NewPairing(api)
		if err != nil {
			panic(err)
		}
		_, _ = pr.Pair([]*sw_bw6761.G1Affine{&dummyG1}, []*sw_bw6761.G2Affine{&dummyG2})

	}, ecc.BN254)

}

type snippetCircuit struct {
	V      [1024]frontend.Variable
	s      snippet
	vIndex int
}

func (d *snippetCircuit) Define(api frontend.API) error {
	d.s(api, d.newVariable)
	return nil
}

func (d *snippetCircuit) newVariable() frontend.Variable {
	d.vIndex++
	return d.V[(d.vIndex-1)%len(d.V)]
}

func makeSnippetCircuit(s snippet) frontend.Circuit {
	return &snippetCircuit{s: s}
}
