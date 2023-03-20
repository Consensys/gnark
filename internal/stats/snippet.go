package stats

import (
	"math"
	"sync"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/sw_bls12377"
	"github.com/consensys/gnark/std/algebra/sw_bls24315"
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
		dummyG2.X.A0 = newVariable()
		dummyG2.X.A1 = newVariable()
		dummyG2.Y.A0 = newVariable()
		dummyG2.Y.A1 = newVariable()

		// e(psi0, -gamma)*e(-πC, -δ)*e(πA, πB)
		resMillerLoop, _ := sw_bls12377.MillerLoop(api, []sw_bls12377.G1Affine{dummyG1}, []sw_bls12377.G2Affine{dummyG2})

		// performs the final expo
		_ = sw_bls12377.FinalExponentiation(api, resMillerLoop)
	}, ecc.BW6_761)

	registerSnippet("pairing_bls24315", func(api frontend.API, newVariable func() frontend.Variable) {

		var dummyG1 sw_bls24315.G1Affine
		var dummyG2 sw_bls24315.G2Affine
		dummyG1.X = newVariable()
		dummyG1.Y = newVariable()
		dummyG2.X.B0.A0 = newVariable()
		dummyG2.X.B0.A1 = newVariable()
		dummyG2.X.B1.A0 = newVariable()
		dummyG2.X.B1.A1 = newVariable()
		dummyG2.Y.B0.A0 = newVariable()
		dummyG2.Y.B0.A1 = newVariable()
		dummyG2.Y.B1.A0 = newVariable()
		dummyG2.Y.B1.A1 = newVariable()

		// e(psi0, -gamma)*e(-πC, -δ)*e(πA, πB)
		resMillerLoop, _ := sw_bls24315.MillerLoop(api, []sw_bls24315.G1Affine{dummyG1}, []sw_bls24315.G2Affine{dummyG2})

		// performs the final expo
		_ = sw_bls24315.FinalExponentiation(api, resMillerLoop)
	}, ecc.BW6_633)

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
