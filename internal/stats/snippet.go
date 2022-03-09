package stats

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/fields_bls12377"
	"github.com/consensys/gnark/std/algebra/fields_bls24315"
	"github.com/consensys/gnark/std/algebra/sw_bls12377"
	"github.com/consensys/gnark/std/algebra/sw_bls24315"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/bits"
)

type snippet func(frontend.API, frontend.Variable)

func registerSnippet(name string, snippet snippet, curves ...ecc.ID) {
	if _, ok := AllCircuits[name]; ok {
		panic("circuit " + name + " already registered")
	}
	if len(curves) == 0 {
		curves = ecc.Implemented()
	}
	AllCircuits[name] = Circuit{makeSnippetCircuit(snippet), curves}
}

func init() {
	// add std snippets
	registerSnippet("math/bits.ToBinary", func(api frontend.API, v frontend.Variable) {
		_ = bits.ToBinary(api, v)
	})
	registerSnippet("math/bits.ToBinary/unconstrained", func(api frontend.API, v frontend.Variable) {
		_ = bits.ToBinary(api, v, bits.WithUnconstrainedOutputs())
	})
	registerSnippet("math/bits.ToTernary", func(api frontend.API, v frontend.Variable) {
		_ = bits.ToTernary(api, v)
	})
	registerSnippet("math/bits.ToTernary/unconstrained", func(api frontend.API, v frontend.Variable) {
		_ = bits.ToTernary(api, v, bits.WithUnconstrainedOutputs())
	})
	registerSnippet("math/bits.ToNAF", func(api frontend.API, v frontend.Variable) {
		_ = bits.ToNAF(api, v)
	})
	registerSnippet("math/bits.ToNAF/unconstrained", func(api frontend.API, v frontend.Variable) {
		_ = bits.ToNAF(api, v, bits.WithUnconstrainedOutputs())
	})

	registerSnippet("hash/mimc", func(api frontend.API, v frontend.Variable) {
		mimc, _ := mimc.NewMiMC(api)
		mimc.Write(v)
		_ = mimc.Sum()
	})

	registerSnippet("pairing_bls12377", func(api frontend.API, v frontend.Variable) {
		ateLoop := uint64(9586122913090633729)
		ext := fields_bls12377.GetBLS12377ExtensionFp12(api)
		pairingInfo := sw_bls12377.PairingContext{AteLoop: ateLoop, Extension: ext}

		var dummyG1 sw_bls12377.G1Affine
		var dummyG2 sw_bls12377.G2Affine
		dummyG1.X = v
		dummyG1.Y = v
		dummyG2.X.A0 = v
		dummyG2.X.A1 = v
		dummyG2.Y.A0 = v
		dummyG2.Y.A1 = v

		var resMillerLoop fields_bls12377.E12
		// e(psi0, -gamma)*e(-πC, -δ)*e(πA, πB)
		sw_bls12377.MillerLoop(api, dummyG1, dummyG2, &resMillerLoop, pairingInfo)

		// performs the final expo
		var resPairing fields_bls12377.E12
		resPairing.FinalExponentiation(api, resMillerLoop, pairingInfo.AteLoop, pairingInfo.Extension)
	}, ecc.BW6_761)

	registerSnippet("pairing_bls24315", func(api frontend.API, v frontend.Variable) {
		ateLoop := uint64(3218079743)
		ext := fields_bls24315.GetBLS24315ExtensionFp24(api)
		pairingInfo := sw_bls24315.PairingContext{AteLoop: ateLoop, Extension: ext}

		var dummyG1 sw_bls24315.G1Affine
		var dummyG2 sw_bls24315.G2Affine
		dummyG1.X = v
		dummyG1.Y = v
		dummyG2.X.B0.A0 = v
		dummyG2.X.B0.A1 = v
		dummyG2.X.B1.A0 = v
		dummyG2.X.B1.A1 = v
		dummyG2.Y.B0.A0 = v
		dummyG2.Y.B0.A1 = v
		dummyG2.Y.B1.A0 = v
		dummyG2.Y.B1.A1 = v

		var resMillerLoop fields_bls24315.E24
		// e(psi0, -gamma)*e(-πC, -δ)*e(πA, πB)
		sw_bls24315.MillerLoop(api, dummyG1, dummyG2, &resMillerLoop, pairingInfo)

		// performs the final expo
		var resPairing fields_bls24315.E24
		resPairing.FinalExponentiation(api, resMillerLoop, pairingInfo.AteLoop, pairingInfo.Extension)
	}, ecc.BW6_633)

}

type snippetCircuit struct {
	V frontend.Variable
	s snippet
}

func (d *snippetCircuit) Define(api frontend.API) error {
	d.s(api, d.V)
	return nil
}

func makeSnippetCircuit(s snippet) frontend.Circuit {
	return &snippetCircuit{s: s}
}
