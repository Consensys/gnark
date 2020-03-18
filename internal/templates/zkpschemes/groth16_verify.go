package zkpschemes

const Groth16Verify = `


{{ template "header" . }}

package groth16

import (
	{{ template "import_curve" . }}
	{{ template "import_backend" . }}
	constants "github.com/consensys/gnark/backend"
)


// Verify verifies a proof
func Verify(proof *Proof, vk *VerifyingKey, publicInputs map[string]backend.Assignment) (bool, error) {

	c := {{- if eq .Curve "GENERIC"}}curve.GetCurve(){{- else}}curve.{{.Curve}}(){{- end}}

	var kSum curve.G1Jac
	var eKrsδ, eArBs, eKvkγ curve.PairingResult
	chan1 := make(chan bool, 1)
	chan2 := make(chan bool, 1)

	// e([Krs]1, -[δ]2)
	go func() {
		c.MillerLoop(proof.Krs, vk.G2.DeltaNeg, &eKrsδ)
		chan1 <- true
	}()

	// e([Ar]1, [Bs]2)
	go func() {
		c.MillerLoop(proof.Ar, proof.Bs, &eArBs)
		chan2 <- true
	}()

	inputs, err := ParsePublicInput(vk.PublicInputs, publicInputs)
	if err != nil {
		return false, err
	}
	<-kSum.MultiExp(c, vk.G1.K, inputs)

	// e(Σx.[Kvk(t)]1, -[γ]2)
	var kSumAff curve.G1Affine
	kSum.ToAffineFromJac(&kSumAff)

	c.MillerLoop(kSumAff, vk.G2.GammaNeg, &eKvkγ)

	<-chan1
	<-chan2
	right := c.FinalExponentiation(&eKrsδ, &eArBs, &eKvkγ)
	return vk.E.Equal(&right), nil
}

// ParsePublicInput return the input values, not in Montgomery form
// TODO should not be here
func ParsePublicInput(expectedNames []string, publicInput map[string]backend.Assignment) ([]fr.Element, error) {

	toReturn := make([]fr.Element, len(expectedNames))

	// // ONE_WIRE is a reserved name, it should not be set by the user
	// if _, ok := publicInput[constants.OneWire]; ok {
	// 	return nil, ErrGotOneWire
	// }

	for i := 0; i < len(expectedNames); i++ {

		if expectedNames[i] == constants.OneWire {
			toReturn[i].SetOne()
			toReturn[i].FromMont()
		} else {

			if val, ok := publicInput[expectedNames[i]]; ok {
				if !val.IsPublic {
					return nil, constants.ErrInputVisiblity
				}
				toReturn[i] = val.Value.ToRegular()
			} else {
				return nil, constants.ErrInputNotSet
			}

		}

	}
	return toReturn, nil
}

`
