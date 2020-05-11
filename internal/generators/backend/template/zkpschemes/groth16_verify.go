package zkpschemes

const Groth16Verify = `

import (
	{{ template "import_curve" . }}
	{{ template "import_backend" . }}
	"github.com/consensys/gnark/backend"
)


// Verify verifies a proof
func Verify(proof *Proof, vk *VerifyingKey, inputs backend.Assignments) (bool, error) {

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

	kInputs, err := parsePublicInput(vk.PublicInputs, inputs)
	if err != nil {
		return false, err
	}
	<-kSum.MultiExp(c, vk.G1.K, kInputs)

	// e(Σx.[Kvk(t)]1, -[γ]2)
	var kSumAff curve.G1Affine
	kSum.ToAffineFromJac(&kSumAff)

	c.MillerLoop(kSumAff, vk.G2.GammaNeg, &eKvkγ)

	<-chan1
	<-chan2
	right := c.FinalExponentiation(&eKrsδ, &eArBs, &eKvkγ)
	return vk.E.Equal(&right), nil
}

// parsePublicInput return the ordered public input values
// in regular form (used as scalars for multi exponentiation)
func parsePublicInput(expectedNames []string, input backend.Assignments) ([]fr.Element, error) {
	toReturn := make([]fr.Element, len(expectedNames))

	// ensure we don't assign private inputs
	publicInput := input.DiscardSecrets()

	for i := 0; i < len(expectedNames); i++ {
		if expectedNames[i] == backend.OneWire {
			// ONE_WIRE is a reserved name, it should not be set by the user
			toReturn[i].SetOne()
			toReturn[i].FromMont()
		} else {
			if val, ok := publicInput[expectedNames[i]]; ok {
				toReturn[i].SetBigInt(&val.Value).FromMont()
			} else {
				return nil, backend.ErrInputNotSet
			}
		}
	}

	return toReturn, nil
}

`
