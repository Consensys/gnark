package zkpschemes

const Groth16Verify = `

import (
	{{ template "import_curve" . }}
	{{ template "import_backend" . }}
	"github.com/consensys/gnark/backend"
	"errors"
)

var errPairingCheckFailed = errors.New("pairing doesn't match")

// Verify verifies a proof
func Verify(proof *Proof, vk *VerifyingKey, inputs map[string]interface{}) error {

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

	kInputs, err := ParsePublicInput(vk.PublicInputs, inputs)
	if err != nil {
		return err
	}
	<-kSum.MultiExp(c, vk.G1.K, kInputs)

	// e(Σx.[Kvk(t)]1, -[γ]2)
	var kSumAff curve.G1Affine
	kSumAff.FromJacobian(&kSum)

	c.MillerLoop(kSumAff, vk.G2.GammaNeg, &eKvkγ)

	<-chan1
	<-chan2
	right := c.FinalExponentiation(&eKrsδ, &eArBs, &eKvkγ)
	if !vk.E.Equal(&right) {
		return errPairingCheckFailed
	}
	return nil
}

// ParsePublicInput return the ordered public input values
// in regular form (used as scalars for multi exponentiation).
// The function is public because it's needed for the recursive snark.
func ParsePublicInput(expectedNames []string, input map[string]interface{}) ([]fr.Element, error) {
	toReturn := make([]fr.Element, len(expectedNames))

	for i := 0; i < len(expectedNames); i++ {
		if expectedNames[i] == backend.OneWire {
			// ONE_WIRE is a reserved name, it should not be set by the user
			toReturn[i].SetOne()
			toReturn[i].FromMont()
		} else {
			if val, ok := input[expectedNames[i]]; ok {
				// TODO : note, similarly to r1cs.Solve() this need a "fast statically typed path"
				toReturn[i].SetInterface(val)
				toReturn[i].FromMont() 
			} else {
				return nil, backend.ErrInputNotSet
			}
		}
	}

	return toReturn, nil
}

`
