package zkpschemes

// Groth16Verify ...
const Groth16Verify = `

import (
	{{ template "import_curve" . }}
	{{ template "import_backend" . }}
	"github.com/consensys/gnark/backend"
	"errors"
)

var errPairingCheckFailed = errors.New("pairing doesn't match")
var errCorrectSubgroupCheckFailed = errors.New("points in the proof are not in the correct subgroup")

// Verify verifies a proof
func Verify(proof *Proof, vk *VerifyingKey, inputs map[string]interface{}) error {
	
	// check that the points in the proof are in the correct subgroup
	correctSubgroupCheck := true
	correctSubgroupCheck = correctSubgroupCheck && proof.Ar.SubgroupCheck()
	correctSubgroupCheck = correctSubgroupCheck && proof.Bs.SubgroupCheck()
	correctSubgroupCheck = correctSubgroupCheck && proof.Krs.SubgroupCheck()
	if !correctSubgroupCheck {
		return errCorrectSubgroupCheckFailed
	}

	var kSum curve.G1Jac
	var eKrsδ, eArBs *curve.PairingResult
	chan1 := make(chan bool, 1)
	chan2 := make(chan bool, 1)

	// e([Krs]1, -[δ]2)
	go func() {
		eKrsδ = curve.MillerLoop(proof.Krs, vk.G2.DeltaNeg)
		chan1 <- true
	}()

	// e([Ar]1, [Bs]2)
	go func() {
		eArBs = curve.MillerLoop(proof.Ar, proof.Bs)
		chan2 <- true
	}()

	kInputs, err := ParsePublicInput(vk.PublicInputs, inputs)
	if err != nil {
		return err
	}
	kSum.MultiExp( vk.G1.K, kInputs)

	// e(Σx.[Kvk(t)]1, -[γ]2)
	var kSumAff curve.G1Affine
	kSumAff.FromJacobian(&kSum)

	eKvkγ := curve.MillerLoop(kSumAff, vk.G2.GammaNeg)

	<-chan1
	<-chan2
	right := curve.FinalExponentiation(eKrsδ, eArBs, eKvkγ)
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
