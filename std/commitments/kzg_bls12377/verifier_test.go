/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package kzg_bls12377

import (
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/kzg"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

type verifierCircuit struct {
	VerifKey VK
	Proof    OpeningProof
	Com      Digest
	S        frontend.Variable
}

func (circuit *verifierCircuit) Define(api frontend.API) error {

	// create the verifier cs
	Verify(api, circuit.Com, circuit.Proof, circuit.S, circuit.VerifKey)

	return nil
}

//-------------------------------------------------------
// proof generated using gnark-crypto

func TestVerifierDynamic(t *testing.T) {

	assert := test.NewAssert(t)

	// sizes of polynomials, kzg
	const kzgSize = 128
	const polynomialSize = 100

	// trusted setup
	alpha, err := rand.Int(rand.Reader, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
	srs, err := kzg.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	// random polynomial
	f := make([]fr.Element, polynomialSize)
	for i := 0; i < 60; i++ {
		f[i].SetRandom()
	}

	// commit to the polynomial
	com, err := kzg.Commit(f, srs.Pk)
	assert.NoError(err)

	// create opening proof
	var point fr.Element
	point.SetRandom()
	proof, err := kzg.Open(f, point, srs.Pk)
	assert.NoError(err)

	// check that the proof is correct
	err = kzg.Verify(&com, &proof, point, srs.Vk)
	if err != nil {
		t.Fatal(err)
	}

	// verify the proof in circuit
	var witness verifierCircuit

	// populate the witness
	witness.Com.X = com.X.String()
	witness.Com.Y = com.Y.String()

	witness.Proof.H.X = proof.H.X.String()
	witness.Proof.H.Y = proof.H.Y.String()

	witness.Proof.ClaimedValue = proof.ClaimedValue.String()

	witness.S = point.String()

	witness.VerifKey.G2[0].X.A0 = srs.Vk.G2[0].X.A0.String()
	witness.VerifKey.G2[0].X.A1 = srs.Vk.G2[0].X.A1.String()
	witness.VerifKey.G2[0].Y.A0 = srs.Vk.G2[0].Y.A0.String()
	witness.VerifKey.G2[0].Y.A1 = srs.Vk.G2[0].Y.A1.String()
	witness.VerifKey.G2[1].X.A0 = srs.Vk.G2[1].X.A0.String()
	witness.VerifKey.G2[1].X.A1 = srs.Vk.G2[1].X.A1.String()
	witness.VerifKey.G2[1].Y.A0 = srs.Vk.G2[1].Y.A0.String()
	witness.VerifKey.G2[1].Y.A1 = srs.Vk.G2[1].Y.A1.String()

	// check if the circuit is solved
	var circuit verifierCircuit
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

//-------------------------------------------------------
// harcoded values

func TestVerifier(t *testing.T) {

	var circuit, witness verifierCircuit

	// static witness
	witness.Com.X = "145429059828629443506099208441019164249918805265766585069511130101715300037889375544644493566733059056337445574142"
	witness.Com.Y = "7748648670212409231552941907406345586179813940682493172078407968203200311849395869785335293628955566021478572791"

	witness.Proof.H.X = "142546216630759857020142552653688574597188212934274836451979072858880695115513802425442488457664742720974070355453"
	witness.Proof.H.Y = "51742728231756961100409716107519203689800988928890924645730616869717553365749083029986151526811552917856555146906"

	witness.Proof.ClaimedValue = "7211341386127354417397285211336133449231039596179023429378585109196698597268"
	witness.S = "4321"
	witness.VerifKey.G2[0].X.A0 = "233578398248691099356572568220835526895379068987715365179118596935057653620464273615301663571204657964920925606294"
	witness.VerifKey.G2[0].X.A1 = "140913150380207355837477652521042157274541796891053068589147167627541651775299824604154852141315666357241556069118"
	witness.VerifKey.G2[0].Y.A0 = "63160294768292073209381361943935198908131692476676907196754037919244929611450776219210369229519898517858833747423"
	witness.VerifKey.G2[0].Y.A1 = "149157405641012693445398062341192467754805999074082136895788947234480009303640899064710353187729182149407503257491"
	witness.VerifKey.G2[1].X.A0 = "123747009012703414871739433259892117784672459657097139998749475279099125411579029748101735145753812822027512995199"
	witness.VerifKey.G2[1].X.A1 = "62735868045337090199933301723513128455431585854943778977190757050206710789139082141526891028732261537358701287808"
	witness.VerifKey.G2[1].Y.A0 = "212548833831227473592895134150456464278558858278752454560645447355770538424096804613692943525553353783189853308160"
	witness.VerifKey.G2[1].Y.A1 = "123051654588413991319606911619099872563646143639520520553172600449178549047186983142138529976243874838154671706124"

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

// bench
var ccsBench constraint.ConstraintSystem

func BenchmarkVerifyKZG(b *testing.B) {
	var c verifierCircuit
	b.ResetTimer()
	b.Run("groth16", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccsBench, _ = frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &c)
		}
	})
	b.Log("groth16", ccsBench.GetNbConstraints())
	b.Run("plonk", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccsBench, _ = frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, &c)
		}
	})
	b.Log("plonk", ccsBench.GetNbConstraints())
}
