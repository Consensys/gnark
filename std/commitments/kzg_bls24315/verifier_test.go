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

package kzg_bls24315

import (
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	"github.com/consensys/gnark-crypto/ecc/bls24-315/fr/kzg"
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
	alpha, err := rand.Int(rand.Reader, ecc.BLS24_315.ScalarField())
	assert.NoError(err)
	srs, err := kzg.NewSRS(kzgSize, alpha)
	assert.NoError(err)

	// random polynomial
	f := make([]fr.Element, polynomialSize)
	for i := 0; i < 60; i++ {
		f[i].SetRandom()
	}

	// commit to the polynomial
	com, err := kzg.Commit(f, srs)
	assert.NoError(err)

	// create opening proof
	var point fr.Element
	point.SetRandom()
	proof, err := kzg.Open(f, point, srs)
	assert.NoError(err)

	// check that the proof is correct
	err = kzg.Verify(&com, &proof, point, srs)
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

	witness.VerifKey.G1.X = srs.G1[0].X.String()
	witness.VerifKey.G1.Y = srs.G1[0].Y.String()

	witness.VerifKey.G2[0].X.B0.A0 = srs.G2[0].X.B0.A0.String()
	witness.VerifKey.G2[0].X.B0.A1 = srs.G2[0].X.B0.A1.String()
	witness.VerifKey.G2[0].X.B1.A0 = srs.G2[0].X.B1.A0.String()
	witness.VerifKey.G2[0].X.B1.A1 = srs.G2[0].X.B1.A1.String()
	witness.VerifKey.G2[0].Y.B0.A0 = srs.G2[0].Y.B0.A0.String()
	witness.VerifKey.G2[0].Y.B0.A1 = srs.G2[0].Y.B0.A1.String()
	witness.VerifKey.G2[0].Y.B1.A0 = srs.G2[0].Y.B1.A0.String()
	witness.VerifKey.G2[0].Y.B1.A1 = srs.G2[0].Y.B1.A1.String()

	witness.VerifKey.G2[1].X.B0.A0 = srs.G2[1].X.B0.A0.String()
	witness.VerifKey.G2[1].X.B0.A1 = srs.G2[1].X.B0.A1.String()
	witness.VerifKey.G2[1].X.B1.A0 = srs.G2[1].X.B1.A0.String()
	witness.VerifKey.G2[1].X.B1.A1 = srs.G2[1].X.B1.A1.String()
	witness.VerifKey.G2[1].Y.B0.A0 = srs.G2[1].Y.B0.A0.String()
	witness.VerifKey.G2[1].Y.B0.A1 = srs.G2[1].Y.B0.A1.String()
	witness.VerifKey.G2[1].Y.B1.A0 = srs.G2[1].Y.B1.A0.String()
	witness.VerifKey.G2[1].Y.B1.A1 = srs.G2[1].Y.B1.A1.String()

	// check if the circuit is solved
	var circuit verifierCircuit
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

}

//-------------------------------------------------------
// harcoded values

func TestVerifier(t *testing.T) {

	var circuit, witness verifierCircuit

	// static witness
	witness.Com.X = "35386189147256460787905142428026982693834102687669771641361389281756222188309133371287736011496"
	witness.Com.Y = "27110917293370507654960132415484655252529074592699870521959828295621560278434020539890708345149"

	witness.Proof.H.X = "237024382315576057940476197527646514934539639879200035206834755549615436908306104502862432730"
	witness.Proof.H.Y = "24965199876048664783103146001620612576865473814618781613850899751573655382828001319566087837055"

	witness.Proof.ClaimedValue = "10347231107172233075459792371577505115223937655290126532055162077965558980163"
	witness.S = "4321"
	witness.VerifKey.G1.X = "34223510504517033132712852754388476272837911830964394866541204856091481856889569724484362330263"
	witness.VerifKey.G1.Y = "24215295174889464585413596429561903295150472552154479431771837786124301185073987899223459122783"

	witness.VerifKey.G2[0].X.B0.A0 = "24614737899199071964341749845083777103809664018538138889239909664991294445469052467064654073699"
	witness.VerifKey.G2[0].X.B0.A1 = "17049297748993841127032249156255993089778266476087413538366212660716380683149731996715975282972"
	witness.VerifKey.G2[0].X.B1.A0 = "11950668649125904104557740112865942804623051114821811669564995102755430514441092495782202668342"
	witness.VerifKey.G2[0].X.B1.A1 = "3603055379462539802413979855826194299714805833759849528529386570240639115620788686893505938793"
	witness.VerifKey.G2[0].Y.B0.A0 = "31740092748246070457677943092194030978994615503726570180895475408200863271773078192139722193079"
	witness.VerifKey.G2[0].Y.B0.A1 = "30261413948955264769241509843031153941332801192447678605718183215275065425758214858190865971597"
	witness.VerifKey.G2[0].Y.B1.A0 = "14195825602561496219090410113749222574308144851497375443809100117082380611212823440674391088885"
	witness.VerifKey.G2[0].Y.B1.A1 = "2391152940984805871402135750194189812615420966694899795235607856168224901793030297133493038211"

	witness.VerifKey.G2[1].X.B0.A0 = "32770621494303675347306576037414743205466109457179006780112295339591667866879607994893522201077"
	witness.VerifKey.G2[1].X.B0.A1 = "26234307989293079589757302086025391411007046129273969450459586440325937793578626756390716239607"
	witness.VerifKey.G2[1].X.B1.A0 = "12885920290770633767625725164719407698814564441475093302178981579150678620682561869830892647708"
	witness.VerifKey.G2[1].X.B1.A1 = "27040439362534196619980827988108357486576687369306457236523666215277529311368226649309430321857"
	witness.VerifKey.G2[1].Y.B0.A0 = "37891043881493427277825396947634598161159358734636209357686614942355583145029806490020871408089"
	witness.VerifKey.G2[1].Y.B0.A1 = "24578978782210992183339450660991675754164024355249488228592063724386132418314115963198249364981"
	witness.VerifKey.G2[1].Y.B1.A0 = "2561567173101794713286533032340948733218695754942152779206184132595475750392464489574163449132"
	witness.VerifKey.G2[1].Y.B1.A1 = "22410372563820522534342381636929948962663337994936763276489712608156477267640544532767398832260"

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

}

// bench
var ccsBench constraint.ConstraintSystem

func BenchmarkVerifyKZG(b *testing.B) {
	var c verifierCircuit
	b.ResetTimer()
	b.Run("groth16", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccsBench, _ = frontend.Compile(ecc.BW6_633.ScalarField(), r1cs.NewBuilder, &c)
		}
	})
	b.Log("groth16", ccsBench.GetNbConstraints())
	b.Run("plonk", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccsBench, _ = frontend.Compile(ecc.BW6_633.ScalarField(), scs.NewBuilder, &c)
		}
	})
	b.Log("plonk", ccsBench.GetNbConstraints())
}
