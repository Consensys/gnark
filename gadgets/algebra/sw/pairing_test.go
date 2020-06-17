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

package sw

import (
	"strconv"
	"testing"

	"github.com/consensys/gnark/backend"
	backend_bw761 "github.com/consensys/gnark/backend/bw761"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gadgets/algebra/fields"
	"github.com/consensys/gurvy/bls377"
	"github.com/consensys/gurvy/bls377/fp"
)

func TestLineEvalBLS377(t *testing.T) {

	// create the circuit
	circuit := frontend.New()

	ext := fields.GetBLS377ExtensionFp12(&circuit)

	var Q, R G2Jac
	var P G1Jac

	Q.X.X = circuit.SECRET_INPUT("qxx")
	Q.X.Y = circuit.ALLOCATE("153924906120314059329163510034379429156688480181182668999642334674073859906019623717844462092443710331558842221198")
	Q.Y.X = circuit.ALLOCATE("217426664443013466493849511677243421913435679616098405782168799962712362374085608530270502677771125796970144049342")
	Q.Y.Y = circuit.ALLOCATE("220113305559851867470055261956775835250492241909876276448085325823827669499391027597256026508256704101389743638320")
	Q.Z.X = circuit.ALLOCATE("1")
	Q.Z.Y = circuit.ALLOCATE("0")

	R.X.X = circuit.SECRET_INPUT("rxx")
	R.X.Y = circuit.ALLOCATE("208837221672103828632878568310047865523715993428626260492233587961023171407529159232705047544612759994485307437530")
	R.Y.X = circuit.ALLOCATE("219129261975485221488302932474367447253380009436652290437731529751224807932621384667224625634955419310221362804739")
	R.Y.Y = circuit.ALLOCATE("62857965187173987050461294586432573826521562230975685098398439555961148392353952895313161290735015726193379258321")
	R.Z.X = circuit.ALLOCATE("1")
	R.Z.Y = circuit.ALLOCATE("0")

	P.X = circuit.SECRET_INPUT("px")
	P.Y = circuit.ALLOCATE("62857965187173987050461294586432573826521562230975685098398439555961148392353952895313161290735015726193379258321")
	P.Z = circuit.ALLOCATE("1")

	var lres LineEvalRes

	LineEvalBLS377(&circuit, Q, R, P, &lres, ext)

	lres.r0.X.Tag("lr0x")
	lres.r0.Y.Tag("lr0y")
	lres.r1.X.Tag("lr1x")
	lres.r1.Y.Tag("lr1y")
	lres.r2.X.Tag("lr2x")
	lres.r2.Y.Tag("lr2y")

	expectedValues := make(map[string]*fp.Element)
	var expres [6]fp.Element
	expres[0].SetString("220291599185938038585565774521033812062947190299680306664648725201730830885666933651848261361463591330567860207241")
	expres[1].SetString("232134458700276476669584229661634543747068594368664068937164975724095736595288995356706959089579876199020312643174")
	expres[2].SetString("74241662856820718491669277383162555524896537826488558937227282983357670568906847284642533051528779250776935382660")
	expres[3].SetString("9787836945036920457066634104342154603142239983688979247440278426242314457905122599227144555989168817796094251258")
	expres[4].SetString("85129589817387660717039592198118788807152207633847410148299763250229022303850156734979397272700502238285752744807")
	expres[5].SetString("245761211327131018855579902758747359135620549826797077633679496719449586668701082009536667506317412690997533857875")
	expectedValues["lr0x"] = &expres[0]
	expectedValues["lr0y"] = &expres[1]
	expectedValues["lr1x"] = &expres[2]
	expectedValues["lr1y"] = &expres[3]
	expectedValues["lr2x"] = &expres[4]
	expectedValues["lr2y"] = &expres[5]

	// create inputs to the circuit
	inputs := backend.NewAssignment()
	inputs.Assign(backend.Secret, "qxx", "11467063222684898633036104763692544506257812867640109164430855414494851760297509943081481005947955008078272733624")
	inputs.Assign(backend.Secret, "rxx", "38348804106969641131654336618231918247608720362924380120333996440589719997236048709530218561145001033408367199467")
	inputs.Assign(backend.Secret, "px", "219129261975485221488302932474367447253380009436652290437731529751224807932621384667224625634955419310221362804739")

	r1cs := backend_bw761.New(&circuit)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		if expectedValues[k].String() != v.String() {
			t.Fatal("error Line eval jac")
		}
	}
}

func TestLineEvalAffineBLS377(t *testing.T) {

	// create the circuit
	circuit := frontend.New()

	ext := fields.GetBLS377ExtensionFp12(&circuit)

	var Q, R G2Aff
	var P G1Aff

	Q.X.X = circuit.SECRET_INPUT("qxx")
	Q.X.Y = circuit.ALLOCATE("153924906120314059329163510034379429156688480181182668999642334674073859906019623717844462092443710331558842221198")
	Q.Y.X = circuit.ALLOCATE("217426664443013466493849511677243421913435679616098405782168799962712362374085608530270502677771125796970144049342")
	Q.Y.Y = circuit.ALLOCATE("220113305559851867470055261956775835250492241909876276448085325823827669499391027597256026508256704101389743638320")

	R.X.X = circuit.SECRET_INPUT("rxx")
	R.X.Y = circuit.ALLOCATE("208837221672103828632878568310047865523715993428626260492233587961023171407529159232705047544612759994485307437530")
	R.Y.X = circuit.ALLOCATE("219129261975485221488302932474367447253380009436652290437731529751224807932621384667224625634955419310221362804739")
	R.Y.Y = circuit.ALLOCATE("62857965187173987050461294586432573826521562230975685098398439555961148392353952895313161290735015726193379258321")

	P.X = circuit.SECRET_INPUT("px")
	P.Y = circuit.ALLOCATE("62857965187173987050461294586432573826521562230975685098398439555961148392353952895313161290735015726193379258321")

	var lres LineEvalRes

	LineEvalAffineBLS377(&circuit, Q, R, P, &lres, ext)

	lres.r0.X.Tag("lr0x")
	lres.r0.Y.Tag("lr0y")
	lres.r1.X.Tag("lr1x")
	lres.r1.Y.Tag("lr1y")
	lres.r2.X.Tag("lr2x")
	lres.r2.Y.Tag("lr2y")

	expectedValues := make(map[string]*fp.Element)
	var expres [6]fp.Element
	expres[0].SetString("220291599185938038585565774521033812062947190299680306664648725201730830885666933651848261361463591330567860207241")
	expres[1].SetString("232134458700276476669584229661634543747068594368664068937164975724095736595288995356706959089579876199020312643174")
	expres[2].SetString("74241662856820718491669277383162555524896537826488558937227282983357670568906847284642533051528779250776935382660")
	expres[3].SetString("9787836945036920457066634104342154603142239983688979247440278426242314457905122599227144555989168817796094251258")
	expres[4].SetString("85129589817387660717039592198118788807152207633847410148299763250229022303850156734979397272700502238285752744807")
	expres[5].SetString("245761211327131018855579902758747359135620549826797077633679496719449586668701082009536667506317412690997533857875")
	expectedValues["lr0x"] = &expres[0]
	expectedValues["lr0y"] = &expres[1]
	expectedValues["lr1x"] = &expres[2]
	expectedValues["lr1y"] = &expres[3]
	expectedValues["lr2x"] = &expres[4]
	expectedValues["lr2y"] = &expres[5]

	// create inputs to the circuit
	inputs := backend.NewAssignment()
	inputs.Assign(backend.Secret, "qxx", "11467063222684898633036104763692544506257812867640109164430855414494851760297509943081481005947955008078272733624")
	inputs.Assign(backend.Secret, "rxx", "38348804106969641131654336618231918247608720362924380120333996440589719997236048709530218561145001033408367199467")
	inputs.Assign(backend.Secret, "px", "219129261975485221488302932474367447253380009436652290437731529751224807932621384667224625634955419310221362804739")

	r1cs := backend_bw761.New(&circuit)

	// inspect and compare the results
	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range res {
		if expectedValues[k].String() != v.String() {
			t.Fatal("error line eval affine")
		}
	}
}

func TestPairingBLS377(t *testing.T) {

	// create the map containing the expected result
	expectedValues := make(map[string]*fp.Element)

	// create circuit
	circuit := frontend.New()

	// set reference result
	curve := bls377.BLS377()

	var _P bls377.G1Affine
	_P.X.SetString("68333130937826953018162399284085925021577172705782285525244777453303237942212457240213897533859360921141590695983")
	_P.Y.SetString("243386584320553125968203959498080829207604143167922579970841210259134422887279629198736754149500839244552761526603")

	var _Q bls377.G2Affine
	_Q.X.A0.SetString("129200027147742761118726589615458929865665635908074731940673005072449785691019374448547048953080140429883331266310")
	_Q.X.A1.SetString("218164455698855406745723400799886985937129266327098023241324696183914328661520330195732120783615155502387891913936")
	_Q.Y.A0.SetString("178797786102020318006939402153521323286173305074858025240458924050651930669327663166574060567346617543016897467207")
	_Q.Y.A1.SetString("246194676937700783734853490842104812127151341609821057456393698060154678349106147660301543343243364716364400889778")

	var milres, pairingRes bls377.PairingResult
	curve.MillerLoop(_P, _Q, &milres)

	expectedValues["millerloop0"] = &milres.C0.B0.A0
	expectedValues["millerloop1"] = &milres.C0.B0.A1
	expectedValues["millerloop2"] = &milres.C0.B1.A0
	expectedValues["millerloop3"] = &milres.C0.B1.A1
	expectedValues["millerloop4"] = &milres.C0.B2.A0
	expectedValues["millerloop5"] = &milres.C0.B2.A1
	expectedValues["millerloop6"] = &milres.C1.B0.A0
	expectedValues["millerloop7"] = &milres.C1.B0.A1
	expectedValues["millerloop8"] = &milres.C1.B1.A0
	expectedValues["millerloop9"] = &milres.C1.B1.A1
	expectedValues["millerloop10"] = &milres.C1.B2.A0
	expectedValues["millerloop11"] = &milres.C1.B2.A1

	pairingRes = curve.FinalExponentiation(&milres)

	expectedValues["pairing0"] = &pairingRes.C0.B0.A0
	expectedValues["pairing1"] = &pairingRes.C0.B0.A1
	expectedValues["pairing2"] = &pairingRes.C0.B1.A0
	expectedValues["pairing3"] = &pairingRes.C0.B1.A1
	expectedValues["pairing4"] = &pairingRes.C0.B2.A0
	expectedValues["pairing5"] = &pairingRes.C0.B2.A1
	expectedValues["pairing6"] = &pairingRes.C1.B0.A0
	expectedValues["pairing7"] = &pairingRes.C1.B0.A1
	expectedValues["pairing8"] = &pairingRes.C1.B1.A0
	expectedValues["pairing9"] = &pairingRes.C1.B1.A1
	expectedValues["pairing10"] = &pairingRes.C1.B2.A0
	expectedValues["pairing11"] = &pairingRes.C1.B2.A1

	// set the circuit
	var ateLoop uint64
	ateLoop = 9586122913090633729
	ext := fields.GetBLS377ExtensionFp12(&circuit)
	pairingInfo := PairingContext{AteLoop: ateLoop, Extension: ext}

	var Q G2Jac
	var P G1Jac

	Q.X.X = circuit.SECRET_INPUT("qxx")
	Q.X.Y = circuit.ALLOCATE("218164455698855406745723400799886985937129266327098023241324696183914328661520330195732120783615155502387891913936")
	Q.Y.X = circuit.ALLOCATE("178797786102020318006939402153521323286173305074858025240458924050651930669327663166574060567346617543016897467207")
	Q.Y.Y = circuit.ALLOCATE("246194676937700783734853490842104812127151341609821057456393698060154678349106147660301543343243364716364400889778")
	Q.Z.X = circuit.ALLOCATE("1")
	Q.Z.Y = circuit.ALLOCATE("0")

	P.X = circuit.SECRET_INPUT("px")
	P.Y = circuit.ALLOCATE("243386584320553125968203959498080829207604143167922579970841210259134422887279629198736754149500839244552761526603")
	P.Z = circuit.ALLOCATE("1")

	// create inputs to the circuit
	inputs := backend.NewAssignment()
	inputs.Assign(backend.Secret, "qxx", "129200027147742761118726589615458929865665635908074731940673005072449785691019374448547048953080140429883331266310")
	inputs.Assign(backend.Secret, "px", "68333130937826953018162399284085925021577172705782285525244777453303237942212457240213897533859360921141590695983")

	milrescircuit := fields.NewFp12ElmtNil(&circuit)

	MillerLoop(&circuit, P, Q, &milrescircuit, pairingInfo)

	// tag the result of the miller loop
	milrescircuit.C0.B0.X.Tag("millerloop0")
	milrescircuit.C0.B0.Y.Tag("millerloop1")
	milrescircuit.C0.B1.X.Tag("millerloop2")
	milrescircuit.C0.B1.Y.Tag("millerloop3")
	milrescircuit.C0.B2.X.Tag("millerloop4")
	milrescircuit.C0.B2.Y.Tag("millerloop5")
	milrescircuit.C1.B0.X.Tag("millerloop6")
	milrescircuit.C1.B0.Y.Tag("millerloop7")
	milrescircuit.C1.B1.X.Tag("millerloop8")
	milrescircuit.C1.B1.Y.Tag("millerloop9")
	milrescircuit.C1.B2.X.Tag("millerloop10")
	milrescircuit.C1.B2.Y.Tag("millerloop11")

	//pairingres := fields.NewFp12ElmtNil(&circuit)
	milrescircuit.FinalExpoBLS(&circuit, &milrescircuit, uint64(9586122913090633729), ext)

	// tag the result of the pairing loop
	milrescircuit.C0.B0.X.Tag("pairing0")
	milrescircuit.C0.B0.Y.Tag("pairing1")
	milrescircuit.C0.B1.X.Tag("pairing2")
	milrescircuit.C0.B1.Y.Tag("pairing3")
	milrescircuit.C0.B2.X.Tag("pairing4")
	milrescircuit.C0.B2.Y.Tag("pairing5")
	milrescircuit.C1.B0.X.Tag("pairing6")
	milrescircuit.C1.B0.Y.Tag("pairing7")
	milrescircuit.C1.B1.X.Tag("pairing8")
	milrescircuit.C1.B1.Y.Tag("pairing9")
	milrescircuit.C1.B2.X.Tag("pairing10")
	milrescircuit.C1.B2.Y.Tag("pairing11")

	// inspect and compare the results
	r1cs := backend_bw761.New(&circuit)

	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	prefixMillerLoop := "millerloop"
	prefixPairing := "pairing"
	for i := 0; i < 12; i++ {
		entry := prefixMillerLoop + strconv.Itoa(i)
		s1 := expectedValues[entry].String()
		s2 := res[entry]
		if s1 != s2.String() {
			t.Fatal("error miller loop")
		}
	}
	for i := 0; i < 12; i++ {
		entry := prefixPairing + strconv.Itoa(i)
		s1 := expectedValues[entry].String()
		s2 := res[entry]
		if s1 != s2.String() {
			t.Fatal("error pairing")
		}
	}

}

func TestPairingAffineBLS377(t *testing.T) {

	// create the map containing the expected result
	expectedValues := make(map[string]*fp.Element)

	// create circuit
	circuit := frontend.New()

	// set reference result
	curve := bls377.BLS377()

	var _P bls377.G1Affine
	_P.X.SetString("68333130937826953018162399284085925021577172705782285525244777453303237942212457240213897533859360921141590695983")
	_P.Y.SetString("243386584320553125968203959498080829207604143167922579970841210259134422887279629198736754149500839244552761526603")

	var _Q bls377.G2Affine
	_Q.X.A0.SetString("129200027147742761118726589615458929865665635908074731940673005072449785691019374448547048953080140429883331266310")
	_Q.X.A1.SetString("218164455698855406745723400799886985937129266327098023241324696183914328661520330195732120783615155502387891913936")
	_Q.Y.A0.SetString("178797786102020318006939402153521323286173305074858025240458924050651930669327663166574060567346617543016897467207")
	_Q.Y.A1.SetString("246194676937700783734853490842104812127151341609821057456393698060154678349106147660301543343243364716364400889778")

	var milres, pairingRes bls377.PairingResult
	curve.MillerLoop(_P, _Q, &milres)
	pairingRes = curve.FinalExponentiation(&milres)

	expectedValues["pairing0"] = &pairingRes.C0.B0.A0
	expectedValues["pairing1"] = &pairingRes.C0.B0.A1
	expectedValues["pairing2"] = &pairingRes.C0.B1.A0
	expectedValues["pairing3"] = &pairingRes.C0.B1.A1
	expectedValues["pairing4"] = &pairingRes.C0.B2.A0
	expectedValues["pairing5"] = &pairingRes.C0.B2.A1
	expectedValues["pairing6"] = &pairingRes.C1.B0.A0
	expectedValues["pairing7"] = &pairingRes.C1.B0.A1
	expectedValues["pairing8"] = &pairingRes.C1.B1.A0
	expectedValues["pairing9"] = &pairingRes.C1.B1.A1
	expectedValues["pairing10"] = &pairingRes.C1.B2.A0
	expectedValues["pairing11"] = &pairingRes.C1.B2.A1

	// set the circuit
	var ateLoop uint64
	ateLoop = 9586122913090633729
	ext := fields.GetBLS377ExtensionFp12(&circuit)
	pairingInfo := PairingContext{AteLoop: ateLoop, Extension: ext}

	var Q G2Aff
	var P G1Aff

	Q.X.X = circuit.SECRET_INPUT("qxx")
	Q.X.Y = circuit.ALLOCATE("218164455698855406745723400799886985937129266327098023241324696183914328661520330195732120783615155502387891913936")
	Q.Y.X = circuit.ALLOCATE("178797786102020318006939402153521323286173305074858025240458924050651930669327663166574060567346617543016897467207")
	Q.Y.Y = circuit.ALLOCATE("246194676937700783734853490842104812127151341609821057456393698060154678349106147660301543343243364716364400889778")

	P.X = circuit.SECRET_INPUT("px")
	P.Y = circuit.ALLOCATE("243386584320553125968203959498080829207604143167922579970841210259134422887279629198736754149500839244552761526603")

	// create inputs to the circuit
	inputs := backend.NewAssignment()
	inputs.Assign(backend.Secret, "qxx", "129200027147742761118726589615458929865665635908074731940673005072449785691019374448547048953080140429883331266310")
	inputs.Assign(backend.Secret, "px", "68333130937826953018162399284085925021577172705782285525244777453303237942212457240213897533859360921141590695983")

	milrescircuit := fields.NewFp12ElmtNil(&circuit)

	MillerLoopAffine(&circuit, P, Q, &milrescircuit, pairingInfo)

	//pairingres := fields.NewFp12ElmtNil(&circuit)
	milrescircuit.FinalExpoBLS(&circuit, &milrescircuit, uint64(9586122913090633729), ext)

	// tag the result of the pairing loop
	milrescircuit.C0.B0.X.Tag("pairing0")
	milrescircuit.C0.B0.Y.Tag("pairing1")
	milrescircuit.C0.B1.X.Tag("pairing2")
	milrescircuit.C0.B1.Y.Tag("pairing3")
	milrescircuit.C0.B2.X.Tag("pairing4")
	milrescircuit.C0.B2.Y.Tag("pairing5")
	milrescircuit.C1.B0.X.Tag("pairing6")
	milrescircuit.C1.B0.Y.Tag("pairing7")
	milrescircuit.C1.B1.X.Tag("pairing8")
	milrescircuit.C1.B1.Y.Tag("pairing9")
	milrescircuit.C1.B2.X.Tag("pairing10")
	milrescircuit.C1.B2.Y.Tag("pairing11")

	// inspect and compare the results
	r1cs := backend_bw761.New(&circuit)

	res, err := r1cs.Inspect(inputs, false)
	if err != nil {
		t.Fatal(err)
	}
	prefixPairing := "pairing"

	for i := 0; i < 12; i++ {
		entry := prefixPairing + strconv.Itoa(i)
		s1 := expectedValues[entry].String()
		s2 := res[entry]
		if s1 != s2.String() {
			t.Fatal("error pairing")
		}
	}

}
