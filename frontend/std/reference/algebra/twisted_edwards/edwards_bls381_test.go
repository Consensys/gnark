// +build bls381

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

package twistededwards

import (
	"testing"

	"github.com/consensys/gnark/curve/fr"
)

func TestAdd(t *testing.T) {

	// set curve parameters
	ed := GetEdwardsCurve()

	var p1, p2 Point

	p1.X.SetString("21793328330329971148710654283888115697962123987759099803244199498744022094670")
	p1.Y.SetString("2101040637884652362150023747029283466236613497763786920682459476507158507058")

	p2.X.SetString("50629843885093813360334764484465489653158679010834922765195739220081842003850")
	p2.Y.SetString("39525475875082628301311747912064089490877815436253076910246067124459956047086")

	var expectedX, expectedY fr.Element

	expectedX.SetString("35199665011228459549784465709909589656817343715952606097903780358611765544262")
	expectedY.SetString("35317228978363680085508213497002527319878195549272460436820924737513178285870")

	p1.Add(&p1, &p2, ed)

	if !p1.X.Equal(&expectedX) {
		t.Fatal("wrong x coordinate")
	}
	if !p1.Y.Equal(&expectedY) {
		t.Fatal("wrong y coordinate")
	}

}

func TestDouble(t *testing.T) {

	// set curve parameters
	ed := GetEdwardsCurve()

	var p Point

	p.X.SetString("21793328330329971148710654283888115697962123987759099803244199498744022094670")
	p.Y.SetString("2101040637884652362150023747029283466236613497763786920682459476507158507058")

	p.Double(&p, ed)

	var expectedX, expectedY fr.Element

	expectedX.SetString("4887768767527220265359686405053440846384750454898507249732188959468533044182")
	expectedY.SetString("52332037604151508724685641460923103263088911891587010793017195088380209977878")

	if !p.X.Equal(&expectedX) {
		t.Fatal("wrong x coordinate")
	}
	if !p.Y.Equal(&expectedY) {
		t.Fatal("wrong y coordinate")
	}

}

func TestScalarMul(t *testing.T) {

	// set curve parameters
	ed := GetEdwardsCurve()

	var scalar fr.Element
	scalar.SetUint64(23902374).FromMont()

	var p Point
	p.ScalarMul(&ed.Base, ed, scalar)

	var expectedX, expectedY fr.Element

	expectedX.SetString("46803808651513276177048978152090125758512142729856301157634295837210154385969")
	expectedY.SetString("6051280156044491864815311759850323556790635624820404123991533640491375546590")

	if !expectedX.Equal(&p.X) {
		t.Fatal("wrong x coordinate")
	}
	if !expectedY.Equal(&p.Y) {
		t.Fatal("wrong y coordinate")
	}

}
