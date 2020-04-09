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

package eddsa

import (
	"testing"

	"github.com/consensys/gurvy/bls381/fr"
	"github.com/consensys/gurvy/bls381/twistededwards"
)

func TestEddsa(t *testing.T) {

	edcurve := twistededwards.GetEdwardsCurve()

	var seed [32]byte
	s := []byte("eddsa")
	for i, v := range s {
		seed[i] = v
	}

	privKey, pubKey := New(seed, edcurve)

	var msg fr.Element
	msg.SetString("44717650746155748460101257525078853138837311576962212923649547644148297035978")

	signedMsg, err := Sign(privKey, pubKey, msg)
	if err != nil {
		t.Fatal(err)
	}

	// verifies correct msg
	res, err := Verify(pubKey, signedMsg, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !res {
		t.Fatal("Verifiy correct signature should return true")
	}

	// verifies wrong msg
	msg.SetString("44717650746155748460101257525078853138837311576962212923649547644148297035979")
	res, err = Verify(pubKey, signedMsg, msg)
	if err != nil {
		t.Fatal(err)
	}
	if res {
		t.Fatal("Verfiy wrong signature should be false")
	}

}
