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

package rollup

import (
	"testing"
)

func TestAccount(t *testing.T) {

	var acc Account
	acc.Reset()
	acc.balance.SetString("1900")
	acc.nonce = 1
	acc.index = 2

	serializedAccount := acc.Serialize()
	var deserializedAccount Account
	err := Deserialize(&deserializedAccount, serializedAccount)
	if err != nil {
		t.Fatal(err)
	}

	// check each field
	if deserializedAccount.index != acc.index {
		t.Fatal("error deserializing index")
	}
	if deserializedAccount.nonce != acc.nonce {
		t.Fatal("error deserializing nonce")
	}
	if !deserializedAccount.balance.Equal(&acc.balance) {
		t.Fatal("error deserializing balance")
	}
	if !deserializedAccount.pubKey.A.X.Equal(&acc.pubKey.A.X) {
		t.Fatal("error deserializing pub key X")
	}
	if !deserializedAccount.pubKey.A.Y.Equal(&acc.pubKey.A.Y) {
		t.Fatal("error deserializing pub key Y")
	}

	// check invalid size
	serializedAccount = append(serializedAccount, 0x00)

	err = Deserialize(&deserializedAccount, serializedAccount)
	if err == nil {
		t.Fatal("Deserializing byte slice with wrong size should raise an error")
	}

}
