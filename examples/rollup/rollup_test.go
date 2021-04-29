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

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestOperatorReadAccount(t *testing.T) {

	// create operator with 10 accounts
	operator, _ := createOperator(10)

	// check if the account read from the operator are correct
	for i := 0; i < 10; i++ {
		opAccount, err := operator.readAccount(uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		acc, _ := createAccount(i)

		compareAccount(t, acc, opAccount)

	}

}

func TestSignTransfer(t *testing.T) {

	var amount uint64

	// create operator with 10 accounts
	operator, userKeys := createOperator(10)

	sender, err := operator.readAccount(0)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := operator.readAccount(1)
	if err != nil {
		t.Fatal(err)
	}

	// create the transfer and sign it (the hash used for signing is the hash function of the operator)
	amount = 10
	transfer := NewTransfer(amount, sender.pubKey, receiver.pubKey, sender.nonce)

	// verify correct signature
	_, err = transfer.Sign(userKeys[0], operator.h)
	if err != nil {
		t.Fatal(err)
	}
	res, err := transfer.Verify(operator.h)
	if err != nil {
		t.Fatal(err)
	}
	if !res {
		t.Fatal("Verifying transaction with the correct key should work")
	}

	// verify wrong signature
	_, err = transfer.Sign(userKeys[1], operator.h)
	if err != nil {
		t.Fatal(err)
	}
	_, err = transfer.Verify(operator.h)
	if err == nil {
		t.Fatal("Verifying transaction signed with the wrong key should output an error")
	}
}

func TestOperatorUpdateAccount(t *testing.T) {

	var amount uint64

	// create operator with 10 accounts
	operator, userKeys := createOperator(10)

	// get info on the parties
	sender, err := operator.readAccount(0)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := operator.readAccount(1)
	if err != nil {
		t.Fatal(err)
	}

	// create the transfer and sign it
	amount = 10
	transfer := NewTransfer(amount, sender.pubKey, receiver.pubKey, sender.nonce)
	transfer.Sign(userKeys[0], operator.h)

	err = operator.updateState(transfer, 0)
	if err != nil {
		t.Fatal(err)
	}

	// read the updated accounts of the sender and receiver and check if they are updated correctly
	newSender, err := operator.readAccount(0)
	if err != nil {
		t.Fatal(err)
	}
	newReceiver, err := operator.readAccount(1)
	if err != nil {
		t.Fatal(err)
	}
	var frAmount fr.Element
	frAmount.SetUint64(amount)

	sender.nonce++
	sender.balance.Sub(&sender.balance, &frAmount)
	receiver.balance.Add(&receiver.balance, &frAmount)

	compareAccount(t, newSender, sender)
	compareHashAccount(t, operator.HashState[0:operator.h.Size()], newSender, operator.h)

	compareAccount(t, newReceiver, receiver)
	compareHashAccount(t, operator.HashState[operator.h.Size():2*operator.h.Size()], newReceiver, operator.h)
}
