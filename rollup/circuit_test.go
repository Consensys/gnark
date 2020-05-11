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
	"fmt"
	"strconv"
	"testing"

	backend_bn256 "github.com/consensys/gnark/backend/bn256"
	"github.com/consensys/gnark/backend/bn256/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gadgets/accumulator/merkle"
	twistededwards_gadget "github.com/consensys/gnark/gadgets/algebra/twistededwards"
	"github.com/consensys/gnark/gadgets/hash/mimc"
	"github.com/consensys/gnark/gadgets/signature/eddsa"
	"github.com/consensys/gurvy"
)

func TestCircuitSignature(t *testing.T) {

	notInInpuList := " is not in the input list"

	nbAccounts := 10

	operator, users := createOperator(nbAccounts)

	// read accounts involved in the transfer
	sender, err := operator.readAccount(0)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := operator.readAccount(1)
	if err != nil {
		t.Fatal(err)
	}

	// create the transfer and sign it
	var amount uint64
	amount = 10
	transfer := NewTransfer(amount, sender.pubKey, receiver.pubKey, sender.nonce)

	// sign the transfer
	_, err = transfer.Sign(users[0], operator.h)
	if err != nil {
		t.Fatal(err)
	}

	// update the state from the received transfer
	err = operator.updateState(transfer, 0)
	if err != nil {
		t.Fatal(err)
	}

	// check that the inputs related to the transfers are instantiated
	ext := "0"
	if _, ok := operator.witnesses[baseNameTransferAmount+ext]; !ok {
		t.Fatal(baseNameTransferAmount + notInInpuList)
	}
	if _, ok := operator.witnesses[baseNameSenderAccountNonceBefore+ext]; !ok {
		t.Fatal(baseNameSenderAccountNonceBefore + notInInpuList)
	}
	if _, ok := operator.witnesses[baseNameTransferSigRx+ext]; !ok {
		t.Fatal(baseNameTransferSigRx + notInInpuList)
	}
	if _, ok := operator.witnesses[baseNameTransferSigRy+ext]; !ok {
		t.Fatal(baseNameTransferSigRy + notInInpuList)
	}
	if _, ok := operator.witnesses[baseNameTransferSigS+ext]; !ok {
		t.Fatal(baseNameTransferSigS + notInInpuList)
	}

	// check that the inputs related to the public keys are instantiated
	if _, ok := operator.witnesses[baseNameSenderAccountPubkeyx+ext]; !ok {
		t.Fatal(baseNameSenderAccountPubkeyx + notInInpuList)
	}
	if _, ok := operator.witnesses[baseNameSenderAccountPubkeyy+ext]; !ok {
		t.Fatal(baseNameSenderAccountPubkeyy + notInInpuList)
	}

	if _, ok := operator.witnesses[baseNameReceiverAccountPubkeyx+ext]; !ok {
		t.Fatal(baseNameSenderAccountPubkeyx + notInInpuList)
	}
	if _, ok := operator.witnesses[baseNameReceiverAccountPubkeyy+ext]; !ok {
		t.Fatal(baseNameSenderAccountPubkeyy + notInInpuList)
	}

	// verifies the signature of the transfer
	circuit := frontend.New()

	paramsGadget, err := twistededwards_gadget.NewEdCurveGadget(gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}

	var gPubKeySender, gPubKeyReceiver eddsa.PublicKeyGadget
	gPubKeySender.Curve = paramsGadget
	gPubKeySender.A.X = circuit.SECRET_INPUT(baseNameSenderAccountPubkeyx + ext)
	gPubKeySender.A.Y = circuit.SECRET_INPUT(baseNameSenderAccountPubkeyy + ext)

	gPubKeyReceiver.Curve = paramsGadget
	gPubKeyReceiver.A.X = circuit.SECRET_INPUT(baseNameReceiverAccountPubkeyx + ext)
	gPubKeyReceiver.A.Y = circuit.SECRET_INPUT(baseNameReceiverAccountPubkeyy + ext)

	var gTransfer TransferCircuit
	gTransfer.amount = circuit.SECRET_INPUT(baseNameTransferAmount + ext)
	gTransfer.nonce = circuit.SECRET_INPUT(baseNameSenderAccountNonceBefore + ext)
	gTransfer.signature.R.A.X = circuit.SECRET_INPUT(baseNameTransferSigRx + ext)
	gTransfer.signature.R.A.Y = circuit.SECRET_INPUT(baseNameTransferSigRy + ext)
	gTransfer.signature.S = circuit.SECRET_INPUT(baseNameTransferSigS + ext)
	gTransfer.senderPubKey = gPubKeySender
	gTransfer.receiverPubKey = gPubKeyReceiver

	hFunc, err := mimc.NewMiMCGadget("seed", gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}

	verifySignatureTransfer(&circuit, gTransfer, hFunc)

	r1cs := backend_bn256.New(&circuit)

	assert := groth16.NewAssert(t)
	assert.Solved(&r1cs, operator.witnesses, nil)
}

func TestCircuitInclusionProof(t *testing.T) {

	notInInpuList := " is not in the input list"

	// 16 accounts so we know that the proof length is 5
	nbAccounts := 16

	operator, users := createOperator(nbAccounts)

	// read accounts involved in the transfer
	sender, err := operator.readAccount(0)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := operator.readAccount(1)
	if err != nil {
		t.Fatal(err)
	}

	// create the transfer and sign it
	var amount uint64
	amount = 16
	transfer := NewTransfer(amount, sender.pubKey, receiver.pubKey, sender.nonce)

	// sign the transfer
	_, err = transfer.Sign(users[0], operator.h)
	if err != nil {
		t.Fatal(err)
	}

	// update the state from the received transfer
	err = operator.updateState(transfer, 0)
	if err != nil {
		t.Fatal(err)
	}

	// check the inputs for the proofs of the sender/receiver are instantiated
	ext := "0"
	for i := 0; i < 2; i++ {
		if _, ok := operator.witnesses[baseNameSenderMerkleBefore+ext+strconv.Itoa(i)]; !ok {
			t.Fatal(baseNameSenderMerkleBefore + ext + strconv.Itoa(i) + notInInpuList)
		}
		if _, ok := operator.witnesses[baseNameSenderMerkleAfter+ext+strconv.Itoa(i)]; !ok {
			t.Fatal(baseNameSenderMerkleAfter + ext + strconv.Itoa(i) + notInInpuList)
		}
		if _, ok := operator.witnesses[baseNameReceiverMerkleBefore+ext+strconv.Itoa(i)]; !ok {
			t.Fatal(baseNameReceiverMerkleBefore + ext + strconv.Itoa(i) + notInInpuList)
		}
		if _, ok := operator.witnesses[baseNameReceiverMerkleAfter+ext+strconv.Itoa(i)]; !ok {
			t.Fatal(baseNameReceiverMerkleAfter + ext + strconv.Itoa(i) + notInInpuList)
		}
		if _, ok := operator.witnesses[baseNameRootHashBefore+ext]; !ok {
			t.Fatal(baseNameRootHashBefore + notInInpuList)
		}
		if _, ok := operator.witnesses[baseNameRootHashAfter+ext]; !ok {
			t.Fatal(baseNameRootHashAfter + notInInpuList)
		}
	}
	// check that the proofs helpers of the sender/receivers are instantiated
	for i := 0; i < 1; i++ {
		if _, ok := operator.witnesses[baseNameSenderProofHelperBefore+ext+strconv.Itoa(i)]; !ok {
			t.Fatal(baseNameSenderProofHelperBefore + ext + strconv.Itoa(i) + notInInpuList)
		}
		if _, ok := operator.witnesses[baseNameSenderProofHelperAfter+ext+strconv.Itoa(i)]; !ok {
			t.Fatal(baseNameSenderProofHelperAfter + ext + strconv.Itoa(i) + notInInpuList)
		}
		if _, ok := operator.witnesses[baseNameReceiverProofHelperBefore+ext+strconv.Itoa(i)]; !ok {
			t.Fatal(baseNameReceiverProofHelperBefore + ext + strconv.Itoa(i) + notInInpuList)
		}
		if _, ok := operator.witnesses[baseNameReceiverProofHelperAfter+ext+strconv.Itoa(i)]; !ok {
			t.Fatal(baseNameReceiverProofHelperAfter + ext + strconv.Itoa(i) + notInInpuList)
		}
	}

	// verifies the proofs of inclusion of the transfer
	circuit := frontend.New()

	merkleProofSenderBefore := make([]*frontend.Constraint, 5)
	merkleProofSenderAfter := make([]*frontend.Constraint, 5)
	merkleProofReceiverBefore := make([]*frontend.Constraint, 5)
	merkleProofReceiverAfter := make([]*frontend.Constraint, 5)

	merkleHelperSenderBefore := make([]*frontend.Constraint, 4)
	merkleHelperSenderAfter := make([]*frontend.Constraint, 4)
	merkleHelperReceiverBefore := make([]*frontend.Constraint, 4)
	merkleHelperReceiverAfter := make([]*frontend.Constraint, 4)

	for i := 0; i < 5; i++ {
		merkleProofSenderBefore[i] = circuit.SECRET_INPUT(baseNameSenderMerkleBefore + ext + strconv.Itoa(i))
		merkleProofSenderAfter[i] = circuit.SECRET_INPUT(baseNameSenderMerkleAfter + ext + strconv.Itoa(i))
		merkleProofReceiverBefore[i] = circuit.SECRET_INPUT(baseNameReceiverMerkleBefore + ext + strconv.Itoa(i))
		merkleProofReceiverAfter[i] = circuit.SECRET_INPUT(baseNameReceiverMerkleAfter + ext + strconv.Itoa(i))
	}
	for i := 0; i < 4; i++ {
		merkleHelperSenderBefore[i] = circuit.SECRET_INPUT(baseNameSenderProofHelperBefore + ext + strconv.Itoa(i))
		merkleHelperSenderAfter[i] = circuit.SECRET_INPUT(baseNameSenderProofHelperAfter + ext + strconv.Itoa(i))
		merkleHelperReceiverBefore[i] = circuit.SECRET_INPUT(baseNameReceiverProofHelperBefore + ext + strconv.Itoa(i))
		merkleHelperReceiverAfter[i] = circuit.SECRET_INPUT(baseNameReceiverProofHelperAfter + ext + strconv.Itoa(i))
	}

	merkleRootBefore := circuit.SECRET_INPUT(baseNameRootHashBefore + ext)
	merkleRootAfter := circuit.SECRET_INPUT(baseNameRootHashAfter + ext)

	hFunc, err := mimc.NewMiMCGadget("seed", gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}

	merkle.VerifyProof(&circuit, hFunc, merkleRootBefore, merkleProofSenderBefore, merkleHelperSenderBefore)
	merkle.VerifyProof(&circuit, hFunc, merkleRootBefore, merkleProofReceiverBefore, merkleHelperReceiverBefore)

	merkle.VerifyProof(&circuit, hFunc, merkleRootAfter, merkleProofSenderAfter, merkleHelperSenderAfter)
	merkle.VerifyProof(&circuit, hFunc, merkleRootAfter, merkleProofReceiverAfter, merkleHelperReceiverAfter)

	r1cs := backend_bn256.New(&circuit)
	fmt.Printf("nb constraints: %d\n", r1cs.NbConstraints)

	assert := groth16.NewAssert(t)
	assert.Solved(&r1cs, operator.witnesses, nil)

}
