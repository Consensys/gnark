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

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

type circuitSignature Circuit

// Circuit implements part of the rollup circuit only by delcaring a subset of the constraints
func (t *circuitSignature) Define(api frontend.API) error {
	if err := (*Circuit)(t).postInit(api); err != nil {
		return err
	}
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	return verifyTransferSignature(api, t.Transfers[0], hFunc)
}

func TestCircuitSignature(t *testing.T) {

	const nbAccounts = 10

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
	amount := uint64(10)
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

	// verifies the signature of the transfer
	assert := test.NewAssert(t)

	var signatureCircuit circuitSignature
	assert.ProverSucceeded(&signatureCircuit, &operator.witnesses, test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))

}

// Same structure as Circuit, but stripped off non unsonstrained inputs
type circuitInclusionProofBis struct {

	// ---------------------------------------------------------------------------------------------
	// SECRET INPUTS

	// list of proofs corresponding to sender account
	MerkleProofReceiverBefore [BatchSizeCircuit]merkle.MerkleProof
	// MerkleProofSenderAfter        [BatchSizeCircuit]merkle.MerkleProof

	MerkleProofsSenderBefore      [BatchSizeCircuit][depth]frontend.Variable
	MerkleProofsSenderAfter       [BatchSizeCircuit][depth]frontend.Variable
	MerkleProofHelperSenderBefore [BatchSizeCircuit][depth - 1]frontend.Variable
	MerkleProofHelperSenderAfter  [BatchSizeCircuit][depth - 1]frontend.Variable

	// list of proofs corresponding to receiver account
	// MerkleProofReceiverBefore [BatchSizeCircuit]merkle.MerkleProof
	// MerkleProofReceiverAfter        [BatchSizeCircuit]merkle.MerkleProof

	MerkleProofsReceiverBefore      [BatchSizeCircuit][depth]frontend.Variable
	MerkleProofsReceiverAfter       [BatchSizeCircuit][depth]frontend.Variable
	MerkleProofHelperReceiverBefore [BatchSizeCircuit][depth - 1]frontend.Variable
	MerkleProofHelperReceiverAfter  [BatchSizeCircuit][depth - 1]frontend.Variable

	// ---------------------------------------------------------------------------------------------
	// PUBLIC INPUTS

	// list of root hashes
	RootHashesBefore [BatchSizeCircuit]frontend.Variable `gnark:",public"`
	RootHashesAfter  [BatchSizeCircuit]frontend.Variable `gnark:",public"`
}

// Circuit implements part of the rollup circuit only by delcaring a subset of the constraints
func (t *circuitInclusionProofBis) Define(api frontend.API) error {

	// if err := (*Circuit)(t).postInit(api); err != nil {
	// 	return err
	// }
	hashFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	t.MerkleProofReceiverBefore[0].VerifyProofBis(api, &hashFunc)

	merkle.VerifyProof(api, &hashFunc, t.RootHashesBefore[0], t.MerkleProofsSenderBefore[0][:], t.MerkleProofHelperSenderBefore[0][:])
	merkle.VerifyProof(api, &hashFunc, t.RootHashesBefore[0], t.MerkleProofsReceiverBefore[0][:], t.MerkleProofHelperReceiverBefore[0][:])

	merkle.VerifyProof(api, &hashFunc, t.RootHashesAfter[0], t.MerkleProofsReceiverAfter[0][:], t.MerkleProofHelperReceiverAfter[0][:])
	merkle.VerifyProof(api, &hashFunc, t.RootHashesAfter[0], t.MerkleProofsSenderAfter[0][:], t.MerkleProofHelperSenderAfter[0][:])

	return nil
}

func TestCircuitInclusionProof(t *testing.T) {

	if testing.Short() {
		t.Skip("skipping rollup tests for circleCI")
	}

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
	amount := uint64(16)
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

	// verifies the proofs of inclusion of the transfer
	// assert := test.NewAssert(t)

	var inclusionProofCircuit circuitInclusionProofBis
	for i := 0; i < BatchSizeCircuit; i++ {
		inclusionProofCircuit.MerkleProofReceiverBefore[i].Path = make([]frontend.Variable, depth)
	}

	_, err = frontend.Compile(ecc.BN254, r1cs.NewBuilder, &inclusionProofCircuit)
	if err != nil {
		t.Fatal(err)
	}

	//assert.ProverSucceeded(&inclusionProofCircuit, &operator.witnesses, test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))

}

type circuitUpdateAccount Circuit

// Circuit implements part of the rollup circuit only by delcaring a subset of the constraints
func (t *circuitUpdateAccount) Define(api frontend.API) error {

	if err := (*Circuit)(t).postInit(api); err != nil {
		return err
	}

	verifyAccountUpdated(api, t.SenderAccountsBefore[0], t.ReceiverAccountsBefore[0],
		t.SenderAccountsAfter[0], t.ReceiverAccountsAfter[0], t.Transfers[0].Amount)
	return nil
}

func TestCircuitUpdateAccount(t *testing.T) {

	if testing.Short() {
		t.Skip("skipping rollup tests for circleCI")
	}

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
	amount := uint64(10)
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

	assert := test.NewAssert(t)

	var updateAccountCircuit circuitUpdateAccount
	(*Circuit)(&updateAccountCircuit).allocateSlicesMerkleProofs()

	assert.ProverSucceeded(&updateAccountCircuit, &operator.witnesses, test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))

}

func TestCircuitFull(t *testing.T) {

	if testing.Short() {
		t.Skip("skipping rollup tests for circleCI")
	}

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
	amount := uint64(10)
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

	assert := test.NewAssert(t)
	// verifies the proofs of inclusion of the transfer

	var rollupCircuit Circuit

	// TODO full circuit has some unconstrained inputs, that's odd.
	assert.ProverSucceeded(&rollupCircuit, &operator.witnesses, test.WithCurves(ecc.BN254), test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))

}
