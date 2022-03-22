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
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

const (
	nbAccounts = 16 // 16 accounts so we know that the proof length is 5
	depth      = 5  // size fo the inclusion proofs
	batchSize  = 1  // nbTranfers to batch in a proof
)

// Circuit "toy" rollup circuit where an operator can generate a proof that he processed
// some transactions
type Circuit struct {
	// ---------------------------------------------------------------------------------------------
	// SECRET INPUTS

	// list of accounts involved before update and their public keys
	SenderAccountsBefore   [batchSize]AccountConstraints
	ReceiverAccountsBefore [batchSize]AccountConstraints
	PublicKeysSender       [batchSize]eddsa.PublicKey

	// list of accounts involved after update and their public keys
	SenderAccountsAfter   [batchSize]AccountConstraints
	ReceiverAccountsAfter [batchSize]AccountConstraints
	PublicKeysReceiver    [batchSize]eddsa.PublicKey

	// list of transactions
	Transfers [batchSize]TransferConstraints

	// list of proofs corresponding to sender account
	MerkleProofsSenderBefore      [batchSize][depth]frontend.Variable
	MerkleProofsSenderAfter       [batchSize][depth]frontend.Variable
	MerkleProofHelperSenderBefore [batchSize][depth - 1]frontend.Variable
	MerkleProofHelperSenderAfter  [batchSize][depth - 1]frontend.Variable

	// list of proofs corresponding to receiver account
	MerkleProofsReceiverBefore      [batchSize][depth]frontend.Variable
	MerkleProofsReceiverAfter       [batchSize][depth]frontend.Variable
	MerkleProofHelperReceiverBefore [batchSize][depth - 1]frontend.Variable
	MerkleProofHelperReceiverAfter  [batchSize][depth - 1]frontend.Variable

	// ---------------------------------------------------------------------------------------------
	// PUBLIC INPUTS

	// list of root hashes
	RootHashesBefore [batchSize]frontend.Variable `gnark:",public"`
	RootHashesAfter  [batchSize]frontend.Variable `gnark:",public"`
}

// AccountConstraints accounts encoded as constraints
type AccountConstraints struct {
	Index   frontend.Variable // index in the tree
	Nonce   frontend.Variable // nb transactions done so far from this account
	Balance frontend.Variable
	PubKey  eddsa.PublicKey `gnark:"-"`
}

// TransferConstraints transfer encoded as constraints
type TransferConstraints struct {
	Amount         frontend.Variable
	Nonce          frontend.Variable `gnark:"-"`
	SenderPubKey   eddsa.PublicKey   `gnark:"-"`
	ReceiverPubKey eddsa.PublicKey   `gnark:"-"`
	Signature      eddsa.Signature
}

func (circuit *Circuit) postInit(api frontend.API) error {

	for i := 0; i < batchSize; i++ {

		// setting the sender accounts before update
		circuit.SenderAccountsBefore[i].PubKey = circuit.PublicKeysSender[i]

		// setting the sender accounts after update
		circuit.SenderAccountsAfter[i].PubKey = circuit.PublicKeysSender[i]

		// setting the receiver accounts before update
		circuit.ReceiverAccountsBefore[i].PubKey = circuit.PublicKeysReceiver[i]

		// setting the receiver accounts after update
		circuit.ReceiverAccountsAfter[i].PubKey = circuit.PublicKeysReceiver[i]

		// setting the transfers
		circuit.Transfers[i].Nonce = circuit.SenderAccountsBefore[i].Nonce
		circuit.Transfers[i].SenderPubKey = circuit.PublicKeysSender[i]
		circuit.Transfers[i].ReceiverPubKey = circuit.PublicKeysReceiver[i]

	}
	return nil
}

// Define declares the circuit's constraints
func (circuit *Circuit) Define(api frontend.API) error {
	if err := circuit.postInit(api); err != nil {
		return err
	}
	// hash function for the merkle proof and the eddsa signature
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// creation of the circuit
	for i := 0; i < batchSize; i++ {

		// verify the sender and receiver accounts exist before the update
		merkle.VerifyProof(api, hFunc, circuit.RootHashesBefore[i], circuit.MerkleProofsSenderBefore[i][:], circuit.MerkleProofHelperSenderBefore[i][:])
		merkle.VerifyProof(api, hFunc, circuit.RootHashesBefore[i], circuit.MerkleProofsReceiverBefore[i][:], circuit.MerkleProofHelperReceiverBefore[i][:])

		// verify the sender and receiver accounts exist after the update
		merkle.VerifyProof(api, hFunc, circuit.RootHashesAfter[i], circuit.MerkleProofsSenderAfter[i][:], circuit.MerkleProofHelperSenderAfter[i][:])
		merkle.VerifyProof(api, hFunc, circuit.RootHashesAfter[i], circuit.MerkleProofsReceiverAfter[i][:], circuit.MerkleProofHelperReceiverAfter[i][:])

		// verify the transaction transfer
		err := verifyTransferSignature(api, circuit.Transfers[i], hFunc)
		if err != nil {
			return err
		}

		// update the accounts
		verifyAccountUpdated(api, circuit.SenderAccountsBefore[i], circuit.ReceiverAccountsBefore[i], circuit.SenderAccountsAfter[i], circuit.ReceiverAccountsAfter[i], circuit.Transfers[i].Amount)
	}

	return nil
}

// verifySignatureTransfer ensures that the signature of the transfer is valid
func verifyTransferSignature(api frontend.API, t TransferConstraints, hFunc mimc.MiMC) error {

	// the signature is on h(nonce ∥ amount ∥ senderpubKey (x&y) ∥ receiverPubkey(x&y))
	hFunc.Write(t.Nonce, t.Amount, t.SenderPubKey.A.X, t.SenderPubKey.A.Y, t.ReceiverPubKey.A.X, t.ReceiverPubKey.A.Y)
	htransfer := hFunc.Sum()

	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}

	hFunc.Reset()
	err = eddsa.Verify(curve, t.Signature, htransfer, t.SenderPubKey, &hFunc)
	if err != nil {
		return err
	}
	return nil
}

func verifyAccountUpdated(api frontend.API, from, to, fromUpdated, toUpdated AccountConstraints, amount frontend.Variable) {

	// ensure that nonce is correctly updated
	nonceUpdated := api.Add(from.Nonce, 1)
	api.AssertIsEqual(nonceUpdated, fromUpdated.Nonce)

	// ensures that the amount is less than the balance
	api.AssertIsLessOrEqual(amount, from.Balance)

	// ensure that balance is correctly updated
	fromBalanceUpdated := api.Sub(from.Balance, amount)
	api.AssertIsEqual(fromBalanceUpdated, fromUpdated.Balance)

	toBalanceUpdated := api.Add(to.Balance, amount)
	api.AssertIsEqual(toBalanceUpdated, toUpdated.Balance)

}
