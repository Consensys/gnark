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
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gadgets/accumulator/merkle"
	"github.com/consensys/gnark/gadgets/algebra/twistededwards"
	"github.com/consensys/gnark/gadgets/hash/mimc"
	"github.com/consensys/gnark/gadgets/signature/eddsa"
	"github.com/consensys/gurvy"
)

// TODO think about doing this as variable / paramter
const (
	nbAccounts = 16 // 16 accounts so we know that the proof length is 5
	depth      = 5  // size fo the inclusion proofs
	batchSize  = 1  // nbTranfers to batch in a proof
)

type RollupCircuit struct {
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

func (circuit *RollupCircuit) Define(curveID gurvy.ID, cs *frontend.CS) error {
	// hash function for the merkle proof and the eddsa signature
	hFunc, err := mimc.NewMiMC("seed", curveID)
	if err != nil {
		return err
	}

	// creation of the circuit
	for i := 0; i < batchSize; i++ {

		// verify the sender and receiver accounts exist before the update
		merkle.VerifyProof(cs, hFunc, circuit.RootHashesBefore[i], circuit.MerkleProofsSenderBefore[i][:], circuit.MerkleProofHelperSenderBefore[i][:])
		merkle.VerifyProof(cs, hFunc, circuit.RootHashesBefore[i], circuit.MerkleProofsReceiverBefore[i][:], circuit.MerkleProofHelperReceiverBefore[i][:])

		// verify the sender and receiver accounts exist after the update
		merkle.VerifyProof(cs, hFunc, circuit.RootHashesAfter[i], circuit.MerkleProofsSenderAfter[i][:], circuit.MerkleProofHelperSenderAfter[i][:])
		merkle.VerifyProof(cs, hFunc, circuit.RootHashesAfter[i], circuit.MerkleProofsReceiverAfter[i][:], circuit.MerkleProofHelperReceiverAfter[i][:])

		// verify the transaction transfer
		err := verifyTransferSignature(cs, circuit.Transfers[i], hFunc)
		if err != nil {
			return err
		}

		// update the accounts
		verifyAccountUpdated(cs, circuit.SenderAccountsBefore[i], circuit.ReceiverAccountsBefore[i], circuit.SenderAccountsAfter[i], circuit.ReceiverAccountsAfter[i], circuit.Transfers[i].Amount)
	}

	return nil
}

func (circuit *RollupCircuit) PostInit(curveID gurvy.ID) error {
	// edward curve gadget
	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	for i := 0; i < batchSize; i++ {
		// setting sender public key
		circuit.PublicKeysSender[i].Curve = params

		// setting receiver public key
		circuit.PublicKeysReceiver[i].Curve = params

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
		circuit.Transfers[i].Signature.R.Curve = params

	}

	return nil
}

// verifySignatureTransfer ensures that the signature of the transfer is valid
func verifyTransferSignature(circuit *frontend.CS, t TransferConstraints, hFunc mimc.MiMC) error {

	// the signature is on h(nonce || amount || senderpubKey (x&y) || receiverPubkey(x&y))
	htransfer := hFunc.Hash(circuit, t.Nonce, t.Amount, t.SenderPubKey.A.X, t.SenderPubKey.A.Y, t.ReceiverPubKey.A.X, t.ReceiverPubKey.A.Y)

	err := eddsa.Verify(circuit, t.Signature, htransfer, t.SenderPubKey)
	if err != nil {
		return err
	}
	return nil
}

func verifyAccountUpdated(circuit *frontend.CS, from, to, fromUpdated, toUpdated AccountConstraints, amount frontend.Variable) {

	// ensure that nonce is correctly updated
	one := circuit.ALLOCATE(1)
	nonceUpdated := circuit.ADD(from.Nonce, one)
	circuit.MUSTBE_EQ(nonceUpdated, fromUpdated.Nonce)

	// TODO ensures that the amount is less than the balance (fix the MUSTBE_LESS_OR_EQ constraint)
	circuit.MUSTBE_LESS_OR_EQ(amount, from.Balance, 256)

	// ensure that balance is correctly updated
	fromBalanceUpdated := circuit.SUB(from.Balance, amount)
	circuit.MUSTBE_EQ(fromBalanceUpdated, fromUpdated.Balance)

	toBalanceUpdated := circuit.ADD(to.Balance, amount)
	circuit.MUSTBE_EQ(toBalanceUpdated, toUpdated.Balance)

}
