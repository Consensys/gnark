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
	twistededwards_gadget "github.com/consensys/gnark/gadgets/algebra/twistededwards"
	"github.com/consensys/gnark/gadgets/hash/mimc"
	"github.com/consensys/gnark/gadgets/signature/eddsa"
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
	PublicKeysSender       [batchSize]eddsa.PublicKeyGadget

	// list of accounts involved after update and their public keys
	SenderAccountsAfter   [batchSize]AccountConstraints
	ReceiverAccountsAfter [batchSize]AccountConstraints
	PublicKeysReceiver    [batchSize]eddsa.PublicKeyGadget

	// list of transactions
	Transfers [batchSize]TransferConstraints

	// list of proofs corresponding to sender account
	MerkleProofsSenderBefore      [batchSize][depth]frontend.CircuitVariable
	MerkleProofsSenderAfter       [batchSize][depth]frontend.CircuitVariable
	MerkleProofHelperSenderBefore [batchSize][depth - 1]frontend.CircuitVariable
	MerkleProofHelperSenderAfter  [batchSize][depth - 1]frontend.CircuitVariable

	// list of proofs corresponding to receiver account
	MerkleProofsReceiverBefore      [batchSize][depth]frontend.CircuitVariable
	MerkleProofsReceiverAfter       [batchSize][depth]frontend.CircuitVariable
	MerkleProofHelperReceiverBefore [batchSize][depth - 1]frontend.CircuitVariable
	MerkleProofHelperReceiverAfter  [batchSize][depth - 1]frontend.CircuitVariable

	// ---------------------------------------------------------------------------------------------
	// PUBLIC INPUTS

	// list of root hashes
	RootHashesBefore [batchSize]frontend.CircuitVariable `gnark:",public"`
	RootHashesAfter  [batchSize]frontend.CircuitVariable `gnark:",public"`
}

// AccountConstraints accounts encoded as constraints
type AccountConstraints struct {
	Index   frontend.CircuitVariable // index in the tree
	Nonce   frontend.CircuitVariable // nb transactions done so far from this account
	Balance frontend.CircuitVariable
	PubKey  eddsa.PublicKeyGadget `gnark:"-"`
}

// TransferConstraints transfer encoded as constraints
type TransferConstraints struct {
	Amount         frontend.CircuitVariable
	Nonce          frontend.CircuitVariable `gnark:"-"`
	SenderPubKey   eddsa.PublicKeyGadget    `gnark:"-"`
	ReceiverPubKey eddsa.PublicKeyGadget    `gnark:"-"`
	Signature      eddsa.SignatureGadget
}

func (circuit *RollupCircuit) Define(ctx *frontend.Context, cs *frontend.CS) error {
	// hash function for the merkle proof and the eddsa signature
	// TODO MimC should take ctx only, with seed fed by first caller
	hFunc, err := mimc.NewMiMCGadget("seed", ctx.CurveID())
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

func (circuit *RollupCircuit) PostInit(ctx *frontend.Context) error {
	// edward curve gadget
	paramsGadget, err := twistededwards_gadget.NewEdCurveGadget(ctx.CurveID())
	if err != nil {
		return err
	}

	for i := 0; i < batchSize; i++ {
		// setting sender public key
		circuit.PublicKeysSender[i].Curve = paramsGadget

		// setting receiver public key
		circuit.PublicKeysReceiver[i].Curve = paramsGadget

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
		circuit.Transfers[i].Signature.R.Curve = paramsGadget

	}

	return nil
}

// verifySignatureTransfer ensures that the signature of the transfer is valid
func verifyTransferSignature(circuit *frontend.CS, t TransferConstraints, hFunc mimc.MiMCGadget) error {

	// the signature is on h(nonce || amount || senderpubKey (x&y) || receiverPubkey(x&y))
	htransfer := hFunc.Hash(circuit, t.Nonce, t.Amount, t.SenderPubKey.A.X, t.SenderPubKey.A.Y, t.ReceiverPubKey.A.X, t.ReceiverPubKey.A.Y)

	err := eddsa.Verify(circuit, t.Signature, htransfer, t.SenderPubKey)
	if err != nil {
		return err
	}
	return nil
}

// checkCorrectLeaf checks if hacc = hFunc(acc)
func ensureCorrectLeaf(circuit *frontend.CS, hFunc mimc.MiMCGadget, acc AccountConstraints, hacc frontend.CircuitVariable) {

	// compute the hash of the account, serialized like this:
	// index || nonce || balance || pubkeyX || pubkeyY
	haccount := hFunc.Hash(circuit, acc.Index, acc.Nonce, acc.Balance, acc.PubKey.A.X, acc.PubKey.A.Y)

	circuit.MUSTBE_EQ(haccount, hacc)

}

// updateAccountGadget ensures that from, to are correctly updated according to t, h is the gadget hash for checking the signature
// returns the updated accounts from, to
func verifyAccountUpdated(circuit *frontend.CS, from, to, fromUpdated, toUpdated AccountConstraints, amount frontend.CircuitVariable) {

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
