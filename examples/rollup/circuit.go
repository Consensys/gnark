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

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gadgets/accumulator/merkle"
	twistededwards_gadget "github.com/consensys/gnark/gadgets/algebra/twistededwards"
	"github.com/consensys/gnark/gadgets/hash/mimc"
	"github.com/consensys/gnark/gadgets/signature/eddsa"
)

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
	MerkleProofsSenderBefore      [batchSize][depth]*frontend.Constraint
	MerkleProofsSenderAfter       [batchSize][depth]*frontend.Constraint
	MerkleProofHelperSenderBefore [batchSize][depth - 1]*frontend.Constraint
	MerkleProofHelperSenderAfter  [batchSize][depth - 1]*frontend.Constraint

	// list of proofs corresponding to receiver account
	MerkleProofsReceiverBefore      [batchSize][depth]*frontend.Constraint
	MerkleProofsReceiverAfter       [batchSize][depth]*frontend.Constraint
	MerkleProofHelperReceiverBefore [batchSize][depth - 1]*frontend.Constraint
	MerkleProofHelperReceiverAfter  [batchSize][depth - 1]*frontend.Constraint

	// ---------------------------------------------------------------------------------------------
	// PUBLIC INPUTS

	// list of root hashes
	RootHashesBefore [batchSize]*frontend.Constraint `gnark:"public"`
	RootHashesAfter  [batchSize]*frontend.Constraint `gnark:"public"`
}

// AccountConstraints accounts encoded as constraints
type AccountConstraints struct {
	Index   *frontend.Constraint // index in the tree
	Nonce   *frontend.Constraint // nb transactions done so far from this account
	Balance *frontend.Constraint
	PubKey  eddsa.PublicKeyGadget `gnark:"omit"`
}

// TransferConstraints transfer encoded as constraints
type TransferConstraints struct {
	Amount         *frontend.Constraint
	Nonce          *frontend.Constraint  `gnark:"omit"`
	SenderPubKey   eddsa.PublicKeyGadget `gnark:"omit"`
	ReceiverPubKey eddsa.PublicKeyGadget `gnark:"omit"`
	Signature      eddsa.SignatureGadget
}

func (circuit *RollupCircuit) PostInit(ctx *frontend.Context) error {
	// this is a post init hook.
	// this is not a mandatory method to implement.
	fmt.Println("init hook called")

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

func (circuit *RollupCircuit) Circuit(ctx *frontend.Context, cs *frontend.CS) error {
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
func ensureCorrectLeaf(circuit *frontend.CS, hFunc mimc.MiMCGadget, acc AccountConstraints, hacc *frontend.Constraint) {

	// compute the hash of the account, serialized like this:
	// index || nonce || balance || pubkeyX || pubkeyY
	haccount := hFunc.Hash(circuit, acc.Index, acc.Nonce, acc.Balance, acc.PubKey.A.X, acc.PubKey.A.Y)

	circuit.MUSTBE_EQ(haccount, hacc)

}

// updateAccountGadget ensures that from, to are correctly updated according to t, h is the gadget hash for checking the signature
// returns the updated accounts from, to
func verifyAccountUpdated(circuit *frontend.CS, from, to, fromUpdated, toUpdated AccountConstraints, amount *frontend.Constraint) {

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

const (
	// basename of the inputs for the proofs before update
	baseNameSenderMerkleBefore        = "MerkleProofsSenderBefore_"
	baseNameSenderProofHelperBefore   = "MerkleProofHelperSenderBefore_"
	baseNameReceiverMerkleBefore      = "MerkleProofsReceiverBefore_"
	baseNameReceiverProofHelperBefore = "MerkleProofHelperReceiverBefore_"
	baseNameRootHashBefore            = "RootHashesBefore_"

	// basename of the inputs for the proofs after update
	baseNameSenderMerkleAfter        = "MerkleProofsSenderAfter_"
	baseNameSenderProofHelperAfter   = "MerkleProofHelperSenderAfter_"
	baseNameReceiverMerkleAfter      = "MerkleProofsReceiverAfter_"
	baseNameReceiverProofHelperAfter = "MerkleProofHelperReceiverAfter_"
	baseNameRootHashAfter            = "RootHashesAfter_"

	// basename sender account pubkey
	// baseNameSenderAccountPubkeyx = "a_sender_pubkeyx_"
	// baseNameSenderAccountPubkeyy = "a_sender_pubkeyy_"

	// basename of the sender account input before update
	baseNameSenderAccountIndexBefore   = "SenderAccountsBefore_Index_"
	baseNameSenderAccountNonceBefore   = "SenderAccountsBefore_Nonce_"
	baseNameSenderAccountBalanceBefore = "SenderAccountsBefore_Balance_"

	// basename of the sender account input adter update
	baseNameSenderAccountIndexAfter   = "SenderAccountsAfter_Index_"
	baseNameSenderAccountNonceAfter   = "SenderAccountsAfter_Nonce_"
	baseNameSenderAccountBalanceAfter = "SenderAccountsAfter_Balance_"

	// basename of the receiver account pubk
	// baseNameReceiverAccountPubkeyx = "a_receiver_pubkeyx_"
	// baseNameReceiverAccountPubkeyy = "a_receiver_pubkeyy_"

	// basename of the receiver account input before update
	baseNameReceiverAccountIndexBefore   = "ReceiverAccountsBefore_Index_"
	baseNameReceiverAccountNonceBefore   = "ReceiverAccountsBefore_Nonce_"
	baseNameReceiverAccountBalanceBefore = "ReceiverAccountsBefore_Balance_"

	// basename of the receiver account input after update
	baseNameReceiverAccountIndexAfter   = "ReceiverAccountsAfter_Index_"
	baseNameReceiverAccountNonceAfter   = "ReceiverAccountsAfter_Nonce_"
	baseNameReceiverAccountBalanceAfter = "ReceiverAccountsAfter_Balance_"

	// basename of the transfer input
	baseNameTransferAmount = "Transfers_Amount_"
	baseNameTransferSigRx  = "t_sig_Rx_"
	baseNameTransferSigRy  = "t_sig_Ry_"
	baseNameTransferSigS   = "t_sig_S_"
)

// rollupCircuit createsa full rollup circuit
// batchSize size of a batch of transaction
// depth size of the merkle proofs
// nbAccounts number of accounts managed by the operator
// indices list of indices for the proofs
// func rollupCircuit(circuit *frontend.CS, batchSize int, depth int, nbAccounts int) error {

// 	// nb accounts managed by the operator
// 	numLeaves := nbAccounts

// 	for i := 0; i < batchSize; i++ {

// 		// setting the root hashes
// 		rootHashesBefore[i] = circuit.PUBLIC_INPUT(baseNameRootHashBefore + strconv.Itoa(i))
// 		rootHashesAfter[i] = circuit.PUBLIC_INPUT(baseNameRootHashAfter + strconv.Itoa(i))

// 		// setting the sender/receiver proofs elmts
// 		merkleProofsSenderBefore[i] = make([]*frontend.Constraint, depth)
// 		merkleProofsReceiverBefore[i] = make([]*frontend.Constraint, depth)
// 		merkleProofHelperSenderBefore[i] = make([]*frontend.Constraint, depth-1)
// 		merkleProofHelperSenderAfter[i] = make([]*frontend.Constraint, depth-1)

// 		merkleProofsSenderAfter[i] = make([]*frontend.Constraint, depth)
// 		merkleProofsReceiverAfter[i] = make([]*frontend.Constraint, depth)
// 		merkleProofHelperReceiverBefore[i] = make([]*frontend.Constraint, depth-1)
// 		merkleProofHelperReceiverAfter[i] = make([]*frontend.Constraint, depth-1)

// 		for j := 0; j < depth; j++ {
// 			ext := strconv.Itoa(i) + strconv.Itoa(j)

// 			merkleProofsSenderBefore[i][j] = circuit.SECRET_INPUT(baseNameSenderMerkleBefore + ext)
// 			merkleProofsSenderAfter[i][j] = circuit.SECRET_INPUT(baseNameSenderMerkleAfter + ext)
// 			merkleProofsReceiverBefore[i][j] = circuit.SECRET_INPUT(baseNameReceiverMerkleBefore + ext)
// 			merkleProofsReceiverAfter[i][j] = circuit.SECRET_INPUT(baseNameReceiverMerkleAfter + ext)

// 			if j < depth-1 {
// 				merkleProofHelperSenderBefore[i][j] = circuit.SECRET_INPUT(baseNameSenderProofHelperBefore + ext)
// 				merkleProofHelperSenderAfter[i][j] = circuit.SECRET_INPUT(baseNameSenderProofHelperAfter + ext)
// 				merkleProofHelperReceiverBefore[i][j] = circuit.SECRET_INPUT(baseNameReceiverProofHelperBefore + ext)
// 				merkleProofHelperReceiverAfter[i][j] = circuit.SECRET_INPUT(baseNameReceiverProofHelperAfter + ext)
// 			}
// 		}

// 		// setting sender public key
// 		publicKeysSender[i].Curve = paramsGadget
// 		publicKeysSender[i].A.X = circuit.SECRET_INPUT(baseNameSenderAccountPubkeyx + strconv.Itoa(i))
// 		publicKeysSender[i].A.Y = circuit.SECRET_INPUT(baseNameSenderAccountPubkeyy + strconv.Itoa(i))

// 		// setting receiver public key
// 		publicKeysReceiver[i].Curve = paramsGadget
// 		publicKeysReceiver[i].A.X = circuit.SECRET_INPUT(baseNameReceiverAccountPubkeyx + strconv.Itoa(i))
// 		publicKeysReceiver[i].A.Y = circuit.SECRET_INPUT(baseNameReceiverAccountPubkeyy + strconv.Itoa(i))

// 		// setting the sender accounts before update
// 		senderAccountsBefore[i].index = circuit.SECRET_INPUT(baseNameSenderAccountIndexBefore + strconv.Itoa(i))
// 		senderAccountsBefore[i].nonce = circuit.SECRET_INPUT(baseNameSenderAccountNonceBefore + strconv.Itoa(i))
// 		senderAccountsBefore[i].balance = circuit.SECRET_INPUT(baseNameSenderAccountBalanceBefore + strconv.Itoa(i))
// 		senderAccountsBefore[i].pubKey = publicKeysSender[i]

// 		// setting the sender accounts after update
// 		senderAccountsAfter[i].index = circuit.SECRET_INPUT(baseNameSenderAccountIndexAfter + strconv.Itoa(i))
// 		senderAccountsAfter[i].nonce = circuit.SECRET_INPUT(baseNameSenderAccountNonceAfter + strconv.Itoa(i))
// 		senderAccountsAfter[i].balance = circuit.SECRET_INPUT(baseNameSenderAccountBalanceAfter + strconv.Itoa(i))
// 		senderAccountsAfter[i].pubKey = publicKeysSender[i]

// 		// setting the receiver accounts before update
// 		receiverAccountsBefore[i].index = circuit.SECRET_INPUT(baseNameReceiverAccountIndexBefore + strconv.Itoa(i))
// 		receiverAccountsBefore[i].nonce = circuit.SECRET_INPUT(baseNameReceiverAccountNonceBefore + strconv.Itoa(i))
// 		receiverAccountsBefore[i].balance = circuit.SECRET_INPUT(baseNameReceiverAccountBalanceBefore + strconv.Itoa(i))
// 		receiverAccountsBefore[i].pubKey = publicKeysReceiver[i]

// 		// setting the receiver accounts after update
// 		receiverAccountsAfter[i].index = circuit.SECRET_INPUT(baseNameReceiverAccountIndexAfter + strconv.Itoa(i))
// 		receiverAccountsAfter[i].nonce = circuit.SECRET_INPUT(baseNameReceiverAccountNonceAfter + strconv.Itoa(i))
// 		receiverAccountsAfter[i].balance = circuit.SECRET_INPUT(baseNameReceiverAccountBalanceAfter + strconv.Itoa(i))
// 		receiverAccountsAfter[i].pubKey = publicKeysReceiver[i]

// 		// setting the transfers
// 		transfers[i].nonce = senderAccountsBefore[i].nonce
// 		transfers[i].amount = circuit.SECRET_INPUT(baseNameTransferAmount + strconv.Itoa(i))
// 		transfers[i].senderPubKey = publicKeysSender[i]
// 		transfers[i].receiverPubKey = publicKeysReceiver[i]
// 		transfers[i].signature.R.A.X = circuit.SECRET_INPUT(baseNameTransferSigRx + strconv.Itoa(i))
// 		transfers[i].signature.R.A.Y = circuit.SECRET_INPUT(baseNameTransferSigRy + strconv.Itoa(i))
// 		transfers[i].signature.R.Curve = paramsGadget
// 		transfers[i].signature.S = circuit.SECRET_INPUT(baseNameTransferSigS + strconv.Itoa(i))
// 	}

// 	// creation of the circuit
// 	for i := 0; i < batchSize; i++ {

// 		// verify the sender and receiver accounts exist before the update
// 		merkle.VerifyProof(circuit, hFunc, rootHashesBefore[i], merkleProofsSenderBefore[i], merkleProofHelperSenderBefore[i])
// 		merkle.VerifyProof(circuit, hFunc, rootHashesBefore[i], merkleProofsReceiverBefore[i], merkleProofHelperReceiverBefore[i])

// 		// verify the sender and receiver accounts exist after the update
// 		merkle.VerifyProof(circuit, hFunc, rootHashesAfter[i], merkleProofsSenderAfter[i], merkleProofHelperSenderAfter[i])
// 		merkle.VerifyProof(circuit, hFunc, rootHashesAfter[i], merkleProofsReceiverAfter[i], merkleProofHelperReceiverAfter[i])

// 		// verify the transaction transfer
// 		err := verifySignatureTransfer(circuit, transfers[i], hFunc)
// 		if err != nil {
// 			return err
// 		}

// 		// update the accounts
// 		verifyUpdateAccountGadget(circuit, senderAccountsBefore[i], receiverAccountsBefore[i], senderAccountsAfter[i], receiverAccountsAfter[i], transfers[i].amount)
// 	}

// 	return nil

// }
