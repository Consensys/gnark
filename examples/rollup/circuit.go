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
	"strconv"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gadgets/accumulator/merkle"
	twistededwards_gadget "github.com/consensys/gnark/gadgets/algebra/twistededwards"
	"github.com/consensys/gnark/gadgets/hash/mimc"
	"github.com/consensys/gnark/gadgets/signature/eddsa"
	"github.com/consensys/gurvy"
)

var (
	// basename of the inputs for the proofs before update
	baseNameSenderMerkleBefore        = "merkle_sender_proof_before_"
	baseNameSenderProofHelperBefore   = "merkle_sender_proof_helper_before"
	baseNameReceiverMerkleBefore      = "merkle_receiver_proof_before_"
	baseNameReceiverProofHelperBefore = "merkle_receiver_proof_helper_before"
	baseNameRootHashBefore            = "merkle_rh_before_"

	// basename of the inputs for the proofs after update
	baseNameSenderMerkleAfter        = "merkle_sender_proof_after_"
	baseNameSenderProofHelperAfter   = "merkle_sender_proof_helper_after"
	baseNameReceiverMerkleAfter      = "merkle_receiver_proof_after_"
	baseNameReceiverProofHelperAfter = "merkle_receiver_proof_helper_after"
	baseNameRootHashAfter            = "merkle_rh_after_"

	// basename sender account pubkey
	baseNameSenderAccountPubkeyx = "a_sender_pubkeyx_"
	baseNameSenderAccountPubkeyy = "a_sender_pubkeyy_"

	// basename of the sender account input before update
	baseNameSenderAccountIndexBefore   = "a_sender_index_before_"
	baseNameSenderAccountNonceBefore   = "a_sender_nonce_before_"
	baseNameSenderAccountBalanceBefore = "a_sender_balance_before_"

	// basename of the sender account input adter update
	baseNameSenderAccountIndexAfter   = "a_sender_index_before_after_"
	baseNameSenderAccountNonceAfter   = "a_sender_nonce_before_after_"
	baseNameSenderAccountBalanceAfter = "a_sender_balance_before_after_"

	// basename of the receiver account pubk
	baseNameReceiverAccountPubkeyx = "a_receiver_pubkeyx_"
	baseNameReceiverAccountPubkeyy = "a_receiver_pubkeyy_"

	// basename of the receiver account input before update
	baseNameReceiverAccountIndexBefore   = "a_receiver_index_before_"
	baseNameReceiverAccountNonceBefore   = "a_receiver_nonce_before_"
	baseNameReceiverAccountBalanceBefore = "a_receiver_balance_before_"

	// basename of the receiver account input after update
	baseNameReceiverAccountIndexAfter   = "a_receiver_index_after_"
	baseNameReceiverAccountNonceAfter   = "a_receiver_nonce_after_"
	baseNameReceiverAccountBalanceAfter = "a_receiver_balance_after_"

	// basename of the transfer input
	baseNameTransferAmount = "t_sender_amount_"
	baseNameTransferSigRx  = "t_sig_Rx_"
	baseNameTransferSigRy  = "t_sig_Ry_"
	baseNameTransferSigS   = "t_sig_S_"
)

// AccountCircuit accounts encoded as constraints
type AccountCircuit struct {
	index   *frontend.Constraint // index in the tree
	nonce   *frontend.Constraint // nb transactions done so far from this account
	balance *frontend.Constraint
	pubKey  eddsa.PublicKeyGadget
}

// TransferCircuit transfer encoded as constraints
type TransferCircuit struct {
	amount         *frontend.Constraint
	nonce          *frontend.Constraint
	senderPubKey   eddsa.PublicKeyGadget
	receiverPubKey eddsa.PublicKeyGadget
	signature      eddsa.SignatureGadget
}

// verifySignatureTransfer ensures that the signature of the transfer is valid
func verifySignatureTransfer(circuit *frontend.CS, t TransferCircuit, hFunc mimc.MiMCGadget) error {

	// the signature is on h(nonce || amount || senderpubKey (x&y) || receiverPubkey(x&y))
	htransfer := hFunc.Hash(circuit, t.nonce, t.amount, t.senderPubKey.A.X, t.senderPubKey.A.Y, t.receiverPubKey.A.X, t.receiverPubKey.A.Y)

	err := eddsa.Verify(circuit, t.signature, htransfer, t.senderPubKey)
	if err != nil {
		return err
	}
	return nil
}

// checkCorrectLeaf checks if hacc = hFunc(acc)
func ensureCorrectLeaf(circuit *frontend.CS, hFunc mimc.MiMCGadget, acc AccountCircuit, hacc *frontend.Constraint) {

	// compute the hash of the account, serialized like this:
	// index || nonce || balance || pubkeyX || pubkeyY
	haccount := hFunc.Hash(circuit, acc.index, acc.nonce, acc.balance, acc.pubKey.A.X, acc.pubKey.A.Y)

	circuit.MUSTBE_EQ(haccount, hacc)

}

// updateAccountGadget ensures that from, to are correctly updated according to t, h is the gadget hash for checking the signature
// returns the updated accounts from, to
func verifyUpdateAccountGadget(circuit *frontend.CS, from, to, fromUpdated, toUpdated AccountCircuit, amount *frontend.Constraint) {

	// ensure that nonce is correctly updated
	one := circuit.ALLOCATE(1)
	nonceUpdated := circuit.ADD(from.nonce, one)
	circuit.MUSTBE_EQ(nonceUpdated, fromUpdated.nonce)

	// TODO ensures that the amount is less than the balance (fix the MUSTBE_LESS_OR_EQ constraint)
	circuit.MUSTBE_LESS_OR_EQ(amount, from.balance, 256)

	// ensure that balance is correctly updated
	fromBalanceUpdated := circuit.SUB(from.balance, amount)
	circuit.MUSTBE_EQ(fromBalanceUpdated, fromUpdated.balance)

	toBalanceUpdated := circuit.ADD(to.balance, amount)
	circuit.MUSTBE_EQ(toBalanceUpdated, toUpdated.balance)

}

// rollupCircuit createsa full rollup circuit
// batchSize size of a batch of transaction
// depth size of the merkle proofs
// nbAccounts number of accounts managed by the operator
// indices list of indices for the proofs
func rollupCircuit(circuit *frontend.CS, batchSize int, depth int, nbAccounts int) error {

	// hash function for the merkle proof and the eddsa signature
	hFunc, err := mimc.NewMiMCGadget("seed", gurvy.BN256)
	if err != nil {
		return err
	}

	// nb accounts managed by the operator
	//numLeaves := nbAccounts

	// edward curve gadget
	paramsGadget, err := twistededwards_gadget.NewEdCurveGadget(gurvy.BN256)
	if err != nil {
		return err
	}

	// list of accounts involved before update and their public keys
	senderAccountsBefore := make([]AccountCircuit, batchSize)
	receiverAccountsBefore := make([]AccountCircuit, batchSize)
	publicKeysSender := make([]eddsa.PublicKeyGadget, batchSize)

	// list of accounts involved after update and their public keys
	senderAccountsAfter := make([]AccountCircuit, batchSize)
	receiverAccountsAfter := make([]AccountCircuit, batchSize)
	publicKeysReceiver := make([]eddsa.PublicKeyGadget, batchSize)

	// list of transactions
	transfers := make([]TransferCircuit, batchSize)

	// list of proofs corresponding to sender account
	merkleProofsSenderBefore := make([][]*frontend.Constraint, batchSize)
	merkleProofsSenderAfter := make([][]*frontend.Constraint, batchSize)
	merkleProofHelperSenderBefore := make([][]*frontend.Constraint, batchSize)
	merkleProofHelperSenderAfter := make([][]*frontend.Constraint, batchSize)

	// list of proofs corresponding to receiver account
	merkleProofsReceiverBefore := make([][]*frontend.Constraint, batchSize)
	merkleProofsReceiverAfter := make([][]*frontend.Constraint, batchSize)
	merkleProofHelperReceiverBefore := make([][]*frontend.Constraint, batchSize)
	merkleProofHelperReceiverAfter := make([][]*frontend.Constraint, batchSize)

	// list of root hashes
	rootHashesBefore := make([]*frontend.Constraint, batchSize)
	rootHashesAfter := make([]*frontend.Constraint, batchSize)

	for i := 0; i < batchSize; i++ {

		// setting the root hashes
		rootHashesBefore[i] = circuit.PUBLIC_INPUT(baseNameRootHashBefore + strconv.Itoa(i))
		rootHashesAfter[i] = circuit.PUBLIC_INPUT(baseNameRootHashAfter + strconv.Itoa(i))

		// setting the sender/receiver proofs elmts
		merkleProofsSenderBefore[i] = make([]*frontend.Constraint, depth)
		merkleProofsReceiverBefore[i] = make([]*frontend.Constraint, depth)
		merkleProofHelperSenderBefore[i] = make([]*frontend.Constraint, depth-1)
		merkleProofHelperSenderAfter[i] = make([]*frontend.Constraint, depth-1)

		merkleProofsSenderAfter[i] = make([]*frontend.Constraint, depth)
		merkleProofsReceiverAfter[i] = make([]*frontend.Constraint, depth)
		merkleProofHelperReceiverBefore[i] = make([]*frontend.Constraint, depth-1)
		merkleProofHelperReceiverAfter[i] = make([]*frontend.Constraint, depth-1)

		for j := 0; j < depth; j++ {
			ext := strconv.Itoa(i) + strconv.Itoa(j)

			merkleProofsSenderBefore[i][j] = circuit.SECRET_INPUT(baseNameSenderMerkleBefore + ext)
			merkleProofsSenderAfter[i][j] = circuit.SECRET_INPUT(baseNameSenderMerkleAfter + ext)
			merkleProofsReceiverBefore[i][j] = circuit.SECRET_INPUT(baseNameReceiverMerkleBefore + ext)
			merkleProofsReceiverAfter[i][j] = circuit.SECRET_INPUT(baseNameReceiverMerkleAfter + ext)

			if j < depth-1 {
				merkleProofHelperSenderBefore[i][j] = circuit.SECRET_INPUT(baseNameSenderProofHelperBefore + ext)
				merkleProofHelperSenderAfter[i][j] = circuit.SECRET_INPUT(baseNameSenderProofHelperAfter + ext)
				merkleProofHelperReceiverBefore[i][j] = circuit.SECRET_INPUT(baseNameReceiverProofHelperBefore + ext)
				merkleProofHelperReceiverAfter[i][j] = circuit.SECRET_INPUT(baseNameReceiverProofHelperAfter + ext)
			}
		}

		// setting sender public key
		publicKeysSender[i].Curve = paramsGadget
		publicKeysSender[i].A.X = circuit.SECRET_INPUT(baseNameSenderAccountPubkeyx + strconv.Itoa(i))
		publicKeysSender[i].A.Y = circuit.SECRET_INPUT(baseNameSenderAccountPubkeyy + strconv.Itoa(i))

		// setting receiver public key
		publicKeysReceiver[i].Curve = paramsGadget
		publicKeysReceiver[i].A.X = circuit.SECRET_INPUT(baseNameReceiverAccountPubkeyx + strconv.Itoa(i))
		publicKeysReceiver[i].A.Y = circuit.SECRET_INPUT(baseNameReceiverAccountPubkeyy + strconv.Itoa(i))

		// setting the sender accounts before update
		senderAccountsBefore[i].index = circuit.SECRET_INPUT(baseNameSenderAccountIndexBefore + strconv.Itoa(i))
		senderAccountsBefore[i].nonce = circuit.SECRET_INPUT(baseNameSenderAccountNonceBefore + strconv.Itoa(i))
		senderAccountsBefore[i].balance = circuit.SECRET_INPUT(baseNameSenderAccountBalanceBefore + strconv.Itoa(i))
		senderAccountsBefore[i].pubKey = publicKeysSender[i]

		// setting the sender accounts after update
		senderAccountsAfter[i].index = circuit.SECRET_INPUT(baseNameSenderAccountIndexAfter + strconv.Itoa(i))
		senderAccountsAfter[i].nonce = circuit.SECRET_INPUT(baseNameSenderAccountNonceAfter + strconv.Itoa(i))
		senderAccountsAfter[i].balance = circuit.SECRET_INPUT(baseNameSenderAccountBalanceAfter + strconv.Itoa(i))
		senderAccountsAfter[i].pubKey = publicKeysSender[i]

		// setting the receiver accounts before update
		receiverAccountsBefore[i].index = circuit.SECRET_INPUT(baseNameReceiverAccountIndexBefore + strconv.Itoa(i))
		receiverAccountsBefore[i].nonce = circuit.SECRET_INPUT(baseNameReceiverAccountNonceBefore + strconv.Itoa(i))
		receiverAccountsBefore[i].balance = circuit.SECRET_INPUT(baseNameReceiverAccountBalanceBefore + strconv.Itoa(i))
		receiverAccountsBefore[i].pubKey = publicKeysReceiver[i]

		// setting the receiver accounts after update
		receiverAccountsAfter[i].index = circuit.SECRET_INPUT(baseNameReceiverAccountIndexAfter + strconv.Itoa(i))
		receiverAccountsAfter[i].nonce = circuit.SECRET_INPUT(baseNameReceiverAccountNonceAfter + strconv.Itoa(i))
		receiverAccountsAfter[i].balance = circuit.SECRET_INPUT(baseNameReceiverAccountBalanceAfter + strconv.Itoa(i))
		receiverAccountsAfter[i].pubKey = publicKeysReceiver[i]

		// setting the transfers
		transfers[i].nonce = senderAccountsBefore[i].nonce
		transfers[i].amount = circuit.SECRET_INPUT(baseNameTransferAmount + strconv.Itoa(i))
		transfers[i].senderPubKey = publicKeysSender[i]
		transfers[i].receiverPubKey = publicKeysReceiver[i]
		transfers[i].signature.R.A.X = circuit.SECRET_INPUT(baseNameTransferSigRx + strconv.Itoa(i))
		transfers[i].signature.R.A.Y = circuit.SECRET_INPUT(baseNameTransferSigRy + strconv.Itoa(i))
		transfers[i].signature.R.Curve = paramsGadget
		transfers[i].signature.S = circuit.SECRET_INPUT(baseNameTransferSigS + strconv.Itoa(i))
	}

	// creation of the circuit
	for i := 0; i < batchSize; i++ {

		// verify the sender and receiver accounts exist before the update
		merkle.VerifyProof(circuit, hFunc, rootHashesBefore[i], merkleProofsSenderBefore[i], merkleProofHelperSenderBefore[i])
		merkle.VerifyProof(circuit, hFunc, rootHashesBefore[i], merkleProofsReceiverBefore[i], merkleProofHelperReceiverBefore[i])

		// verify the sender and receiver accounts exist after the update
		merkle.VerifyProof(circuit, hFunc, rootHashesAfter[i], merkleProofsSenderAfter[i], merkleProofHelperSenderAfter[i])
		merkle.VerifyProof(circuit, hFunc, rootHashesAfter[i], merkleProofsReceiverAfter[i], merkleProofHelperReceiverAfter[i])

		// verify the transaction transfer
		err := verifySignatureTransfer(circuit, transfers[i], hFunc)
		if err != nil {
			return err
		}

		// update the accounts
		verifyUpdateAccountGadget(circuit, senderAccountsBefore[i], receiverAccountsBefore[i], senderAccountsAfter[i], receiverAccountsAfter[i], transfers[i].amount)
	}

	return nil

}
