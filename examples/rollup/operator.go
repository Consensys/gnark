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
	"bytes"
	"hash"
	"math/big"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/std/accumulator/merkle"
)

var hFunc = mimc.NewMiMC("seed")

// BatchSize size of a batch of transactions to put in a snark
var BatchSize = 10

// Queue queue for storing the transfers (fixed size queue)
type Queue struct {
	listTransfers chan Transfer
}

// NewQueue creates a new queue, batchSize is the capaciy
func NewQueue(batchSize int) Queue {
	resChan := make(chan Transfer, batchSize)
	var res Queue
	res.listTransfers = resChan
	return res
}

// Operator represents a rollup operator
type Operator struct {
	State      []byte            // list of accounts: index || nonce || balance || pubkeyX || pubkeyY, each chunk is 256 bits
	HashState  []byte            // Hashed version of the state, each chunk is 256bits: ... || H(index || nonce || balance || pubkeyX || pubkeyY)) || ...
	AccountMap map[string]uint64 // hashmap of all available accounts (the key is the account.pubkey.X), the value is the index of the account in the state
	nbAccounts int               // number of accounts managed by this operator
	h          hash.Hash         // hash function used to build the Merkle Tree
	q          Queue             // queue of transfers
	batch      int               // current number of transactions in a batch
	witnesses  Circuit           // witnesses for the snark cicruit
}

// NewOperator creates a new operator.
// nbAccounts is the number of accounts managed by this operator, h is the hash function for the merkle proofs
func NewOperator(nbAccounts int) Operator {
	res := Operator{}

	// create a list of empty accounts
	res.State = make([]byte, SizeAccount*nbAccounts)

	// initialize hash of the state
	res.HashState = make([]byte, hFunc.Size()*nbAccounts)
	for i := 0; i < nbAccounts; i++ {
		hFunc.Reset()
		_, _ = hFunc.Write(res.State[i*SizeAccount : i*SizeAccount+SizeAccount])
		s := hFunc.Sum([]byte{})
		copy(res.HashState[i*hFunc.Size():(i+1)*hFunc.Size()], s)
	}

	res.AccountMap = make(map[string]uint64)
	res.nbAccounts = nbAccounts
	res.h = hFunc
	res.q = NewQueue(BatchSize)
	res.batch = 0
	return res
}

// readAccount reads the account located at index i
func (o *Operator) readAccount(i uint64) (Account, error) {

	var res Account
	err := Deserialize(&res, o.State[int(i)*SizeAccount:int(i)*SizeAccount+SizeAccount])
	if err != nil {
		return res, err
	}
	return res, nil
}

// updateAccount updates the state according to transfer
// numTransfer is the number of the transfer currently handled (between 0 and batchSize)
func (o *Operator) updateState(t Transfer, numTransfer int) error {

	var posSender, posReceiver uint64
	var ok bool

	// ext := strconv.Itoa(numTransfer)
	segmentSize := o.h.Size()

	// read sender's account
	b := t.senderPubKey.A.X.Bytes()
	if posSender, ok = o.AccountMap[string(b[:])]; !ok {
		return ErrNonExistingAccount
	}
	senderAccount, err := o.readAccount(posSender)
	if err != nil {
		return err
	}

	// read receiver's account
	b = t.receiverPubKey.A.X.Bytes()
	if posReceiver, ok = o.AccountMap[string(b[:])]; !ok {
		return ErrNonExistingAccount
	}
	receiverAccount, err := o.readAccount(posReceiver)
	if err != nil {
		return err
	}

	// set witnesses for the public keys
	o.witnesses.PublicKeysSender[numTransfer].A.X.Assign(senderAccount.pubKey.A.X)
	o.witnesses.PublicKeysSender[numTransfer].A.Y.Assign(senderAccount.pubKey.A.Y)
	o.witnesses.PublicKeysReceiver[numTransfer].A.X.Assign(receiverAccount.pubKey.A.X)
	o.witnesses.PublicKeysReceiver[numTransfer].A.Y.Assign(receiverAccount.pubKey.A.Y)

	// set witnesses for the accounts before update
	o.witnesses.SenderAccountsBefore[numTransfer].Index.Assign(senderAccount.index)
	o.witnesses.SenderAccountsBefore[numTransfer].Nonce.Assign(senderAccount.nonce)
	o.witnesses.SenderAccountsBefore[numTransfer].Balance.Assign(senderAccount.balance)

	o.witnesses.ReceiverAccountsBefore[numTransfer].Index.Assign(receiverAccount.index)
	o.witnesses.ReceiverAccountsBefore[numTransfer].Nonce.Assign(receiverAccount.nonce)
	o.witnesses.ReceiverAccountsBefore[numTransfer].Balance.Assign(receiverAccount.balance)

	//  Set witnesses for the proof of inclusion of sender and receivers account before update
	var buf bytes.Buffer
	_, err = buf.Write(o.HashState)
	if err != nil {
		return err
	}
	merkleRootBefore, proofInclusionSenderBefore, numLeaves, err := merkletree.BuildReaderProof(&buf, o.h, segmentSize, posSender)
	if err != nil {
		return err
	}
	merkletree.VerifyProof(o.h, merkleRootBefore, proofInclusionSenderBefore, posSender, numLeaves)
	merkleProofHelperSenderBefore := merkle.GenerateProofHelper(proofInclusionSenderBefore, posSender, numLeaves)

	buf.Reset() // the buffer needs to be reset
	_, err = buf.Write(o.HashState)
	if err != nil {
		return err
	}
	_, proofInclusionReceiverBefore, _, err := merkletree.BuildReaderProof(&buf, o.h, segmentSize, posReceiver)
	if err != nil {
		return err
	}
	merkleProofHelperReceiverBefore := merkle.GenerateProofHelper(proofInclusionReceiverBefore, posReceiver, numLeaves)
	o.witnesses.RootHashesBefore[numTransfer].Assign(merkleRootBefore)
	for i := 0; i < len(proofInclusionSenderBefore); i++ {
		o.witnesses.MerkleProofsSenderBefore[numTransfer][i].Assign(proofInclusionSenderBefore[i])
		o.witnesses.MerkleProofsReceiverBefore[numTransfer][i].Assign(proofInclusionReceiverBefore[i])

		if i < len(proofInclusionReceiverBefore)-1 {
			o.witnesses.MerkleProofHelperSenderBefore[numTransfer][i].Assign(merkleProofHelperSenderBefore[i])
			o.witnesses.MerkleProofHelperReceiverBefore[numTransfer][i].Assign(merkleProofHelperReceiverBefore[i])
		}
	}

	// set witnesses for the transfer
	o.witnesses.Transfers[numTransfer].Amount.Assign(t.amount)
	o.witnesses.Transfers[numTransfer].Signature.R.X.Assign(t.signature.R.X)
	o.witnesses.Transfers[numTransfer].Signature.R.Y.Assign(t.signature.R.Y)
	o.witnesses.Transfers[numTransfer].Signature.S1.Assign(t.signature.S[:16])
	o.witnesses.Transfers[numTransfer].Signature.S2.Assign(t.signature.S[16:])

	// verifying the signature. The msg is the hash (o.h) of the transfer
	// nonce || amount || senderpubKey(x&y) || receiverPubkey(x&y)
	resSig, err := t.Verify(o.h)
	if err != nil {
		return err
	}
	if !resSig {
		return ErrWrongSignature
	}

	// checks if the amount is correct
	var bAmount, bBalance big.Int
	receiverAccount.balance.ToBigIntRegular(&bBalance)
	t.amount.ToBigIntRegular(&bAmount)
	if bAmount.Cmp(&bBalance) == 1 {
		return ErrAmountTooHigh
	}

	// check if the nonce is correct
	if t.nonce != senderAccount.nonce {
		return ErrNonce
	}

	// update the balance of the sender
	senderAccount.balance.Sub(&senderAccount.balance, &t.amount)

	// update the balance of the receiver
	receiverAccount.balance.Add(&receiverAccount.balance, &t.amount)

	// update the nonce of the sender
	senderAccount.nonce++

	// set the witnesses for the account after update
	o.witnesses.SenderAccountsAfter[numTransfer].Index.Assign(senderAccount.index)
	o.witnesses.SenderAccountsAfter[numTransfer].Nonce.Assign(senderAccount.nonce)
	o.witnesses.SenderAccountsAfter[numTransfer].Balance.Assign(senderAccount.balance)

	o.witnesses.ReceiverAccountsAfter[numTransfer].Index.Assign(receiverAccount.index)
	o.witnesses.ReceiverAccountsAfter[numTransfer].Nonce.Assign(receiverAccount.nonce)
	o.witnesses.ReceiverAccountsAfter[numTransfer].Balance.Assign(receiverAccount.balance)

	// update the state of the operator
	copy(o.State[int(posSender)*SizeAccount:], senderAccount.Serialize())
	o.h.Reset()
	_, _ = o.h.Write(senderAccount.Serialize())
	bufSender := o.h.Sum([]byte{})
	copy(o.HashState[int(posSender)*o.h.Size():(int(posSender)+1)*o.h.Size()], bufSender)

	copy(o.State[int(posReceiver)*SizeAccount:], receiverAccount.Serialize())
	o.h.Reset()
	_, _ = o.h.Write(receiverAccount.Serialize())
	bufReceiver := o.h.Sum([]byte{})
	copy(o.HashState[int(posReceiver)*o.h.Size():(int(posReceiver)+1)*o.h.Size()], bufReceiver)

	//  Set witnesses for the proof of inclusion of sender and receivers account after update
	buf.Reset()
	_, err = buf.Write(o.HashState)
	if err != nil {
		return err
	}
	merkleRootAfer, proofInclusionSenderAfter, _, err := merkletree.BuildReaderProof(&buf, o.h, segmentSize, posSender)
	if err != nil {
		return err
	}
	merkleProofHelperSenderAfter := merkle.GenerateProofHelper(proofInclusionSenderAfter, posSender, numLeaves)

	buf.Reset() // the buffer needs to be reset
	_, err = buf.Write(o.HashState)
	if err != nil {
		return err
	}
	_, proofInclusionReceiverAfter, _, err := merkletree.BuildReaderProof(&buf, o.h, segmentSize, posReceiver)
	if err != nil {
		return err
	}
	merkleProofHelperReceiverAfter := merkle.GenerateProofHelper(proofInclusionReceiverAfter, posReceiver, numLeaves)

	o.witnesses.RootHashesAfter[numTransfer].Assign(merkleRootAfer)
	for i := 0; i < len(proofInclusionSenderAfter); i++ {
		o.witnesses.MerkleProofsSenderAfter[numTransfer][i].Assign(proofInclusionSenderAfter[i])
		o.witnesses.MerkleProofsReceiverAfter[numTransfer][i].Assign(proofInclusionReceiverAfter[i])

		if i < len(proofInclusionReceiverAfter)-1 {
			o.witnesses.MerkleProofHelperSenderAfter[numTransfer][i].Assign(merkleProofHelperSenderAfter[i])
			o.witnesses.MerkleProofHelperReceiverAfter[numTransfer][i].Assign(merkleProofHelperReceiverAfter[i])
		}
	}

	return nil
}
