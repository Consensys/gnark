package main

import (
	"crypto/ecdsa"
	contract "github.com/consensys/gnark/backend/plonk/bn254/solidity/gopkg"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

type instance struct {
	sk              *ecdsa.PrivateKey
	contractAddress common.Address
	contract        *contract.Contract
	client          *backends.SimulatedBackend
	auth            *bind.TransactOpts
	t               *testing.T
}

func (i *instance) getTransactionOpts() *bind.TransactOpts {
	var err error
	i.auth, err = getTransactionOpts(i.sk, i.auth, i.client)
	assert.NoError(i.t, err)
	return i.auth
}

func newInstance(t *testing.T) instance {
	var err error
	var res instance

	res.t = t

	// create account
	res.sk, err = crypto.GenerateKey()
	assert.NoError(t, err)

	// create simulated backend
	res.client, res.auth, err = createSimulatedBackend(res.sk)
	assert.NoError(t, err)

	// deploy the contract
	res.contractAddress, _, res.contract, err = contract.DeployContract(res.auth, res.client)
	assert.NoError(t, err)
	res.client.Commit()
	return res
}

func TestMarshal(t *testing.T) {
	instance := newInstance(t)
	_, err := instance.contract.TestPlonkDeserialize(instance.getTransactionOpts(), withCommitment.kzgVk, withCommitment.plonkVk, withCommitment.proof, withCommitment.public)
	assert.NoError(t, err)
}
